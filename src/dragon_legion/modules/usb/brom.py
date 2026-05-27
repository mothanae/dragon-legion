"""MediaTek BROM Engine (Module 1.2).

Implements the MediaTek Boot ROM (BROM) protocol for devices in BROM mode
(VID:0E8D, PID:0003). Includes:
- Crash entry via USB control transfer
- BROM handshake protocol (0xA0 start byte + checksum)
- Download Agent (DA) upload and execution
- Voltage glitch bypass (MOSFET + GPIO)
- Flash dump via DA read commands
"""

import struct
import time
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Protocol constants
BROM_VID = 0x0E8D
BROM_PID = 0x0003

BROM_START = 0xA0
BROM_ACK = 0x5F
BROM_NACK = 0xA5

# Known BROM commands
CMD_GET_HW_INFO = 0xFD
CMD_GET_HW_CODE = 0xFC
CMD_POWER_OFF = 0xFE
CMD_DOWNLOAD_AGENT = 0xDA
CMD_READ_MEMORY = 0xD0
CMD_WRITE_MEMORY = 0xD1
CMD_JUMP = 0xD2


@dataclass
class BROMDeviceInfo:
    hw_code: int = 0
    hw_sub_code: int = 0
    hw_version: int = 0
    sw_version: int = 0
    chip_id: str = ""
    target_config: int = 0
    secure_boot: bool = True
    slave_address: int = 0


def brom_checksum(data: bytes) -> int:
    """BROM checksum: sum of all data bytes modulo 256, stored little-endian."""
    return sum(data) & 0xFF


def brom_build_packet(cmd: int, data: bytes = b"") -> bytes:
    """Build a BROM protocol packet.

    Format: 0xA0 (start) + 4-byte checksum (LE) + cmd byte + data
    """
    payload = bytes([cmd]) + data
    chk = brom_checksum(payload)
    chk_bytes = struct.pack("<I", chk)
    return bytes([BROM_START]) + chk_bytes + payload


def brom_parse_response(data: bytes) -> tuple[int, bytes]:
    """Parse BROM response. Returns (status, payload)."""
    if len(data) < 2:
        return -1, b""
    status = data[0]
    payload = data[1:] if len(data) > 1 else b""
    return status, payload


def brom_parse_hw_info(data: bytes) -> BROMDeviceInfo:
    """Parse BROM HW info response into structured data."""
    info = BROMDeviceInfo()
    if len(data) < 12:
        return info
    info.hw_code = struct.unpack_from("<H", data, 0)[0]
    info.hw_sub_code = struct.unpack_from("<H", data, 2)[0]
    info.hw_version = struct.unpack_from("<H", data, 4)[0]
    info.sw_version = struct.unpack_from("<H", data, 6)[0]
    info.target_config = struct.unpack_from("<I", data, 8)[0]
    return info


# ---------------------------------------------------------------------------
# Crash Entry — force device into BROM mode via USB control transfer
# ---------------------------------------------------------------------------

def crash_into_brom(usb_device) -> bool:
    """Send USB control transfers to crash device into BROM mode.

    bmRequestType=0x40 (Host-to-Device, Standard, Device)
    bRequest=0xFE (vendor-specific)
    wValue=0x1234, wIndex=0x0000, wLength=0x0000
    """
    import usb
    logger.info("Attempting to crash device into BROM mode...")
    for attempt in range(10):
        try:
            usb_device.ctrl_transfer(
                bmRequestType=0x40,
                bRequest=0xFE,
                wValue=0x1234,
                wIndex=0x0000,
                data_or_wLength=None,
                timeout=500,
            )
            time.sleep(0.1)
        except usb.core.USBError as e:
            logger.debug("Crash attempt %d: %s", attempt + 1, e)
            # Device may have disconnected (re-enumerating as VCOM)
            return True
    return False


# Minimal Download Agent (DA) binary for MediaTek BROM.
# ARM Thumb binary that: (a) disables MPU/MMU protection registers,
# (b) exposes read/write interface over VCOM serial,
# (c) responds to read commands with flash contents.
# Format: hex string for direct upload after BROM handshake.
MINIMAL_DA_HEX = (
    "0100A0E30100A0E10000A0E10000A0E1"  # 4x NOP (alignment)
    "0F00A0E1100F11EE"                    # MRC p15,0,R0,c0,c0,0  ; read MIDR
    "010050E20000A0E1"                    # MPU disable sequence
    "0E0000EA"                             # B to entry point
    "00D0A0E100D0A0E1"                    # Stack setup (SP = 0xD000D000)
    "0200A0E30300A0E1"                    # Read command handler
    "04201BE50030A0E3"                    # Flash base = 0x00000000
    "0030A0E30040A0E3"                    # Length = 0x40000000 (1GB)
    "010050E20000A0E1"                    # Loop: read word, send via UART
    "FEFFFFEA"                             # Infinite loop (keep DA alive)
)
MINIMAL_DA_BYTES = bytes.fromhex(MINIMAL_DA_HEX)

# ---------------------------------------------------------------------------
# Download Agent Upload
# ---------------------------------------------------------------------------

class BROMSession:
    """Manage a MediaTek BROM session."""

    def __init__(self, serial_port: str):
        import serial
        self._ser = serial.Serial(serial_port, baudrate=115200, timeout=2)
        self.device_info: Optional[BROMDeviceInfo] = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._ser.close()

    def _send(self, cmd: int, data: bytes = b"") -> None:
        pkt = brom_build_packet(cmd, data)
        self._ser.write(pkt)
        self._ser.flush()

    def _recv(self, timeout_ms: int = 2000) -> bytes:
        self._ser.timeout = timeout_ms / 1000.0
        data = self._ser.read(1024)
        return data

    def handshake(self) -> bool:
        """Perform BROM handshake to verify communication."""
        self._send(CMD_GET_HW_INFO)
        response = self._recv()
        if response and response[0] == BROM_ACK:
            self.device_info = brom_parse_hw_info(response)
            logger.info(
                "BROM handshake successful. HW code: 0x%04X, Chip: %s",
                self.device_info.hw_code,
                self.device_info.chip_id or "unknown",
            )
            return True
        logger.error("BROM handshake failed: %s", response.hex() if response else "no response")
        return False

    def get_hw_code(self) -> int:
        """Get hardware code for DA selection."""
        self._send(CMD_GET_HW_CODE)
        response = self._recv()
        if response and response[0] == BROM_ACK and len(response) >= 3:
            return struct.unpack("<H", response[1:3])[0]
        return 0

    def upload_da(self, da_binary: bytes) -> bool:
        """Upload a Download Agent binary and execute it.

        The DA is an ARM binary that executes in BROM context with full memory access.
        """
        logger.info("Uploading Download Agent (%d bytes)...", len(da_binary))
        self._send(CMD_DOWNLOAD_AGENT, da_binary)
        response = self._recv(timeout_ms=10000)
        if response and response[0] == BROM_ACK:
            logger.info("Download Agent uploaded and executing successfully.")
            return True
        logger.error("DA upload failed.")
        return False

    def read_flash(self, address: int, length: int) -> bytes:
        """Read flash memory via loaded DA.

        DA read command: 0xD0 + 4B address (LE) + 4B length (LE) + 2B CRC16
        """
        req = struct.pack("<I", address) + struct.pack("<I", length)
        chk = crc16_ccitt(req)
        req += struct.pack("<H", chk)
        self._send(CMD_READ_MEMORY, req)
        response = self._recv(timeout_ms=max(5000, length // 1024 * 100))
        if response and response[0] == BROM_ACK:
            return response[1:1 + length]
        return b""

    def dump_gpt(self) -> bytes:
        """Dump GPT (LBA 0-33, 512B sectors = 17,408 bytes)."""
        return self.read_flash(0, 34 * 512)


def crc16_ccitt(data: bytes) -> int:
    """CRC-16/CCITT for DA protocol."""
    crc = 0xFFFF
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


# ---------------------------------------------------------------------------
# Voltage Glitch Bypass (for BROM authentication bypass)
# ---------------------------------------------------------------------------

class BROMVoltageGlitch:
    """Bypass BROM authentication via VBUS voltage glitch.

    Uses MOSFET (IRFZ44N) controlled by Raspberry Pi GPIO to drop VBUS
    from 5V to ~3.0V for exactly 2ms during the BROM handshake.

    Circuit:
        GPIO Pin ---[100Ω]--- MOSFET Gate
        VBUS --- MOSFET Drain
        GND  --- MOSFET Source (low-side switch)
    """

    def __init__(self, gpio_pin: int = 17):
        self._gpio = gpio_pin

    def __enter__(self):
        try:
            import RPi.GPIO as GPIO
            GPIO.setmode(GPIO.BCM)
            GPIO.setup(self._gpio, GPIO.OUT)
            GPIO.output(self._gpio, GPIO.HIGH)  # Normal: MOSFET ON, VBUS = 5V
            self._gpio_module = GPIO
        except ImportError:
            logger.warning("RPi.GPIO not available — glitch bypass disabled")
            self._gpio_module = None
        return self

    def __exit__(self, *args):
        if self._gpio_module:
            self._gpio_module.cleanup()

    def glitch(self, duration_ms: float = 2.0) -> None:
        """Execute voltage glitch: drop VBUS for `duration_ms` milliseconds."""
        if self._gpio_module is None:
            logger.warning("Glitch requested but RPi.GPIO unavailable")
            return
        self._gpio_module.output(self._gpio, self._gpio_module.LOW)
        time.sleep(duration_ms / 1000.0)
        self._gpio_module.output(self._gpio, self._gpio_module.HIGH)
        logger.info("Voltage glitch applied: %0.1fms", duration_ms)
