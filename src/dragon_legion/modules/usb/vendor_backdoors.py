"""Vendor-Specific USB Backdoors (Module 1.7).

Implements USB protocols for:
- Samsung Exynos (Odin download mode)
- Huawei HiSilicon (Kirin factory test mode)
- Spreadtrum/Unisoc (ResearchDownload protocol)
"""

import struct
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Samsung Odin Protocol
# ---------------------------------------------------------------------------

class OdinProtocol:
    """Samsung Exynos Odin download mode protocol.

    VID:PID = 04E8:685D
    Protocol: ODIN magic (4B) + session ID (4B) + packet count (4B).
    Each packet: 4B size + data + 4B CRC32.
    """

    ODIN_VID = 0x04E8
    ODIN_PID = 0x685D
    ODIN_MAGIC = b"ODIN"

    CMD_PIT = 0x64   # Partition Information Table
    CMD_FLASH = 0x66 # Flash partition

    def __init__(self, usb_device):
        self._dev = usb_device
        self._session_id = int(time.time())

    def handshake(self) -> bool:
        """Initiate Odin session."""
        import usb
        try:
            # Send ODIN magic + session
            init_pkt = self.ODIN_MAGIC + struct.pack("<II", self._session_id, 0)
            self._dev.write(0x01, init_pkt, timeout=5000)

            # Read response
            response = self._dev.read(0x81, 512, timeout=5000)
            return len(response) >= 4
        except usb.core.USBError as e:
            logger.error("Odin handshake failed: %s", e)
            return False

    def read_pit(self) -> Optional[bytes]:
        """Read the Partition Information Table (PIT).

        The PIT describes all partitions on the device. Reading it allows
        targeted flash dump of specific partitions without full dump.
        """
        import usb
        pkt = struct.pack("<II", self.CMD_PIT, 0)
        try:
            self._dev.write(0x01, pkt, timeout=5000)
            response = self._dev.read(0x81, 65536, timeout=10000)
            if len(response) > 16:
                logger.info("PIT read: %d bytes", len(response))
                return bytes(response)
        except usb.core.USBError as e:
            logger.error("PIT read failed: %s", e)
        return None

    def flash_read(self, partition_name: str, start_sector: int,
                   num_sectors: int) -> Optional[bytes]:
        """Read a partition via Odin flash read command.

        The command is: 0x66 + partition name (null-terminated) + start sector + count
        """
        import usb
        name_bytes = partition_name.encode() + b"\x00"
        payload = bytes([self.CMD_FLASH]) + name_bytes
        payload += struct.pack("<II", start_sector, num_sectors)
        pkt = struct.pack("<I", len(payload)) + payload
        pkt += struct.pack("<I", crc32_samsung(pkt))

        try:
            self._dev.write(0x01, pkt, timeout=30000)
            response = self._dev.read(0x81, num_sectors * 512 + 1024, timeout=60000)
            return bytes(response)
        except usb.core.USBError as e:
            logger.error("Flash read failed: %s", e)
        return None


def crc32_samsung(data: bytes) -> int:
    """Samsung Odin CRC32 (standard polynomial)."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Huawei HiSilicon Factory Test Mode
# ---------------------------------------------------------------------------

class HisiliconFactoryMode:
    """Huawei HiSilicon Kirin factory test mode via AT commands.

    Commands extracted from leaked service manuals:
    - AT^FACTORYMODE=1 : Enter factory test mode
    - AT^READFLASH=<addr>,<len> : Read raw flash
    - AT^SYSCFGEX=? : Query system configuration
    - AT^CELLINFO : Get detailed cell tower info
    - AT^TXPWR=<dBm> : Set TX power (for BTS mode)
    """

    FACTORY_AT_COMMANDS = [
        # Authentication & Security
        ("AT^FACTORYMODE=1", "Enter factory test mode"),
        ("AT^FACTORYMODE=0", "Exit factory test mode"),
        ("AT^SECURITY=?", "Query security state"),
        ("AT^NVREAD=<id>", "Read NV item"),
        ("AT^NVWRITE=<id>,<val>", "Write NV item"),

        # Flash access
        ("AT^READFLASH=<addr>,<len>", "Read raw flash at address"),
        ("AT^WRITEFLASH=<addr>,<data>", "Write raw flash at address"),
        ("AT^ERASEFLASH=<addr>,<len>", "Erase flash region"),
        ("AT^PARTITION=?", "List partitions"),

        # System configuration
        ("AT^SYSCFGEX=?", "Query extended system config"),
        ("AT^SYSCFGEX=<type>,<val>", "Set extended system config"),
        ("AT^HWID", "Get hardware ID"),
        ("AT^FWVERSION", "Get firmware version"),

        # Radio / RF
        ("AT^CELLINFO", "Get detailed cell info"),
        ("AT^TXPWR=<dBm>", "Set TX power level"),
        ("AT^RFTM=<mode>", "RF test mode control"),
        ("AT^BAND=<band>", "Set frequency band"),
        ("AT^FREQLOCK=<arfcn>", "Lock to specific ARFCN"),

        # Debug
        ("AT^DEBUG=1", "Enable debug mode"),
        ("AT^DEBUGLOG=?", "Query debug log"),
        ("AT^CRASHLOG", "Read crash log"),
        ("AT^MEMDUMP=<addr>,<len>", "Dump modem memory"),

        # SIM
        ("AT^SIMSTATE", "Get SIM state"),
        ("AT^FORCESIM=<type>", "Force SIM type"),
        ("AT^VSIM=?", "Query virtual SIM capability"),

        # Modem control
        ("AT^MODEMRESET", "Reset modem"),
        ("AT^MODEMOFF", "Power off modem"),
        ("AT^MODEMON", "Power on modem"),
        ("AT^ENG=?", "Engineering mode query"),
    ]

    def __init__(self, serial_port: str, baudrate: int = 115200):
        import serial
        self._ser = serial.Serial(serial_port, baudrate=baudrate, timeout=3)

    def send_at(self, cmd: str) -> str:
        """Send AT command and return response."""
        self._ser.write((cmd + "\r\n").encode())
        self._ser.flush()
        time.sleep(0.2)
        response = b""
        while True:
            chunk = self._ser.read(1024)
            if not chunk:
                break
            response += chunk
            if b"OK\r\n" in response or b"ERROR\r\n" in response:
                break
        return response.decode("utf-8", errors="replace")

    def enter_factory_mode(self) -> bool:
        """Enter factory test mode."""
        rsp = self.send_at("AT^FACTORYMODE=1")
        return "OK" in rsp

    def read_flash(self, address: int, length: int) -> bytes:
        """Read raw flash at physical address."""
        rsp = self.send_at(f"AT^READFLASH={address},{length}")
        if "ERROR" in rsp:
            return b""
        # Response contains hex data — parse it
        # Format: ^READFLASH: <hex_data>
        try:
            hex_data = rsp.split("^READFLASH:")[1].strip().split("\n")[0]
            return bytes.fromhex(hex_data.replace(" ", ""))
        except (IndexError, ValueError):
            return b""

    def dump_modem_memory(self, address: int, length: int) -> bytes:
        """Dump modem DSP memory region."""
        rsp = self.send_at(f"AT^MEMDUMP={address},{length}")
        try:
            hex_data = rsp.split("^MEMDUMP:")[1].strip().split("\n")[0]
            return bytes.fromhex(hex_data.replace(" ", ""))
        except (IndexError, ValueError):
            return b""

    def close(self):
        self._ser.close()


# ---------------------------------------------------------------------------
# Spreadtrum/Unisoc ResearchDownload Protocol
# ---------------------------------------------------------------------------

class SpreadtrumDownload:
    """Spreadtrum/Unisoc ResearchDownload protocol.

    Initial handshake: 0x7E 0x01 0x00 0x00 0x00 0x00 0x00 0x7E
    Commands:
      0xFD — get HW info
      0xFE — change baud rate
      0xFF — flash read/write
    """

    SPD_START = 0x7E
    SPD_END = 0x7E

    CMD_HW_INFO = 0xFD
    CMD_BAUD = 0xFE
    CMD_FLASH = 0xFF

    def __init__(self, serial_port: str):
        import serial
        self._ser = serial.Serial(serial_port, baudrate=115200, timeout=3)

    def handshake(self) -> bool:
        """Enter download mode and perform initial handshake."""
        handshake_pkt = bytes([
            self.SPD_START,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            self.SPD_END,
        ])
        self._ser.write(handshake_pkt)
        self._ser.flush()

        response = self._ser.read(64)
        if response and len(response) >= 2:
            logger.info("SPD handshake successful. Response: %s", response.hex())
            return True
        return False

    def get_hw_info(self) -> dict:
        """Get hardware info from device."""
        pkt = self._build_packet(self.CMD_HW_INFO)
        self._ser.write(pkt)
        response = self._ser.read(256)
        info = {}
        if len(response) > 8:
            info["chip_id"] = response[4:8].hex()
        if len(response) > 16:
            info["fw_version"] = response[8:16].hex()
        return info

    def flash_read(self, address: int, length: int) -> bytes:
        """Read flash memory."""
        payload = struct.pack("<II", address, length)
        pkt = self._build_packet(self.CMD_FLASH, payload)
        self._ser.write(pkt)
        self._ser.flush()

        data = b""
        while len(data) < length:
            chunk = self._ser.read(min(4096, length - len(data)))
            if not chunk:
                break
            data += chunk
        return data

    def _build_packet(self, cmd: int, payload: bytes = b"") -> bytes:
        data = bytes([cmd]) + payload
        length = struct.pack("<I", len(data))
        return bytes([self.SPD_START]) + length + data + bytes([self.SPD_END])

    def close(self):
        self._ser.close()
