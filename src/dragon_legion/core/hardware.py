"""Hardware Abstraction Layer (Module 0 — Cross-cutting).

Detects connected peripherals via USB VID/PID enumeration, serial port probing,
and PCI device listing. Enables corresponding modules dynamically.
Falls back gracefully when hardware is absent.
"""

import os
import re
import time
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class HardwareType(str, Enum):
    USB_SERIAL = "usb_serial"
    SDR = "sdr"
    NFC = "nfc"
    CHIPSHOUTER = "chipshouter"
    TEENSY = "teensy"
    FPGA = "fpga"
    RASPBERRY_PI = "raspberry_pi"
    BLUETOOTH_DONGLE = "bluetooth_dongle"
    WIFI_ADAPTER = "wifi_adapter"
    EMMC_READER = "emmc_reader"
    LOGIC_ANALYZER = "logic_analyzer"


# Known USB VID/PID mappings
KNOWN_DEVICES: dict[tuple[str, str], HardwareType] = {
    # SDRs
    ("1D50", "6089"): HardwareType.SDR,        # HackRF One
    ("1D50", "60A1"): HardwareType.SDR,        # AirSpy
    ("2500", "0020"): HardwareType.SDR,        # USRP B200
    ("0403", "6010"): HardwareType.SDR,        # LimeSDR (FTDI)

    # NFC
    ("04CC", "2533"): HardwareType.NFC,        # PN532 via UART bridge

    # ChipSHOUTER
    ("04D8", "FC92"): HardwareType.CHIPSHOUTER,  # NewAE ChipSHOUTER

    # Teensy
    ("16C0", "0483"): HardwareType.TEENSY,     # Teensy 2.0/3.x
    ("16C0", "0478"): HardwareType.TEENSY,     # Teensy 4.0

    # FPGA
    ("0403", "6014"): HardwareType.FPGA,       # FT601 (Xilinx/Intel FPGA bridge)

    # Bluetooth
    ("0A12", "0001"): HardwareType.BLUETOOTH_DONGLE,  # CSR

    # Wi-Fi (monitor mode capable)
    ("0BDA", "8812"): HardwareType.WIFI_ADAPTER,   # RTL8812AU
    ("0CF3", "9271"): HardwareType.WIFI_ADAPTER,   # Atheros AR9271

    # eMMC programmers
    ("0483", "374B"): HardwareType.EMMC_READER,   # ST-Link (used in some readers)
}

# Known serial port device paths
SERIAL_PATTERNS = [
    (re.compile(r"ttyUSB\d+"), HardwareType.USB_SERIAL),
    (re.compile(r"ttyACM\d+"), HardwareType.USB_SERIAL),
    (re.compile(r"ttyHS\d+"), HardwareType.USB_SERIAL),
    (re.compile(r"ttyAMA\d+"), HardwareType.USB_SERIAL),
]


@dataclass
class HardwareDevice:
    hw_type: HardwareType
    name: str
    path: Optional[str] = None     # e.g., /dev/ttyUSB0
    usb_vid: Optional[str] = None
    usb_pid: Optional[str] = None
    serial_number: Optional[str] = None
    pci_address: Optional[str] = None
    extra: dict[str, str] = field(default_factory=dict)

    def __hash__(self):
        return hash((self.hw_type, self.path, self.usb_vid, self.usb_pid))


class HardwareManager:
    """Detect and track connected attack hardware.

    Usage:
        hw = HardwareManager()
        hw.detect_all()
        if hw.has(HardwareType.SDR):
            sdr_devices = hw.get(HardwareType.SDR)
    """

    def __init__(self):
        self._devices: list[HardwareDevice] = []
        self._by_type: dict[HardwareType, list[HardwareDevice]] = {}
        self._last_scan: float = 0.0

    def detect_all(self) -> list[HardwareDevice]:
        """Full hardware scan. Returns list of all found devices."""
        self._devices.clear()
        self._by_type.clear()

        self._detect_usb()
        self._detect_serial()
        self._detect_pci()
        self._detect_special()

        # Index by type
        for dev in self._devices:
            self._by_type.setdefault(dev.hw_type, []).append(dev)

        self._last_scan = time.monotonic()
        logger.info("Hardware scan complete: %d devices found", len(self._devices))
        for dev in self._devices:
            logger.info("  [%s] %s at %s", dev.hw_type.value, dev.name, dev.path or "N/A")

        return self._devices

    def _detect_usb(self) -> None:
        """Enumerate USB devices via sysfs."""
        usb_base = "/sys/bus/usb/devices"
        if not os.path.isdir(usb_base):
            logger.debug("USB sysfs not available (non-Linux or container)")
            return

        try:
            for entry in os.listdir(usb_base):
                dev_path = os.path.join(usb_base, entry)
                vid_file = os.path.join(dev_path, "idVendor")
                pid_file = os.path.join(dev_path, "idProduct")
                serial_file = os.path.join(dev_path, "serial")

                if not (os.path.isfile(vid_file) and os.path.isfile(pid_file)):
                    continue

                vid = open(vid_file).read().strip()
                pid = open(pid_file).read().strip()
                serial = ""
                if os.path.isfile(serial_file):
                    serial = open(serial_file).read().strip()

                hw_type = KNOWN_DEVICES.get((vid, pid))
                if hw_type is not None:
                    self._devices.append(HardwareDevice(
                        hw_type=hw_type,
                        name=f"{entry} (USB {vid}:{pid})",
                        usb_vid=vid,
                        usb_pid=pid,
                        serial_number=serial or None,
                    ))

                # Also log unknown USB devices for protocol discovery
                elif vid not in ("1D6B",):  # Skip Linux foundation root hubs
                    logger.debug("Unknown USB device: %s:%s (%s)", vid, pid, entry)

        except PermissionError:
            logger.warning("Cannot read USB sysfs (permission denied)")

    def _detect_serial(self) -> None:
        """Probe /dev for serial ports."""
        dev_dir = "/dev"
        if not os.path.isdir(dev_dir):
            return

        try:
            for entry in os.listdir(dev_dir):
                for pattern, hw_type in SERIAL_PATTERNS:
                    if pattern.match(entry):
                        path = os.path.join(dev_dir, entry)
                        if os.path.exists(path):
                            # Check if already found via USB
                            existing = [d for d in self._devices if d.path == path]
                            if not existing:
                                self._devices.append(HardwareDevice(
                                    hw_type=hw_type,
                                    name=entry,
                                    path=path,
                                ))
        except PermissionError:
            logger.warning("Cannot scan /dev (permission denied)")

    def _detect_pci(self) -> None:
        """Scan PCI bus for relevant devices."""
        pci_base = "/sys/bus/pci/devices"
        if not os.path.isdir(pci_base):
            return

        try:
            for entry in os.listdir(pci_base):
                dev_path = os.path.join(pci_base, entry)
                vendor_file = os.path.join(dev_path, "vendor")
                device_file = os.path.join(dev_path, "device")

                if not (os.path.isfile(vendor_file) and os.path.isfile(device_file)):
                    continue

                vid = open(vendor_file).read().strip()
                did = open(device_file).read().strip()

                # Thunderbolt / USB4 host controllers
                if vid == "0x8086" and did in ("0x9A1B", "0x9A1D", "0x463E"):
                    logger.info("Thunderbolt controller found at PCI %s", entry)

        except PermissionError:
            pass

    def _detect_special(self) -> None:
        """Detect Raspberry Pi GPIO, ChipSHOUTER via serial, etc."""
        # Raspberry Pi detection
        if os.path.exists("/proc/device-tree/model"):
            try:
                model = open("/proc/device-tree/model").read().strip("\x00")
                if "Raspberry Pi" in model:
                    self._devices.append(HardwareDevice(
                        hw_type=HardwareType.RASPBERRY_PI,
                        name=model,
                        path="/dev/gpiomem",
                    ))
            except (PermissionError, FileNotFoundError):
                pass

    def has(self, hw_type: HardwareType) -> bool:
        return hw_type in self._by_type and len(self._by_type[hw_type]) > 0

    def get(self, hw_type: HardwareType) -> list[HardwareDevice]:
        return self._by_type.get(hw_type, [])

    def get_first(self, hw_type: HardwareType) -> Optional[HardwareDevice]:
        devs = self._by_type.get(hw_type, [])
        return devs[0] if devs else None

    @property
    def all_devices(self) -> list[HardwareDevice]:
        return list(self._devices)

    @property
    def enabled_modules(self) -> list[str]:
        """Return list of module names that can be enabled based on hardware."""
        modules = []
        if self.has(HardwareType.USB_SERIAL):
            modules.extend(["usb_diag", "usb_at", "usb_modem"])
        if self.has(HardwareType.SDR):
            modules.extend(["lte_rogue_cell", "wifi_monitor"])
        if self.has(HardwareType.NFC):
            modules.append("nfc_attacks")
        if self.has(HardwareType.CHIPSHOUTER):
            modules.append("em_fault_injection")
        if self.has(HardwareType.TEENSY):
            modules.append("usb_hid_bruteforce")
        if self.has(HardwareType.FPGA):
            modules.extend(["thunderbolt_dma", "flash_mitm"])
        if self.has(HardwareType.WIFI_ADAPTER):
            modules.extend(["wifi_monitor", "pmkid_capture"])
        if self.has(HardwareType.BLUETOOTH_DONGLE):
            modules.append("bluetooth_attacks")
        return modules


# Singleton
_hw_manager: Optional[HardwareManager] = None


def get_hardware() -> HardwareManager:
    global _hw_manager
    if _hw_manager is None:
        _hw_manager = HardwareManager()
        _hw_manager.detect_all()
    return _hw_manager
