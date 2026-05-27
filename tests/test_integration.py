"""Integration tests for Dragon Legion module interactions."""

import pytest


class TestSMSTPDUIntegration:
    """Verify SMS TPDU building and encoding consistency."""

    def test_silent_sms_roundtrip(self):
        from dragon_legion.modules.cellular import (
            build_silent_type0_sms, build_sms_submit_tpdu, encode_gsm7,
        )
        # Silent Type 0 SMS
        tpdu = build_silent_type0_sms()
        assert isinstance(tpdu, bytes)
        assert len(tpdu) > 10

    def test_sms_submit_basic(self):
        from dragon_legion.modules.cellular import build_sms_submit_tpdu
        tpdu = build_sms_submit_tpdu(
            smsc="123456789012",
            destination="12345678",
            message="Hello",
        )
        assert isinstance(tpdu, bytes)
        assert len(tpdu) > 20

    def test_gsm7_encoding(self):
        from dragon_legion.modules.cellular import encode_gsm7
        encoded = encode_gsm7("Hello World")
        assert isinstance(encoded, bytes)
        # "Hello World" is 11 chars * 7 bits = 77 bits / 8 = 10 bytes (rounded up)
        assert len(encoded) == 10  # 77/8 = 9.625 → ceil 10


class TestCryptoConsistency:
    """Verify crypto operations are consistent."""

    def test_fde_magic_constant(self):
        from dragon_legion.modules.crypto import FDE_MAGIC
        import struct
        assert struct.pack("<I", FDE_MAGIC) == b"\xC4\xB1\xB5\xD0"

    def test_fde_footer_parse_empty(self):
        from dragon_legion.modules.crypto import parse_fde_footer
        result = parse_fde_footer(b"\x00" * 65536)
        assert result is None  # No FDE magic in zero data

    def test_ext4_magic_verify(self):
        from dragon_legion.modules.crypto import verify_ext4_superblock
        # Empty data should fail
        assert not verify_ext4_superblock(b"")

    def test_f2fs_magic_verify(self):
        from dragon_legion.modules.crypto import verify_f2fs_superblock
        assert not verify_f2fs_superblock(b"")

    def test_kernel_suggester(self):
        from dragon_legion.modules.crypto import KernelExploitSuggester
        suggester = KernelExploitSuggester()
        exploits = suggester.suggest("5.10.50", 31)
        assert any(e["cve_id"] in ("CVE-2023-35788", "CVE-2024-29745") for e in exploits)


class TestWirelessFrames:
    """Verify wireless attack frame generation."""

    def test_broadpwn_beacon_structure(self):
        from dragon_legion.modules.wireless import build_broadpwn_beacon
        beacon = build_broadpwn_beacon(ssid="Test")
        # Should contain malicious IE: 0xDD (vendor) + 0xFF (len=255) + data
        assert b"\xDD\xFF" in beacon

    def test_dragonblood_commit(self):
        from dragon_legion.modules.wireless import build_dragonblood_sae_commit
        commit = build_dragonblood_sae_commit()
        # Should be a valid 802.11 auth frame
        assert len(commit) > 24  # Min 802.11 frame + auth body

    def test_blueborne_l2cap(self):
        from dragon_legion.modules.wireless import build_blueborne_l2cap
        l2cap = build_blueborne_l2cap()
        # L2CAP header: 2B length + 2B CID
        assert len(l2cap) >= 4


class TestUSBProtocols:
    """Verify USB protocol packet building."""

    def test_sahara_hello_packet(self):
        from dragon_legion.modules.usb.sahara import build_hello_packet, SaharaPacket
        hello = build_hello_packet()
        pkt = SaharaPacket.from_bytes(hello.to_bytes())
        assert pkt.cmd == 0x01
        assert b"Sahara" in pkt.payload

    def test_sahara_crc32_consistency(self):
        from dragon_legion.modules.usb.sahara import crc32_sahara
        crc1 = crc32_sahara(b"test")
        crc2 = crc32_sahara(b"test")
        assert crc1 == crc2

    def test_brom_packet_building(self):
        from dragon_legion.modules.usb.brom import brom_build_packet, brom_checksum, BROM_START
        pkt = brom_build_packet(cmd=0xFD)
        assert pkt[0] == BROM_START

    def test_fastboot_device_defaults(self):
        from dragon_legion.modules.usb.fastboot import FastbootDevice
        dev = FastbootDevice()
        assert dev.serial == ""
        assert not dev.unlocked


class TestAIEnvironment:
    """Verify RL attack environment."""

    def test_environment_actions(self):
        from dragon_legion.modules.ai import AttackEnvironment, DeviceState
        state = DeviceState(privilege_level="none")
        env = AttackEnvironment(state)
        available = env.get_available_actions()
        assert len(available) > 0

    def test_state_transitions(self):
        from dragon_legion.modules.ai import AttackEnvironment, DeviceState
        state = DeviceState(privilege_level="none")
        env = AttackEnvironment(state)
        actions = env.get_available_actions()
        new_state, reward, done = env.step(actions[0])
        assert isinstance(reward, float)


class TestIOSDeviceDetection:
    """Verify iOS device detection logic."""

    def test_dfudevice_cpid_vulnerability(self):
        from dragon_legion.modules.ios import DFUDevice
        # A5 → A11 are vulnerable
        vuln_cpids = [0x8940, 0x8950, 0x8960, 0x7000, 0x8000, 0x8010, 0x8020]
        for cpid in vuln_cpids:
            dev = DFUDevice()
            dev.cpid = cpid
            assert dev.is_vulnerable, f"CPID {hex(cpid)} should be vulnerable"

        # A12+ are NOT vulnerable
        dev = DFUDevice()
        dev.cpid = 0x8025  # A12
        assert not dev.is_vulnerable


class TestReporting:
    """Verify reporting module functionality."""

    def test_attack_tree_build(self):
        from dragon_legion.modules.reporting import AttackTree
        tree = AttackTree("dev001")
        tree.add_node("root", "step1", "Qualcomm Sahara", "usb.sahara", "CVE-2019-14040")
        tree.update_node("step1", "success", {"gid_key": True})
        json_tree = tree.to_json()
        assert json_tree["name"] == "Device: dev001"
        assert len(json_tree["children"]) == 1
        assert json_tree["children"][0]["status"] == "success"

    def test_cve_mapper(self):
        from dragon_legion.modules.reporting import CVEMapper
        mapper = CVEMapper()
        report = mapper.build_compliance_report("dev001", [
            {"cve_id": "CVE-2022-0847", "module": "crypto.kernel", "vector": "dirty_pipe"},
        ])
        assert report["total_cves_exploited"] == 1
        assert report["max_cvss"] > 7.0

    def test_replay_script_generation(self):
        from dragon_legion.modules.reporting import ReplaySystem
        replay = ReplaySystem()
        script = replay.save_replay("attack_001", [
            {"module": "usb.sahara", "action": "handshake", "params": {"mode": 0}},
            {"module": "usb.sahara", "action": "upload_programmer", "params": {}},
        ])
        assert "replay" in script
        assert "attack_001" in script
