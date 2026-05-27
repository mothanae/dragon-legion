"""Verify all Dragon Legion modules import cleanly."""

import pytest


def test_core_imports():
    from dragon_legion.core import config, models, hardware, database, worker, master
    assert config.get_config() is not None


def test_hardware_detection():
    from dragon_legion.core.hardware import HardwareManager, HardwareType
    hw = HardwareManager()
    # Should not crash even without actual hardware
    devices = hw.detect_all()
    assert isinstance(devices, list)


def test_usb_modules_import():
    from dragon_legion.modules.usb import sahara, brom, fastboot, hid_attack, vendor_backdoors
    from dragon_legion.modules.usb.sahara import (
        build_hello_packet, crc32_sahara, SaharaPacket, SaharaSession
    )
    # Verify constants
    assert sahara.SAHARA_HELLO_REQ == 0x01
    assert sahara.STAGE1_SHELLCODE is not None
    assert len(sahara.STAGE2_SHELLCODE) > 0


def test_cellular_imports():
    from dragon_legion.modules.cellular import (
        build_silent_type0_sms, build_exploit_sms_tpdu, encode_address, encode_gsm7
    )
    tpdu = build_silent_type0_sms()
    assert tpdu is not None
    assert len(tpdu) > 0


def test_wireless_imports():
    from dragon_legion.modules.wireless import (
        build_broadpwn_beacon, build_dragonblood_sae_commit, build_blueborne_l2cap
    )
    beacon = build_broadpwn_beacon()
    assert len(beacon) > 50  # Radiotap + 802.11 header + IEs


def test_crypto_imports():
    from dragon_legion.modules.crypto import (
        parse_fde_footer, fde_derive_key, FDE_MAGIC, KernelExploitSuggester
    )
    assert FDE_MAGIC == 0xD0B5B1C4
    suggester = KernelExploitSuggester()
    exploits = suggester.suggest("4.14.150", 28)
    assert isinstance(exploits, list)


def test_ios_imports():
    from dragon_legion.modules.ios import (
        Checkm8Exploit, AMRExploitGenerator, iOSBruteForce, DFUDevice
    )
    dfu = DFUDevice()
    dfu.cpid = 0x8010  # A10
    assert dfu.is_vulnerable
    assert not dfu.is_arm64


def test_physical_imports():
    from dragon_legion.modules.physical import (
        EMFaultInjection, VBUSVoltageGlitch, PowerAnalysisCPA, PMICAttack
    )
    # Verify S-box is correct size
    assert len(PowerAnalysisCPA.SBOX) == 256
    assert PowerAnalysisCPA.SBOX[0] == 0x63


def test_blackberry_imports():
    from dragon_legion.modules.blackberry import (
        QNXExploit, BlackBerryLoaderProtocol, FIPSCryptoBruteForce
    )
    bf = FIPSCryptoBruteForce()
    assert bf.FIPS_HEADER_MAGIC == b"BB_CP"


def test_symbian_imports():
    from dragon_legion.modules.symbian import (
        SymbianROMDumper, SISExploit, NokiaNK2Protocol, MotorolaP2K
    )
    assert MotorolaP2K.P2K_AT_COMMANDS  # Not empty
    assert NokiaNK2Protocol.NK2_MAGIC


def test_kaios_imports():
    from dragon_legion.modules.kaios import WasmJITExploit
    gen = WasmJITExploit()
    wasm = gen.generate_malicious_wasm()
    assert wasm[:4] == b"\x00asm"


def test_ai_imports():
    from dragon_legion.modules.ai import AttackEnvironment, DeviceState, AIScheduler
    state = DeviceState(privilege_level="none")
    env = AttackEnvironment(state)
    actions = env.get_available_actions()
    assert len(actions) > 0


def test_supply_chain_imports():
    from dragon_legion.modules.supply_chain import RogueOTAServer, FPGA_VERILOG_TEMPLATE
    assert "module flash_mitm" in FPGA_VERILOG_TEMPLATE


def test_post_exploitation_imports():
    from dragon_legion.modules.post_exploitation import UniversalFSCarver
    carver = UniversalFSCarver()
    assert carver.FS_SIGNATURES


def test_reporting_imports():
    from dragon_legion.modules.reporting import (
        OperationLogger, AttackTree, CVEMapper, ReplaySystem
    )
    logger = OperationLogger()
    assert logger.get_entries() == []

    tree = AttackTree("test_device")
    assert tree.device_id == "test_device"


def test_celllink_bridge_imports():
    from dragon_legion.core.celllink_bridge import (
        DiagSession, BtsTower, UeClient, DeviceInfo, CellLinkOrchestrator,
        ADBBridge, is_native_available,
    )
    # Should not crash — bridge handles missing native lib gracefully
    assert isinstance(is_native_available(), bool)
