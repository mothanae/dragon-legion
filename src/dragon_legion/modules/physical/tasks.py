"""Celery tasks for physical/hardware-assisted attack modules."""

from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(bind=True, max_retries=2)
def execute_em_fault_injection(self, attack_id: str, device_id: str,
                               attack_vector: str, params: dict) -> dict:
    """Run automated EM fault injection scanning with Bayesian optimization."""
    logger.info("Starting EM fault injection on device %s", device_id)
    from dragon_legion.modules.physical import EMFaultInjection

    emfi = EMFaultInjection(serial_port=params.get("chipshouter_port", "/dev/ttyACM0"))
    if not emfi.connect():
        return {"attack_id": attack_id, "status": "error", "error": "ChipSHOUTER not connected"}

    bounds = params.get("bounds", {
        "x_min": 0, "x_max": 20000, "y_min": 0, "y_max": 20000,
        "delay_min": 0, "delay_max": 500, "pw_min": 5, "pw_max": 100,
        "v_min": 100, "v_max": 500,
    })
    result = emfi.bayesian_scan(bounds, n_iter=params.get("iterations", 200))

    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "physical_emfi",
        "best_params": result["best_params"],
        "success_rate": result["success_rate"],
    }


@shared_task(bind=True, max_retries=3)
def execute_vbus_glitch(self, attack_id: str, device_id: str,
                        attack_vector: str, params: dict) -> dict:
    """Execute VBUS voltage glitch attack."""
    logger.info("Executing VBUS glitch on device %s", device_id)
    from dragon_legion.modules.physical import VBUSVoltageGlitch

    with VBUSVoltageGlitch(gpio_pin=params.get("gpio_pin", 17)) as glitcher:
        results = glitcher.scan_timing(
            duration_range=(0.1, 10.0),
            offset_range=(0, 500.0),
            steps=params.get("scan_steps", 50),
        )

    successes = [r for r in results if r["success"]]
    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "physical_vbus_glitch",
        "attempts": len(results),
        "successes": len(successes),
    }


@shared_task(bind=True, max_retries=2)
def execute_cpa_power_analysis(self, attack_id: str, device_id: str,
                               attack_vector: str, params: dict) -> dict:
    """Capture and analyze power traces via CPA."""
    logger.info("Starting CPA power analysis on device %s", device_id)
    from dragon_legion.modules.physical import PowerAnalysisCPA

    cpa = PowerAnalysisCPA(audio_device=params.get("audio_device", 0))
    traces = cpa.capture_traces(num_traces=params.get("num_traces", 500))

    plaintext = bytes.fromhex(params.get("plaintext", "00"))
    key = cpa.recover_key(plaintext=plaintext, key_length=params.get("key_length", 16))

    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "physical_cpa",
        "traces_captured": len(traces),
        "recovered_key_bytes": len(key),
        "key_hex": bytes(key).hex(),
    }


@shared_task(bind=True, max_retries=2)
def execute_emmc_dump(self, attack_id: str, device_id: str,
                      attack_vector: str, params: dict) -> dict:
    """Dump eMMC flash via direct access (ISP or chip-off)."""
    logger.info("Dumping eMMC for device %s", device_id)
    from dragon_legion.modules.physical import eMMCDirectAccess

    reader = eMMCDirectAccess(device_path=params.get("device", "/dev/mmcblk0"))
    partitions = reader.dump_gpt()

    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "physical_emmc",
        "partitions_found": len(partitions),
        "partitions": partitions,
    }


@shared_task(bind=True, max_retries=2)
def execute_pmic_attack(self, attack_id: str, device_id: str,
                        attack_vector: str, params: dict) -> dict:
    """Compile and deploy PMIC I2C injection firmware to ATtiny85."""
    logger.info("Deploying PMIC attack firmware for device %s", device_id)
    from dragon_legion.modules.physical import PMICAttack

    pmic = PMICAttack(chipset=params.get("chipset", "pm8953"))
    compiled = pmic.compile_firmware(output_hex=params.get("output_hex", "pmic_attack.hex"))
    if compiled:
        flashed = pmic.flash_firmware(hex_path=params.get("output_hex", "pmic_attack.hex"))
        return {
            "attack_id": attack_id,
            "status": "completed" if flashed else "error",
            "module": "physical_pmic",
            "error": None if flashed else "Flash failed",
        }
    return {"attack_id": attack_id, "status": "error", "error": "Firmware compilation failed"}
