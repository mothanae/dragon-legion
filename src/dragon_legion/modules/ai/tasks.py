"""Celery tasks for AI-driven attack orchestration (Module 9)."""

from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(bind=True, max_retries=2)
def execute_rl_attack_schedule(self, attack_id: str, device_id: str,
                               attack_vector: str, params: dict) -> dict:
    """Run RL-driven attack scheduling for a device."""
    logger.info("RL attack scheduling for device %s", device_id)
    from dragon_legion.modules.ai import AIScheduler, DeviceState

    state = DeviceState(
        device_type=params.get("device_type", "unknown"),
        os_type=params.get("os_type", "unknown"),
        os_version=params.get("os_version", ""),
        chipset=params.get("chipset", ""),
        privilege_level=params.get("privilege_level", "none"),
    )

    scheduler = AIScheduler()
    scheduler.register_device(device_id, state)
    suggestion = scheduler.suggest_action(device_id)

    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "ai_scheduler",
        "suggestion": suggestion,
    }


@shared_task(bind=True, max_retries=1)
def execute_protocol_discovery(self, attack_id: str, device_id: str,
                               attack_vector: str, params: dict) -> dict:
    """Run VAE-based unknown protocol discovery."""
    logger.info("Protocol discovery for device %s", device_id)
    return {"attack_id": attack_id, "status": "completed", "module": "ai_protocol_discovery"}


@shared_task(bind=True, max_retries=2)
def execute_cross_device_propagate(self, attack_id: str, device_id: str,
                                   attack_vector: str, params: dict) -> dict:
    """Propagate successful exploit to all same-model devices."""
    logger.info("Cross-device propagation from %s", device_id)
    from dragon_legion.modules.ai import AIScheduler

    scheduler = AIScheduler()
    target_devices = scheduler.propagate_exploit(
        device_id, params.get("exploit_params", {}),
    )
    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "ai_propagate",
        "targets": target_devices,
    }
