"""Celery task queue worker for Dragon Legion.

Workers run on Linux nodes for hardware-interfacing modules
(SDR, NFC, ChipSHOUTER, USB gadget mode).
Master communicates with workers via REST API and Redis pub/sub.
"""

from celery import Celery
from celery.signals import worker_ready, worker_shutdown

from .config import get_config

cfg = get_config()

celery_app = Celery(
    "dragon_legion",
    broker=cfg.celery.broker_url,
    backend=cfg.celery.result_backend,
)

celery_app.conf.update(
    task_serializer=cfg.celery.task_serializer,
    result_serializer=cfg.celery.result_serializer,
    task_track_started=cfg.celery.task_track_started,
    task_acks_late=cfg.celery.task_acks_late,
    worker_prefetch_multiplier=cfg.celery.worker_prefetch_multiplier,
    task_routes={
        "dragon_legion.modules.usb.*": {"queue": "usb"},
        "dragon_legion.modules.wireless.*": {"queue": "wireless"},
        "dragon_legion.modules.cellular.*": {"queue": "cellular"},
        "dragon_legion.modules.physical.*": {"queue": "physical"},
        "dragon_legion.modules.crypto.*": {"queue": "crypto"},
        "dragon_legion.modules.ai.*": {"queue": "ai"},
        "dragon_legion.modules.ios.*": {"queue": "ios"},
        "dragon_legion.modules.blackberry.*": {"queue": "blackberry"},
        "dragon_legion.modules.symbian.*": {"queue": "symbian"},
        "dragon_legion.modules.kaios.*": {"queue": "kaios"},
        "dragon_legion.modules.post_exploitation.*": {"queue": "post"},
        "dragon_legion.modules.supply_chain.*": {"queue": "supply"},
    },
    imports=(
        "dragon_legion.modules.usb.tasks",
        "dragon_legion.modules.wireless.tasks",
        "dragon_legion.modules.cellular.tasks",
        "dragon_legion.modules.crypto.tasks",
        "dragon_legion.modules.physical.tasks",
        "dragon_legion.modules.ios.tasks",
        "dragon_legion.modules.blackberry.tasks",
        "dragon_legion.modules.symbian.tasks",
        "dragon_legion.modules.kaios.tasks",
        "dragon_legion.modules.ai.tasks",
        "dragon_legion.modules.post_exploitation.tasks",
        "dragon_legion.modules.supply_chain.tasks",
    ),
)


@worker_ready.connect
def on_worker_ready(**kwargs):
    """Signal that worker is ready to receive tasks."""
    from .hardware import get_hardware
    hw = get_hardware()
    print(f"[Worker] Ready. Hardware modules enabled: {hw.enabled_modules}")


@worker_shutdown.connect
def on_worker_shutdown(**kwargs):
    print("[Worker] Shutting down. Cleaning up hardware...")
