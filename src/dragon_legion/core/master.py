"""Central Master: FastAPI web application + WebSocket real-time dashboard.

Runs on Linux, Windows, or macOS.
Tagline: "The Legion kneels to no key; it tests all doors until they are unbreakable."
"""

import time
import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_config
from .database import init_database, close_database, get_async_session
from .hardware import get_hardware, HardwareManager
from .models import Device, Attack, Exploit, DeviceState, AttackStatus

logger = logging.getLogger(__name__)

# WebSocket connections for live dashboard
_active_ws: set[WebSocket] = set()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup/shutdown."""
    cfg = get_config()
    logger.info("Dragon Legion starting on %s:%d", cfg.master_host, cfg.master_port)

    try:
        await init_database()
        logger.info("Database initialized")
    except Exception as e:
        logger.warning("Database not available: %s (continuing without DB)", e)

    get_hardware()
    logger.info("Hardware layer initialized")

    yield

    logger.info("Dragon Legion shutting down")
    await close_database()


app = FastAPI(
    title="Dragon Legion",
    description="Cross-Platform Universal Mobile Penetration Testing Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Health & Status
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    cfg = get_config()
    hw = get_hardware()
    return {
        "status": "ok",
        "version": "1.0.0",
        "codename": "Legion of Dragons",
        "timestamp": time.time(),
        "hardware_modules": hw.enabled_modules,
        "active_ws_connections": len(_active_ws),
        "worker_mode": cfg.worker_mode,
    }


@app.get("/api/hardware")
async def list_hardware():
    hw = get_hardware()
    return {
        "devices": [
            {
                "type": d.hw_type.value,
                "name": d.name,
                "path": d.path,
                "usb_vid": d.usb_vid,
                "usb_pid": d.usb_pid,
                "serial": d.serial_number,
            }
            for d in hw.all_devices
        ],
        "enabled_modules": hw.enabled_modules,
    }


@app.post("/api/hardware/rescan")
async def rescan_hardware():
    hw = get_hardware()
    devices = hw.detect_all()
    return {
        "devices_found": len(devices),
        "enabled_modules": hw.enabled_modules,
    }


# ---------------------------------------------------------------------------
# Device CRUD
# ---------------------------------------------------------------------------

@app.get("/api/devices")
async def list_devices(
    os_type: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_async_session),
):
    """List known devices with optional filters."""
    from sqlalchemy import select

    stmt = select(Device)
    if os_type:
        stmt = stmt.where(Device.os_type == os_type)
    if state:
        stmt = stmt.where(Device.device_state == state)
    stmt = stmt.order_by(Device.last_seen.desc()).offset(offset).limit(limit)

    result = await db.execute(stmt)
    devices = result.scalars().all()
    return {
        "devices": [
            {
                "id": d.id,
                "serial_number": d.serial_number,
                "model": d.model,
                "manufacturer": d.manufacturer,
                "os_type": d.os_type.value if d.os_type else None,
                "os_version": d.os_version,
                "chipset": d.chipset,
                "device_state": d.device_state.value if d.device_state else None,
                "is_rooted": bool(d.is_rooted),
                "last_seen": d.last_seen.isoformat() if d.last_seen else None,
            }
            for d in devices
        ],
        "total": len(devices),
    }


@app.get("/api/devices/{device_id}")
async def get_device(
    device_id: str,
    db: AsyncSession = Depends(get_async_session),
):
    from sqlalchemy import select

    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

    # Get recent attacks
    attack_result = await db.execute(
        select(Attack)
        .where(Attack.device_id == device_id)
        .order_by(Attack.created_at.desc())
        .limit(20)
    )
    attacks = attack_result.scalars().all()

    return {
        "device": {
            "id": device.id,
            "serial_number": device.serial_number,
            "model": device.model,
            "manufacturer": device.manufacturer,
            "os_type": device.os_type.value if device.os_type else None,
            "os_version": device.os_version,
            "firmware": device.firmware,
            "security_patch": device.security_patch,
            "chipset": device.chipset,
            "baseband_version": device.baseband_version,
            "device_state": device.device_state.value if device.device_state else None,
            "usb_vid": device.usb_vid,
            "usb_pid": device.usb_pid,
            "is_rooted": bool(device.is_rooted),
            "selinux_enforcing": bool(device.selinux_enforcing),
            "bootloader_unlocked": bool(device.bootloader_unlocked),
            "last_attack_tree": device.last_attack_tree,
            "first_seen": device.first_seen.isoformat() if device.first_seen else None,
            "last_seen": device.last_seen.isoformat() if device.last_seen else None,
        },
        "recent_attacks": [
            {
                "id": a.id,
                "module": a.module_name,
                "vector": a.attack_vector,
                "cve_id": a.cve_id,
                "status": a.status.value if a.status else None,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in attacks
        ],
    }


# ---------------------------------------------------------------------------
# Exploit Database
# ---------------------------------------------------------------------------

@app.get("/api/exploits")
async def list_exploits(
    target_os: Optional[str] = Query(None),
    target_arch: Optional[str] = Query(None),
    cve_id: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_async_session),
):
    from sqlalchemy import select

    stmt = select(Exploit)
    if target_os:
        stmt = stmt.where(Exploit.target_os == target_os)
    if target_arch:
        stmt = stmt.where(Exploit.target_arch == target_arch)
    if cve_id:
        stmt = stmt.where(Exploit.cve_id == cve_id)
    stmt = stmt.order_by(Exploit.success_rate.desc()).limit(limit)

    result = await db.execute(stmt)
    exploits = result.scalars().all()
    return {
        "exploits": [
            {
                "id": e.id,
                "cve_id": e.cve_id,
                "name": e.name,
                "target_os": e.target_os,
                "target_arch": e.target_arch,
                "target_chipset": e.target_chipset,
                "success_rate": e.success_rate,
                "times_used": e.times_used,
                "requires_hardware": e.requires_hardware,
            }
            for e in exploits
        ],
    }


# ---------------------------------------------------------------------------
# Attack Execution
# ---------------------------------------------------------------------------

@app.post("/api/attack/start")
async def start_attack(
    device_id: str,
    module_name: str,
    attack_vector: str,
    params: dict = None,
    db: AsyncSession = Depends(get_async_session),
):
    """Queue an attack against a device. Dispatched to appropriate Celery worker."""
    from .worker import celery_app

    # Verify device exists
    from sqlalchemy import select
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

    # Create attack record
    attack = Attack(
        device_id=device_id,
        module_name=module_name,
        attack_vector=attack_vector,
        cve_id=(params or {}).get("cve_id"),
        status=AttackStatus.QUEUED,
        metadata_=params or {},
    )
    db.add(attack)
    await db.commit()
    await db.refresh(attack)

    # Dispatch task
    task = celery_app.send_task(
        f"dragon_legion.modules.{module_name}.execute",
        args=[str(attack.id), device_id, attack_vector, params or {}],
        queue=module_name.split(".")[0] if "." in module_name else "default",
    )

    return {
        "attack_id": str(attack.id),
        "task_id": task.id,
        "status": "queued",
    }


# ---------------------------------------------------------------------------
# WebSocket Dashboard
# ---------------------------------------------------------------------------

@app.websocket("/ws/dashboard")
async def dashboard_ws(ws: WebSocket):
    """Real-time WebSocket dashboard for live attack progress."""
    await ws.accept()
    _active_ws.add(ws)

    # Send initial state
    await ws.send_json({
        "type": "connected",
        "message": "The Legion kneels to no key; it tests all doors until they are unbreakable.",
        "active_connections": len(_active_ws),
    })

    try:
        while True:
            # Keep alive — client can send commands
            data = await ws.receive_json()
            cmd = data.get("command")

            if cmd == "ping":
                await ws.send_json({"type": "pong", "timestamp": time.time()})
            elif cmd == "subscribe_device":
                device_id = data.get("device_id")
                await ws.send_json({
                    "type": "subscribed",
                    "device_id": device_id,
                })

    except WebSocketDisconnect:
        pass
    finally:
        _active_ws.discard(ws)


# ---------------------------------------------------------------------------
# Pub/Sub relay (receives events from workers, broadcasts to dashboard)
# ---------------------------------------------------------------------------

async def broadcast_event(event_type: str, data: dict) -> None:
    """Send event to all connected dashboard clients."""
    dead: list[WebSocket] = []
    for ws in _active_ws:
        try:
            await ws.send_json({"type": event_type, **data})
        except Exception:
            dead.append(ws)
    for ws in dead:
        _active_ws.discard(ws)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    """Run the master server."""
    import uvicorn
    cfg = get_config()
    uvicorn.run(
        "dragon_legion.core.master:app",
        host=cfg.master_host,
        port=cfg.master_port,
        reload=cfg.debug,
        log_level=cfg.log_level.lower(),
    )


if __name__ == "__main__":
    main()
