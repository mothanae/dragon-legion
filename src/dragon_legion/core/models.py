"""Database models for Dragon Legion platform.

Schema per phoneBypass.txt spec:
- devices: device inventory with JSONB attack tree state
- attacks: attack execution log with replay scripts
- exploits: CVE-indexed exploit payloads with success metrics
"""

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    Column, String, Text, Integer, Float, DateTime, Enum as SAEnum,
    ForeignKey, LargeBinary, JSON, Index, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


class DeviceState(str, Enum):
    UNLOCKED = "unlocked"
    LOCKED = "locked"
    DFU = "dfu"
    EDL = "edl"
    BROM = "brom"
    FASTBOOT = "fastboot"
    RECOVERY = "recovery"
    NORMAL = "normal"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class AttackStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    ERROR = "error"
    BLOCKED = "blocked"


class OSType(str, Enum):
    ANDROID = "android"
    IOS = "ios"
    BLACKBERRY = "blackberry"
    SYMBIAN = "symbian"
    NOKIA_FEATURE = "nokia_feature"
    KAIOS = "kaios"
    LEGACY = "legacy"
    UNKNOWN = "unknown"


class Device(Base):
    __tablename__ = "devices"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    serial_number = Column(String(128), unique=True, nullable=False, index=True)
    model = Column(String(128), nullable=False)
    manufacturer = Column(String(128))
    os_type = Column(SAEnum(OSType), default=OSType.UNKNOWN)
    os_version = Column(String(64))
    firmware = Column(String(128))
    security_patch = Column(String(32))
    chipset = Column(String(64))
    baseband_version = Column(String(128))
    device_state = Column(SAEnum(DeviceState), default=DeviceState.UNKNOWN)

    # Hardware IDs
    usb_vid = Column(String(8))
    usb_pid = Column(String(8))
    usb_serial = Column(String(64))

    # Root / jailbreak state
    is_rooted = Column(Integer, default=0)
    selinux_enforcing = Column(Integer, default=1)
    bootloader_unlocked = Column(Integer, default=0)

    # JSONB attack tree — tracks all attempted attack paths per device
    last_attack_tree = Column(JSONB, default=dict)

    # Timestamps
    first_seen = Column(DateTime(timezone=True), default=utcnow)
    last_seen = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    attacks = relationship("Attack", back_populates="device", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_devices_os_chipset", "os_type", "chipset"),
        Index("ix_devices_state", "device_state"),
    )


class Attack(Base):
    __tablename__ = "attacks"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    device_id = Column(UUID(as_uuid=False), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    module_name = Column(String(64), nullable=False)
    attack_vector = Column(String(128), nullable=False)
    cve_id = Column(String(32))
    payload_used = Column(Text)

    status = Column(SAEnum(AttackStatus), default=AttackStatus.QUEUED, index=True)

    result_log = Column(Text)
    replay_script = Column(Text)
    raw_output = Column(LargeBinary)
    metadata_ = Column("metadata", JSONB, default=dict)
    duration_ms = Column(Integer)

    created_at = Column(DateTime(timezone=True), default=utcnow)

    # Relationship
    device = relationship("Device", back_populates="attacks")


class Exploit(Base):
    __tablename__ = "exploits"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    cve_id = Column(String(32), unique=True, nullable=False, index=True)
    name = Column(String(256))
    description = Column(Text)
    target_os = Column(String(64))
    target_arch = Column(String(32))
    target_chipset = Column(String(64))
    min_version = Column(String(32))
    max_version = Column(String(32))

    payload = Column(LargeBinary)
    payload_sha256 = Column(String(64))

    success_rate = Column(Float, default=0.0)
    times_used = Column(Integer, default=0)

    # Requirements
    requires_hardware = Column(JSON, default=list)
    prerequisites = Column(JSON, default=list)

    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ix_exploits_target", "target_os", "target_arch", "target_chipset"),
    )


class LogEntry(Base):
    """TimescaleDB-backed operation log (Module 11)."""
    __tablename__ = "operation_logs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    time = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    module = Column(String(64), nullable=False)
    action = Column(String(128), nullable=False)
    device_id = Column(UUID(as_uuid=False), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)

    raw_data_sent = Column(Text)
    raw_data_received = Column(Text)
    status = Column(String(32), index=True)
    metadata_ = Column("metadata", JSONB, default=dict)

    __table_args__ = (
        Index("ix_logs_time_module", "time", "module"),
    )
