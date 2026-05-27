"""Central configuration for Dragon Legion platform.

Reads from config/default.yaml, env vars, and CLI overrides.
"""

import os
import json
from dataclasses import dataclass, field
from typing import Optional

ENV_PREFIX = "DL_"


@dataclass
class DatabaseConfig:
    host: str = "127.0.0.1"
    port: int = 5432
    user: str = "dragon_legion"
    password: str = ""
    database: str = "dragon_legion"
    pool_size: int = 20

    @property
    def dsn(self) -> str:
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"

    @property
    def sync_dsn(self) -> str:
        return f"postgresql+psycopg2://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"


@dataclass
class RedisConfig:
    host: str = "127.0.0.1"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None

    @property
    def url(self) -> str:
        auth = f":{self.password}@" if self.password else ""
        return f"redis://{auth}{self.host}:{self.port}/{self.db}"


@dataclass
class CeleryConfig:
    broker_url: str = ""
    result_backend: str = ""
    task_serializer: str = "json"
    result_serializer: str = "json"
    task_track_started: bool = True
    task_acks_late: bool = True
    worker_prefetch_multiplier: int = 1


@dataclass
class HardwareConfig:
    usb_vendor_whitelist: list[str] = field(default_factory=list)
    enable_sdr: bool = False
    enable_nfc: bool = False
    enable_chipshouter: bool = False
    teensy_port: str = "/dev/ttyACM0"
    pn532_port: str = "/dev/ttyUSB0"


@dataclass
class SecurityConfig:
    encrypt_logs: bool = True
    log_retention_days: int = 90
    require_2fa: bool = True
    allowed_ips: list[str] = field(default_factory=list)
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60


@dataclass
class Config:
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    redis: RedisConfig = field(default_factory=RedisConfig)
    celery: CeleryConfig = field(default_factory=CeleryConfig)
    hardware: HardwareConfig = field(default_factory=HardwareConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    debug: bool = False
    log_level: str = "INFO"
    worker_mode: bool = False
    master_host: str = "127.0.0.1"
    master_port: int = 8000

    @classmethod
    def from_env(cls) -> "Config":
        """Build Config from environment variables, overriding defaults."""
        cfg = cls()

        # Database
        cfg.database.host = os.getenv(f"{ENV_PREFIX}DB_HOST", cfg.database.host)
        cfg.database.port = int(os.getenv(f"{ENV_PREFIX}DB_PORT", str(cfg.database.port)))
        cfg.database.user = os.getenv(f"{ENV_PREFIX}DB_USER", cfg.database.user)
        cfg.database.password = os.getenv(f"{ENV_PREFIX}DB_PASSWORD", cfg.database.password)
        cfg.database.database = os.getenv(f"{ENV_PREFIX}DB_NAME", cfg.database.database)

        # Redis
        cfg.redis.host = os.getenv(f"{ENV_PREFIX}REDIS_HOST", cfg.redis.host)
        cfg.redis.port = int(os.getenv(f"{ENV_PREFIX}REDIS_PORT", str(cfg.redis.port)))
        cfg.redis.password = os.getenv(f"{ENV_PREFIX}REDIS_PASSWORD")
        cfg.redis.db = int(os.getenv(f"{ENV_PREFIX}REDIS_DB", str(cfg.redis.db)))

        # Celery
        cfg.celery.broker_url = cfg.redis.url
        cfg.celery.result_backend = cfg.redis.url

        # Security
        cfg.security.jwt_secret = os.getenv(f"{ENV_PREFIX}JWT_SECRET", os.urandom(32).hex())

        # General
        cfg.debug = os.getenv(f"{ENV_PREFIX}DEBUG", "").lower() in ("1", "true", "yes")
        cfg.log_level = os.getenv(f"{ENV_PREFIX}LOG_LEVEL", cfg.log_level)
        cfg.master_host = os.getenv(f"{ENV_PREFIX}MASTER_HOST", cfg.master_host)

        return cfg


# Singleton
_config: Optional[Config] = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config.from_env()
    return _config


def set_config(cfg: Config) -> None:
    global _config
    _config = cfg
