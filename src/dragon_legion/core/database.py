"""Database session management for Dragon Legion."""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_config
from .models import Base

_async_engine = None
_async_session_factory = None
_sync_engine = None
_sync_session_factory = None


async def init_database() -> None:
    """Initialize async database engine and create tables."""
    global _async_engine, _async_session_factory, _sync_engine, _sync_session_factory

    cfg = get_config()

    _async_engine = create_async_engine(
        cfg.database.dsn,
        echo=cfg.debug,
        pool_size=cfg.database.pool_size,
        max_overflow=10,
        pool_pre_ping=True,
    )

    _async_session_factory = async_sessionmaker(
        _async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # Sync engine for Celery tasks and CLI tools
    _sync_engine = create_engine(
        cfg.database.sync_dsn,
        echo=cfg.debug,
        pool_size=cfg.database.pool_size,
    )
    _sync_session_factory = sessionmaker(bind=_sync_engine)

    # Create tables
    async with _async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_database() -> None:
    if _async_engine:
        await _async_engine.dispose()


async def get_async_session() -> AsyncSession:
    if _async_session_factory is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    async with _async_session_factory() as session:
        yield session


def get_sync_session() -> Session:
    """Get synchronous session (for Celery tasks)."""
    if _sync_session_factory is None:
        raise RuntimeError("Database not initialized.")
    return _sync_session_factory()
