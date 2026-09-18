"""Async SQLAlchemy oturum yonetimi."""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ..config import get_settings
from .models import Base

_settings = get_settings()

engine = create_async_engine(_settings.database_url, future=True, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def init_db() -> None:
    """Tablolari olusturur.

    Odev kapsaminda `create_all` yeterli; uretimde Alembic migration kullanilir.
    """
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI bagimliligi olarak oturum saglar."""
    async with SessionLocal() as session:
        yield session
