"""FastAPI uygulama girisi."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .api.routes import router
from .config import get_settings
from .db.session import init_db

DESCRIPTION = """
Kimlik dogrulama loglarini ayristirir, kayan zaman penceresiyle brute-force
denemelerini tespit eder ve alarm uretir.

Desteklenen bicimler: SSH `auth.log`, JSON satirlari, nginx/apache combined
erisim logu. Esikler (`X deneme / Y saniye`) yapilandirilabilir; alarmlar
`low`/`medium`/`high` guven etiketiyle gelir.
"""


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await init_db()
    yield


def create_app() -> FastAPI:
    """Uygulama fabrikasi (test icin de kullanilir)."""
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        description=DESCRIPTION,
        version="1.0.0",
        lifespan=lifespan,
        contact={"name": "hasancrlk", "url": "https://github.com/hasancrlk"},
        license_info={"name": "MIT"},
    )
    app.include_router(router)
    return app


app = create_app()
