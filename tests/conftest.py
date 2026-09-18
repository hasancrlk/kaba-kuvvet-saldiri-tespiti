"""Test ortami.

Ortam degiskenleri uygulama modulleri *import edilmeden once* ayarlanir:
`app.db.session` motoru modul yuklenirken kuruyor, sonra degistirmek gec kalir.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

_TMP_DB = Path(tempfile.gettempdir()) / "authwatch_test.db"
_TMP_DB.unlink(missing_ok=True)

os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{_TMP_DB.as_posix()}")
os.environ.setdefault("DETECT_THRESHOLD", "5")
os.environ.setdefault("DETECT_WINDOW_SECONDS", "60")

import pytest  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.core.parsers import FAILURE, AuthEvent  # noqa: E402
from app.db.session import engine, init_db  # noqa: E402
from app.main import create_app  # noqa: E402

BASE = datetime(2026, 9, 17, 3, 0, 0, tzinfo=UTC)


def event(
    offset_seconds: float,
    *,
    ip: str = "203.0.113.5",
    username: str = "root",
    outcome: str = FAILURE,
    invalid_user: bool = False,
) -> AuthEvent:
    """Testlerde okunakli olay uretmek icin kisayol."""
    return AuthEvent(
        timestamp=BASE + timedelta(seconds=offset_seconds),
        ip=ip,
        username=username,
        outcome=outcome,
        service="ssh",
        invalid_user=invalid_user,
    )


@pytest.fixture(scope="session")
def sample_log_lines() -> list[str]:
    """Depodaki ornek log dosyasi."""
    path = Path(__file__).resolve().parent.parent / "data" / "sample-auth.log"
    return path.read_text(encoding="utf-8").splitlines()


@pytest.fixture(scope="session", autouse=True)
def _cleanup_db() -> AsyncIterator[None]:
    yield
    _TMP_DB.unlink(missing_ok=True)


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    """Uygulamayi ag katmani olmadan cagiran test istemcisi."""
    await init_db()
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client
    await engine.dispose()
