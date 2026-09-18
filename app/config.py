"""Uygulama ayarlari."""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from .core.detector import DetectionConfig


class Settings(BaseSettings):
    """Ortam degiskenlerinden yuklenen ayarlar."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "AuthWatch"
    database_url: str = Field(default="sqlite+aiosqlite:///./authwatch.db")

    # --- Tespit esikleri (odev: "konfigure edilebilir olmali") ---
    detect_threshold: int = Field(default=5, ge=2, le=1000, description="Y saniyedeki X deneme -> X")
    detect_window_seconds: int = Field(default=60, ge=1, le=86400, description="Pencere genisligi Y")
    detect_cooldown_seconds: int = Field(
        default=300, ge=0, le=86400, description="Ayni IP icin alarm tekrarlamama suresi."
    )
    takeover_failures: int = Field(default=5, ge=1, le=1000)
    takeover_window_seconds: int = Field(default=600, ge=1, le=86400)

    # NoDecode: pydantic-settings karmasik tipleri JSON sanip cozmeye calisiyor;
    # burada virgulle ayrilmis duz metin istiyoruz.
    detect_allowlist: Annotated[set[str], NoDecode] = Field(
        default_factory=set,
        description="Alarm uretilmeyecek IP'ler (ofis cikisi, izleme sistemi...).",
    )

    # --- Yukleme sinirlari ---
    max_lines_per_ingest: int = Field(default=200000, ge=1)
    max_skipped_stored: int = Field(default=200, ge=0, description="Kac bozuk satir ornek olarak saklanir.")

    # --- Zenginlestirme ---
    geoip_db_path: str | None = Field(default=None, description="MaxMind mmdb yolu (opsiyonel).")

    @field_validator("detect_allowlist", mode="before")
    @classmethod
    def _split_allowlist(cls, value: object) -> object:
        if isinstance(value, str):
            return {item.strip() for item in value.split(",") if item.strip()}
        return value

    def detection(self) -> DetectionConfig:
        """Ayarlardan tespit yapilandirmasi uretir."""
        return DetectionConfig(
            threshold=self.detect_threshold,
            window_seconds=self.detect_window_seconds,
            allowlist=frozenset(self.detect_allowlist),
            cooldown_seconds=self.detect_cooldown_seconds,
            takeover_failures=self.takeover_failures,
            takeover_window_seconds=self.takeover_window_seconds,
        )


@lru_cache
def get_settings() -> Settings:
    """Ayarlari bir kez okuyup onbellekler."""
    return Settings()
