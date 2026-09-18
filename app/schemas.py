"""API istek/yanit semalari."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class IngestRequest(BaseModel):
    """POST /ingest govdesi (JSON yolu)."""

    lines: list[str] = Field(..., min_length=1, description="Ham log satirlari.")
    source: str = Field(default="api", max_length=255)
    year_hint: int | None = Field(
        default=None,
        ge=1970,
        le=2999,
        description="SSH auth.log yil yazmaz; eski bir dosya yukluyorsaniz yilini verin.",
    )
    threshold: int | None = Field(default=None, ge=2, le=1000)
    window_seconds: int | None = Field(default=None, ge=1, le=86400)


class AlertOut(BaseModel):
    """Tek bir alarm."""

    id: int
    batch_id: int
    kind: str
    ip: str
    attempt_count: int
    window_start: datetime
    window_end: datetime
    window_seconds: float
    usernames: list[str] = Field(default_factory=list)
    confidence: str
    confidence_score: float
    reasons: list[str] = Field(default_factory=list)
    service: str
    compromised_user: str | None = None
    ip_scope: str | None = None
    ip_country: str | None = None
    ip_city: str | None = None


class IngestOut(BaseModel):
    """Yukleme sonucu."""

    batch_id: int
    source: str
    total_lines: int
    parsed_count: int
    skipped_count: int
    ignored_count: int
    alert_count: int
    created_at: datetime
    skipped_samples: list[str] = Field(default_factory=list)
    alerts: list[AlertOut] = Field(default_factory=list)


class IpStat(BaseModel):
    """IP basina ozet."""

    ip: str
    failures: int
    successes: int
    distinct_usernames: int
    first_seen: datetime
    last_seen: datetime
    scope: str | None = None
    country: str | None = None


class UserStat(BaseModel):
    """En cok hedef alinan kullanicilar."""

    username: str
    failures: int
    successes: int
    distinct_ips: int


class StatsOut(BaseModel):
    """GET /stats ciktisi."""

    total_events: int
    total_failures: int
    total_successes: int
    distinct_ips: int
    alert_count: int
    top_ips: list[IpStat] = Field(default_factory=list)
    top_targeted_users: list[UserStat] = Field(default_factory=list)


class BatchSummary(BaseModel):
    """GET /batches listesindeki ozet kayit."""

    id: int
    source: str
    total_lines: int
    parsed_count: int
    skipped_count: int
    alert_count: int
    created_at: datetime


class ConfigOut(BaseModel):
    """Yururlukteki tespit esikleri."""

    threshold: int
    window_seconds: int
    cooldown_seconds: int
    takeover_failures: int
    takeover_window_seconds: int
    allowlist: list[str] = Field(default_factory=list)
    geoip_enabled: bool = False


class ErrorOut(BaseModel):
    """Hata govdesi."""

    detail: str
