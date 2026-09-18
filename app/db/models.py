"""Log olaylari, alarmlar ve yukleme partileri."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Ortak taban sinif."""


def _utcnow() -> datetime:
    return datetime.now(UTC)


class IngestBatch(Base):
    """Tek bir log yukleme islemi."""

    __tablename__ = "ingest_batches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(255), default="upload")
    total_lines: Mapped[int] = mapped_column(Integer, default=0)
    parsed_count: Mapped[int] = mapped_column(Integer, default=0)
    skipped_count: Mapped[int] = mapped_column(Integer, default=0)
    ignored_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    events: Mapped[list[AuthRecord]] = relationship(
        back_populates="batch", cascade="all, delete-orphan"
    )
    alerts: Mapped[list[AlertRecord]] = relationship(
        back_populates="batch", cascade="all, delete-orphan", lazy="selectin"
    )


class AuthRecord(Base):
    """Ayristirilmis tek bir kimlik dogrulama olayi."""

    __tablename__ = "auth_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    batch_id: Mapped[int] = mapped_column(ForeignKey("ingest_batches.id", ondelete="CASCADE"), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    username: Mapped[str] = mapped_column(String(255), index=True)
    outcome: Mapped[str] = mapped_column(String(16), index=True)
    service: Mapped[str] = mapped_column(String(32), default="ssh")
    invalid_user: Mapped[bool] = mapped_column(default=False)
    raw_line: Mapped[str | None] = mapped_column(Text, nullable=True)

    batch: Mapped[IngestBatch] = relationship(back_populates="events")


class AlertRecord(Base):
    """Uretilen tek bir alarm."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    batch_id: Mapped[int] = mapped_column(ForeignKey("ingest_batches.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(48), index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    attempt_count: Mapped[int] = mapped_column(Integer)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    usernames: Mapped[str] = mapped_column(Text, default="[]")
    confidence: Mapped[str] = mapped_column(String(16), index=True)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    reasons: Mapped[str] = mapped_column(Text, default="[]")
    service: Mapped[str] = mapped_column(String(32), default="ssh")
    compromised_user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_scope: Mapped[str | None] = mapped_column(String(24), nullable=True)
    ip_country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    ip_city: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    batch: Mapped[IngestBatch] = relationship(back_populates="alerts")


class SkippedLine(Base):
    """Ayristirilamayan satir.

    Atmak yerine saklaniyor: bir log kaynaginin bicimi degistiginde bunu
    gorebilmenin tek yolu, neyi anlayamadigimizi kaydetmek.
    """

    __tablename__ = "skipped_lines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    batch_id: Mapped[int] = mapped_column(ForeignKey("ingest_batches.id", ondelete="CASCADE"), index=True)
    content: Mapped[str] = mapped_column(Text)


Index("ix_auth_events_ip_time", AuthRecord.ip, AuthRecord.occurred_at)
Index("ix_alerts_ip_kind", AlertRecord.ip, AlertRecord.kind)
