"""Yukleme, tespit ve istatistik akisi."""

from __future__ import annotations

import json
from dataclasses import replace

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings
from ..core.detector import Alert, detect
from ..core.geoip import enrich
from ..core.parsers import FAILURE, SUCCESS, ParseReport, parse_lines
from ..db.models import AlertRecord, AuthRecord, IngestBatch, SkippedLine


class TooManyLines(ValueError):
    """Yuklenen satir sayisi yapilandirilan siniri asiyor."""


def analyze(
    lines: list[str],
    *,
    settings: Settings,
    year_hint: int | None = None,
    threshold: int | None = None,
    window_seconds: int | None = None,
) -> tuple[ParseReport, list[Alert]]:
    """Satirlari ayristirir ve alarmlari uretir."""
    if len(lines) > settings.max_lines_per_ingest:
        raise TooManyLines(
            f"Tek yuklemede en fazla {settings.max_lines_per_ingest} satir islenebilir "
            f"(gelen: {len(lines)}). Dosyayi parcalara ayirin."
        )

    report = parse_lines(lines, year_hint=year_hint)
    config = settings.detection()
    if threshold is not None:
        config = replace(config, threshold=threshold)
    if window_seconds is not None:
        config = replace(config, window_seconds=window_seconds)
    return report, detect(report.events, config)


async def persist(
    session: AsyncSession,
    report: ParseReport,
    alerts: list[Alert],
    *,
    settings: Settings,
    source: str,
) -> IngestBatch:
    """Olaylari, alarmlari ve bozuk satir orneklerini kaydeder."""
    batch = IngestBatch(
        source=source,
        total_lines=report.total_lines,
        parsed_count=report.parsed_count,
        skipped_count=report.skipped_count,
        ignored_count=report.ignored_count,
        alert_count=len(alerts),
        events=[
            AuthRecord(
                occurred_at=event.timestamp,
                ip=event.ip,
                username=event.username,
                outcome=event.outcome,
                service=event.service,
                invalid_user=event.invalid_user,
                raw_line=event.raw,
            )
            for event in report.events
        ],
        alerts=[
            AlertRecord(
                kind=alert.kind,
                ip=alert.ip,
                attempt_count=alert.attempt_count,
                window_start=alert.window_start,
                window_end=alert.window_end,
                usernames=json.dumps(alert.usernames, ensure_ascii=False),
                confidence=alert.confidence,
                confidence_score=alert.confidence_score,
                reasons=json.dumps(alert.reasons, ensure_ascii=False),
                service=alert.service,
                compromised_user=alert.compromised_user,
                **_ip_fields(alert.ip, settings),
            )
            for alert in alerts
        ],
    )
    session.add(batch)
    await session.flush()

    # Bozuk satirlarin tamami degil, ornegi saklanir: bicimi tamamen yanlis bir
    # dosya yuklendiginde veritabanini o dosyanin kopyasiyla doldurmanin anlami yok.
    for content in report.skipped[: settings.max_skipped_stored]:
        session.add(SkippedLine(batch_id=batch.id, content=content))

    await session.commit()
    await session.refresh(batch)
    return batch


def _ip_fields(ip: str, settings: Settings) -> dict[str, str | None]:
    info = enrich(ip, db_path=settings.geoip_db_path)
    return {"ip_scope": info.scope, "ip_country": info.country, "ip_city": info.city}


async def list_alerts(
    session: AsyncSession,
    *,
    limit: int = 100,
    offset: int = 0,
    ip: str | None = None,
    kind: str | None = None,
    confidence: str | None = None,
) -> list[AlertRecord]:
    """Alarmlari suzerek listeler (en yeni once)."""
    statement = select(AlertRecord).order_by(AlertRecord.window_end.desc())
    if ip:
        statement = statement.where(AlertRecord.ip == ip)
    if kind:
        statement = statement.where(AlertRecord.kind == kind)
    if confidence:
        statement = statement.where(AlertRecord.confidence == confidence)
    statement = statement.limit(limit).offset(offset)
    return list((await session.execute(statement)).scalars().all())


async def list_batches(session: AsyncSession, *, limit: int = 50) -> list[IngestBatch]:
    """Yukleme gecmisini listeler."""
    statement = select(IngestBatch).order_by(IngestBatch.created_at.desc()).limit(limit)
    return list((await session.execute(statement)).scalars().all())


async def skipped_samples(session: AsyncSession, batch_id: int, *, limit: int = 20) -> list[str]:
    """Bir partideki bozuk satir orneklerini getirir."""
    statement = (
        select(SkippedLine.content).where(SkippedLine.batch_id == batch_id).limit(limit)
    )
    return list((await session.execute(statement)).scalars().all())


_FAIL = case((AuthRecord.outcome == FAILURE, 1), else_=0)
_OK = case((AuthRecord.outcome == SUCCESS, 1), else_=0)


async def compute_stats(session: AsyncSession, *, top: int = 10) -> dict[str, object]:
    """IP ve kullanici bazinda ozet istatistikleri hesaplar.

    Toplama veritabaninda yapiliyor: milyonlarca satiri Python'a cekip saymak,
    hem bellegi hem de sureyi gereksiz yere buyutur.
    """
    totals = (
        await session.execute(
            select(
                func.count(AuthRecord.id),
                func.sum(_FAIL),
                func.sum(_OK),
                func.count(func.distinct(AuthRecord.ip)),
            )
        )
    ).one()

    ip_rows = (
        await session.execute(
            select(
                AuthRecord.ip,
                func.sum(_FAIL).label("failures"),
                func.sum(_OK).label("successes"),
                func.count(func.distinct(AuthRecord.username)),
                func.min(AuthRecord.occurred_at),
                func.max(AuthRecord.occurred_at),
            )
            .group_by(AuthRecord.ip)
            .order_by(func.sum(_FAIL).desc())
            .limit(top)
        )
    ).all()

    user_rows = (
        await session.execute(
            select(
                AuthRecord.username,
                func.sum(_FAIL).label("failures"),
                func.sum(_OK).label("successes"),
                func.count(func.distinct(AuthRecord.ip)),
            )
            .group_by(AuthRecord.username)
            .order_by(func.sum(_FAIL).desc())
            .limit(top)
        )
    ).all()

    alert_count = (await session.execute(select(func.count(AlertRecord.id)))).scalar_one()

    return {
        "total_events": totals[0] or 0,
        "total_failures": totals[1] or 0,
        "total_successes": totals[2] or 0,
        "distinct_ips": totals[3] or 0,
        "alert_count": alert_count or 0,
        "ip_rows": ip_rows,
        "user_rows": user_rows,
    }
