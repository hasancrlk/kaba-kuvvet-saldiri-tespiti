"""HTTP uc noktalari."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings, get_settings
from ..core.geoip import classify
from ..db.models import AlertRecord, IngestBatch
from ..db.session import get_session
from ..schemas import (
    AlertOut,
    BatchSummary,
    ConfigOut,
    ErrorOut,
    IngestOut,
    IngestRequest,
    IpStat,
    StatsOut,
    UserStat,
)
from ..services import ingest_service

router = APIRouter()

MAX_UPLOAD_BYTES = 50 * 1024 * 1024


def _loads(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def _alert_out(record: AlertRecord) -> AlertOut:
    return AlertOut(
        id=record.id,
        batch_id=record.batch_id,
        kind=record.kind,
        ip=record.ip,
        attempt_count=record.attempt_count,
        window_start=record.window_start,
        window_end=record.window_end,
        window_seconds=round((record.window_end - record.window_start).total_seconds(), 2),
        usernames=_loads(record.usernames),
        confidence=record.confidence,
        confidence_score=record.confidence_score,
        reasons=_loads(record.reasons),
        service=record.service,
        compromised_user=record.compromised_user,
        ip_scope=record.ip_scope,
        ip_country=record.ip_country,
        ip_city=record.ip_city,
    )


def _ingest_out(batch: IngestBatch, samples: list[str]) -> IngestOut:
    return IngestOut(
        batch_id=batch.id,
        source=batch.source,
        total_lines=batch.total_lines,
        parsed_count=batch.parsed_count,
        skipped_count=batch.skipped_count,
        ignored_count=batch.ignored_count,
        alert_count=batch.alert_count,
        created_at=batch.created_at,
        skipped_samples=samples,
        alerts=[_alert_out(record) for record in batch.alerts],
    )


@router.get("/health", tags=["system"], summary="Servis saglik kontrolu")
async def health() -> dict[str, str]:
    """Konteyner saglik kontrolu icin hafif uc nokta."""
    return {"status": "ok"}


@router.get("/config", response_model=ConfigOut, tags=["system"], summary="Yururlukteki tespit esikleri")
async def config(settings: Settings = Depends(get_settings)) -> ConfigOut:
    """Hangi esikle calisildigini seffaf biçimde doner.

    Bir alarmin neden uretildigi (ya da uretilmedigi), esikler gorulmeden
    tartisilamaz.
    """
    detection = settings.detection()
    return ConfigOut(
        threshold=detection.threshold,
        window_seconds=detection.window_seconds,
        cooldown_seconds=detection.cooldown_seconds,
        takeover_failures=detection.takeover_failures,
        takeover_window_seconds=detection.takeover_window_seconds,
        allowlist=sorted(detection.allowlist),
        geoip_enabled=bool(settings.geoip_db_path),
    )


@router.post(
    "/ingest",
    response_model=IngestOut,
    status_code=status.HTTP_201_CREATED,
    tags=["ingest"],
    summary="Log satirlarini yukler, ayristirir ve alarm uretir",
    responses={400: {"model": ErrorOut, "description": "Satir siniri asildi ya da govde gecersiz"}},
)
async def ingest(
    payload: IngestRequest,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> IngestOut:
    """Ham log satirlarini isler; bozuk satirlar atlanmaz, sayilir."""
    try:
        report, alerts = ingest_service.analyze(
            payload.lines,
            settings=settings,
            year_hint=payload.year_hint,
            threshold=payload.threshold,
            window_seconds=payload.window_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    batch = await ingest_service.persist(
        session, report, alerts, settings=settings, source=payload.source
    )
    return _ingest_out(batch, report.skipped[:20])


@router.post(
    "/ingest/file",
    response_model=IngestOut,
    status_code=status.HTTP_201_CREATED,
    tags=["ingest"],
    summary="Log dosyasi yukler",
    responses={400: {"model": ErrorOut, "description": "Dosya bos, cok buyuk ya da okunamadi"}},
)
async def ingest_file(
    file: UploadFile = File(..., description="auth.log, JSON satirlari ya da combined erisim logu"),
    year_hint: int | None = Query(default=None, ge=1970, le=2999),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> IngestOut:
    """Dosya yoluyla yukleme."""
    raw = await file.read()
    if not raw:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Dosya bos.")
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Dosya cok buyuk ({len(raw)} bayt); sinir {MAX_UPLOAD_BYTES} bayt.",
        )

    # Log dosyalari sik sik bozuk bayt icerir; 'replace' ile tek bir kotu bayt
    # yuzunden tum yuklemeyi reddetmekten kacinilir.
    lines = raw.decode("utf-8", errors="replace").splitlines()
    try:
        report, alerts = ingest_service.analyze(lines, settings=settings, year_hint=year_hint)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    batch = await ingest_service.persist(
        session, report, alerts, settings=settings, source=file.filename or "upload"
    )
    return _ingest_out(batch, report.skipped[:20])


@router.get(
    "/alerts",
    response_model=list[AlertOut],
    tags=["alerts"],
    summary="Tespit edilen brute-force olaylarini listeler",
)
async def alerts(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    ip: str | None = Query(default=None, description="Tek bir kaynak IP'ye suz."),
    kind: str | None = Query(default=None, description="brute_force | possible_account_takeover"),
    confidence: str | None = Query(default=None, description="low | medium | high"),
    session: AsyncSession = Depends(get_session),
) -> list[AlertOut]:
    """Her alarm icin kaynak IP, deneme sayisi, zaman araligi ve hedef kullanicilar."""
    records = await ingest_service.list_alerts(
        session, limit=limit, offset=offset, ip=ip, kind=kind, confidence=confidence
    )
    return [_alert_out(record) for record in records]


@router.get("/stats", response_model=StatsOut, tags=["alerts"], summary="Ozet istatistikler")
async def stats(
    top: int = Query(default=10, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
) -> StatsOut:
    """IP basina basarili/basarisiz sayilari ve en cok hedef alinan kullanicilar."""
    data = await ingest_service.compute_stats(session, top=top)
    return StatsOut(
        total_events=data["total_events"],  # type: ignore[arg-type]
        total_failures=data["total_failures"],  # type: ignore[arg-type]
        total_successes=data["total_successes"],  # type: ignore[arg-type]
        distinct_ips=data["distinct_ips"],  # type: ignore[arg-type]
        alert_count=data["alert_count"],  # type: ignore[arg-type]
        top_ips=[
            IpStat(
                ip=row[0],
                failures=row[1] or 0,
                successes=row[2] or 0,
                distinct_usernames=row[3] or 0,
                first_seen=row[4],
                last_seen=row[5],
                scope=classify(row[0])[0],
            )
            for row in data["ip_rows"]  # type: ignore[union-attr]
        ],
        top_targeted_users=[
            UserStat(
                username=row[0],
                failures=row[1] or 0,
                successes=row[2] or 0,
                distinct_ips=row[3] or 0,
            )
            for row in data["user_rows"]  # type: ignore[union-attr]
        ],
    )


@router.get(
    "/batches",
    response_model=list[BatchSummary],
    tags=["ingest"],
    summary="Yukleme gecmisini listeler",
)
async def batches(
    limit: int = Query(default=50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
) -> list[BatchSummary]:
    """Hangi dosyanin ne kadarinin ayristirilabildigini gosterir."""
    records = await ingest_service.list_batches(session, limit=limit)
    return [
        BatchSummary(
            id=record.id,
            source=record.source,
            total_lines=record.total_lines,
            parsed_count=record.parsed_count,
            skipped_count=record.skipped_count,
            alert_count=record.alert_count,
            created_at=record.created_at,
        )
        for record in records
    ]


@router.get(
    "/batches/{batch_id}/skipped",
    response_model=list[str],
    tags=["ingest"],
    summary="Ayristirilamayan satir ornekleri",
)
async def skipped(
    batch_id: int,
    limit: int = Query(default=20, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
) -> list[str]:
    """Bicimi degisen bir log kaynagini fark etmenin tek yolu bunlari gormek."""
    return await ingest_service.skipped_samples(session, batch_id, limit=limit)
