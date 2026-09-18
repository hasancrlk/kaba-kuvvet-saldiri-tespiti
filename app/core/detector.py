"""Kayan zaman penceresi ile brute-force tespiti.

## Kayan pencere neden "sayac + sifirla" degil?

Sabit pencere (her 60 sn'de sayaci sifirla) kolay yazilir ve **atlatilmasi da o
kadar kolaydir**: esik 5 ise, saldirgan pencerenin sonunda 4, hemen ardindan
yeni pencerenin basinda 4 deneme yapar; 8 saniyede 8 deneme gecer ve hicbir
alarm uretilmez.

Kayan pencere her yeni denemede "son Y saniyedeki deneme sayisi"na bakar:

    deque(baslangic)  ──►  yeni olay eklenir
                           soldan, [simdi - Y] oncesindekiler atilir
                           kalan sayi >= X ise alarm

Maliyet dogrusal: her olay deque'e bir kez girer, bir kez cikar. 1 milyon
satirlik bir auth.log icin de tek gecis yeterli.

## Normal kullanici hatasi ile saldiri nasil ayriliyor?

Esigi gecen her yigin saldiri degildir. Parolasini unutmus bir kullanici da 60
saniyede 6 kez deneyebilir. Fark, *davranisin sekli*:

| Sinyal | Insan | Bot |
|---|---|---|
| Denenen kullanici adi sayisi | 1 | cogu zaman cok |
| Var olmayan kullanici denemesi | yok | sik (`invalid user`) |
| Denemeler arasi aralik | duzensiz | duzenli (dusuk sapma) |
| Ayni IP'den gecmis basarili giris | genelde var | genelde yok |

Bu sinyaller bir **guven skoruna** cevrilir ve alarm `low`/`medium`/`high`
olarak etiketlenir. Esigi gecen ama insan gibi davranan yiginlar silinmez -
`low` guvenle raporlanir. Karar analistte kalir; sessizce yutmak, gercek bir
saldiriyi da yutma riski tasir.
"""

from __future__ import annotations

import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .parsers import FAILURE, SUCCESS, AuthEvent

BRUTE_FORCE = "brute_force"
ACCOUNT_TAKEOVER = "possible_account_takeover"


@dataclass(slots=True)
class Alert:
    """Uretilen tek bir alarm."""

    kind: str
    ip: str
    attempt_count: int
    window_start: datetime
    window_end: datetime
    usernames: list[str] = field(default_factory=list)
    confidence: str = "medium"
    confidence_score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    service: str = "ssh"
    compromised_user: str | None = None

    @property
    def window_seconds(self) -> float:
        return round((self.window_end - self.window_start).total_seconds(), 2)


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    """Tespit esikleri - tamami yapilandirilabilir."""

    threshold: int = 5
    window_seconds: int = 60
    allowlist: frozenset[str] = frozenset()
    # Ayni IP icin pes pese alarm uretmemek icin soguma suresi.
    cooldown_seconds: int = 300
    # Basarili giristen once bu kadar basarisizlik varsa ele gecirme suphesi.
    takeover_failures: int = 5
    takeover_window_seconds: int = 600


def _interval_regularity(timestamps: list[datetime]) -> float | None:
    """Denemeler arasi araligin duzenliligi: 0 (duzensiz) - 1 (saat gibi).

    Bir insan 3 sn, sonra 12 sn, sonra 40 sn bekler. Bot sabit araliklarla
    gelir. Standart sapmanin ortalamaya oranini (varyasyon katsayisi) tersine
    cevirip 0-1 araligina sikistiriyoruz.
    """
    if len(timestamps) < 3:
        return None
    gaps = [
        (timestamps[index + 1] - timestamps[index]).total_seconds()
        for index in range(len(timestamps) - 1)
    ]
    mean = statistics.fmean(gaps)
    if mean <= 0:
        return 1.0
    deviation = statistics.pstdev(gaps)
    return max(0.0, min(1.0, 1.0 - (deviation / mean)))


def _score(
    *,
    attempts: int,
    threshold: int,
    usernames: set[str],
    invalid_users: int,
    regularity: float | None,
    ip_had_success: bool,
) -> tuple[float, list[str]]:
    """Alarmin gercek bir saldiri olma guvenini 0-1 arasi puanlar."""
    score = 0.35
    reasons: list[str] = []

    excess = attempts / max(1, threshold)
    if excess >= 3:
        score += 0.25
        reasons.append(f"Esigin {excess:.1f} kati deneme ({attempts}).")
    elif excess >= 1.5:
        score += 0.12
        reasons.append(f"Esigin belirgin uzerinde deneme ({attempts}).")

    # Web erisim loglarinda kullanici adi cogu zaman yoktur ("-"). Bunu "tek
    # kullanici" sayip indirim uygulamak, gercek bir bot yigininin puanini
    # haksiz yere dusururdu - sinyal yok, indirim de yok.
    named = {user for user in usernames if user not in {"-", "", "unknown"}}
    if len(named) >= 3:
        score += 0.25
        reasons.append(f"{len(named)} farkli kullanici adi denendi (kullanici tarama).")
    elif len(named) == 1:
        score -= 0.15
        reasons.append("Tek kullanici adi - parolasini unutmus bir kullanici olabilir.")
    elif not named:
        reasons.append("Log kullanici adi tasimiyor; hesap bazli sinyal degerlendirilemedi.")

    if invalid_users:
        score += 0.20
        reasons.append(f"{invalid_users} deneme var olmayan kullanici adina yapildi.")

    if regularity is not None and regularity >= 0.8:
        score += 0.15
        reasons.append("Denemeler neredeyse sabit araliklarla geldi (otomasyon izi).")
    elif regularity is not None and regularity <= 0.35:
        score -= 0.10
        reasons.append("Denemeler duzensiz aralikli - insan davranisina yakin.")

    if ip_had_success:
        score -= 0.20
        reasons.append("Bu IP daha once basariyla giris yapmis (bilinen kaynak).")

    return max(0.0, min(1.0, score)), reasons


def _label(score: float) -> str:
    if score >= 0.7:
        return "high"
    if score >= 0.45:
        return "medium"
    return "low"


def detect(events: list[AuthEvent], config: DetectionConfig | None = None) -> list[Alert]:
    """Olay akisinda brute-force ve olasi hesap ele gecirme alarmlari uretir.

    Olaylar zamana gore sirali gelmelidir (`parse_lines` bunu garanti eder).
    """
    settings = config or DetectionConfig()
    window = timedelta(seconds=settings.window_seconds)
    takeover_window = timedelta(seconds=settings.takeover_window_seconds)

    failures: dict[str, deque[AuthEvent]] = defaultdict(deque)
    success_seen: set[str] = set()
    last_alert_at: dict[str, datetime] = {}
    alerts: list[Alert] = []

    for event in events:
        if event.ip in settings.allowlist:
            continue

        if event.outcome == SUCCESS:
            recent = failures.get(event.ip)
            if recent:
                # Basaridan hemen once yogun basarisizlik: klasik ele gecirme izi.
                preceding = [
                    item
                    for item in recent
                    if event.timestamp - item.timestamp <= takeover_window
                    and item.username == event.username
                ]
                if len(preceding) >= settings.takeover_failures:
                    alerts.append(
                        Alert(
                            kind=ACCOUNT_TAKEOVER,
                            ip=event.ip,
                            attempt_count=len(preceding),
                            window_start=preceding[0].timestamp,
                            window_end=event.timestamp,
                            usernames=[event.username],
                            confidence="high",
                            confidence_score=0.9,
                            reasons=[
                                f"{len(preceding)} basarisiz denemenin ardindan ayni kullanici "
                                "adiyla basarili giris yapildi."
                            ],
                            service=event.service,
                            compromised_user=event.username,
                        )
                    )
                # Basarili giristen sonra sayac sifirlanir: ayni yigini tekrar
                # tekrar raporlamanin anlami yok.
                recent.clear()
            success_seen.add(event.ip)
            continue

        if event.outcome != FAILURE:
            continue

        bucket = failures[event.ip]
        bucket.append(event)
        while bucket and event.timestamp - bucket[0].timestamp > window:
            bucket.popleft()

        if len(bucket) < settings.threshold:
            continue

        previous = last_alert_at.get(event.ip)
        if previous and (event.timestamp - previous).total_seconds() < settings.cooldown_seconds:
            continue

        usernames = {item.username for item in bucket}
        score, reasons = _score(
            attempts=len(bucket),
            threshold=settings.threshold,
            usernames=usernames,
            invalid_users=sum(1 for item in bucket if item.invalid_user),
            regularity=_interval_regularity([item.timestamp for item in bucket]),
            ip_had_success=event.ip in success_seen,
        )
        alerts.append(
            Alert(
                kind=BRUTE_FORCE,
                ip=event.ip,
                attempt_count=len(bucket),
                window_start=bucket[0].timestamp,
                window_end=event.timestamp,
                usernames=sorted(usernames),
                confidence=_label(score),
                confidence_score=round(score, 2),
                reasons=reasons,
                service=event.service,
            )
        )
        last_alert_at[event.ip] = event.timestamp

    return alerts
