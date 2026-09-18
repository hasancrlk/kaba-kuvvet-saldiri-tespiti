"""Kimlik dogrulama loglarinin ayristirilmasi.

Uc bicim destekleniyor: SSH `auth.log`, JSON satirlari ve nginx/apache
combined erisim logu. Her satir once bicim tahmini yapilmadan sirayla
denenmiyor; ilk eslesen ayristirici kazaniyor.

Bozuk satirlar **atilmiyor, isaretleniyor**: bir log yiginininin yuzde kaci
ayristirilamadi bilgisi guvenlik acisindan anlamlidir. Sessizce atmak, formati
degisen bir kaynagin haftalarca hic olay uretmemesi demekti - ve bunun bir
belirtisi olmazdi.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime

FAILURE = "failure"
SUCCESS = "success"

# --- SSH auth.log -----------------------------------------------------------
# Jan 10 03:12:45 srv01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52344 ssh2
_SSH = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<body>.+)$"
)
_SSH_FAILED = re.compile(
    r"^Failed (?:password|publickey) for (?:(?P<invalid>invalid user) )?(?P<user>\S+) from (?P<ip>\S+)"
)
_SSH_ACCEPTED = re.compile(r"^Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)")
_SSH_INVALID = re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)")

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# --- nginx/apache combined --------------------------------------------------
# 203.0.113.5 - admin [10/Jan/2026:03:12:45 +0000] "POST /login HTTP/1.1" 401 220 "-" "curl/8"
_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})'
)
_LOGIN_PATHS = ("/login", "/signin", "/auth", "/session", "/api/login", "/oturum")

_JSON_SUCCESS_WORDS = {"success", "accepted", "ok", "login_success", "true"}
_JSON_FAILURE_WORDS = {"failure", "failed", "denied", "login_failed", "invalid", "false"}


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """Ayristirilmis tek bir kimlik dogrulama olayi."""

    timestamp: datetime
    ip: str
    username: str
    outcome: str  # "success" | "failure"
    service: str  # "ssh" | "web"
    invalid_user: bool = False
    raw: str = ""


def _ssh_timestamp(month: str, day: str, time_text: str, year_hint: int) -> datetime:
    """Yilsiz syslog damgasini tarihe cevirir.

    `auth.log` yil yazmaz. Yil verilmezse icinde bulunulan yil varsayilir; ama
    aralik/ocak gecisinde bu gelecege dusen bir tarih uretir. O durumda bir yil
    geri alinir - aksi halde "gelecekten gelen" olaylar kayan pencereyi bozardi.
    """
    hour, minute, second = (int(part) for part in time_text.split(":"))
    candidate = datetime(
        year_hint, _MONTHS[month], int(day), hour, minute, second, tzinfo=UTC
    )
    if candidate > datetime.now(UTC):
        candidate = candidate.replace(year=year_hint - 1)
    return candidate


def parse_ssh(line: str, *, year_hint: int) -> AuthEvent | None:
    """SSH `auth.log` satirini ayristirir."""
    head = _SSH.match(line.strip())
    if not head:
        return None

    body = head.group("body")
    timestamp = _ssh_timestamp(head.group("month"), head.group("day"), head.group("time"), year_hint)

    failed = _SSH_FAILED.match(body)
    if failed:
        return AuthEvent(
            timestamp=timestamp,
            ip=failed.group("ip"),
            username=failed.group("user"),
            outcome=FAILURE,
            service="ssh",
            invalid_user=bool(failed.group("invalid")),
            raw=line.strip(),
        )

    accepted = _SSH_ACCEPTED.match(body)
    if accepted:
        return AuthEvent(
            timestamp=timestamp,
            ip=accepted.group("ip"),
            username=accepted.group("user"),
            outcome=SUCCESS,
            service="ssh",
            raw=line.strip(),
        )

    invalid = _SSH_INVALID.match(body)
    if invalid:
        return AuthEvent(
            timestamp=timestamp,
            ip=invalid.group("ip"),
            username=invalid.group("user"),
            outcome=FAILURE,
            service="ssh",
            invalid_user=True,
            raw=line.strip(),
        )

    # sshd satiri ama kimlik dogrulamayla ilgisi yok (baglanti kapandi vb.)
    return None


def parse_json_line(line: str) -> AuthEvent | None:
    """JSON bicimli uygulama logu satirini ayristirir."""
    text = line.strip()
    if not text.startswith("{"):
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None

    ip = str(data.get("ip") or data.get("client_ip") or data.get("remote_addr") or "").strip()
    raw_ts = data.get("ts") or data.get("timestamp") or data.get("time")
    if not ip or not raw_ts:
        return None

    try:
        timestamp = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)

    marker = str(
        data.get("event") or data.get("outcome") or data.get("result") or data.get("status") or ""
    ).lower()
    if marker in _JSON_SUCCESS_WORDS:
        outcome = SUCCESS
    elif marker in _JSON_FAILURE_WORDS:
        outcome = FAILURE
    else:
        return None

    return AuthEvent(
        timestamp=timestamp,
        ip=ip,
        username=str(data.get("user") or data.get("username") or "-"),
        outcome=outcome,
        service=str(data.get("service") or "web"),
        raw=text,
    )


def parse_combined(line: str) -> AuthEvent | None:
    """nginx/apache combined erisim logu satirini ayristirir.

    Yalnizca giris yollarina (`/login` vb.) yapilan istekler kimlik dogrulama
    olayi sayilir; her 401 bir brute-force denemesi degildir.
    """
    match = _COMBINED.match(line.strip())
    if not match:
        return None
    if not _is_login_path(match.group("path")):
        return None

    try:
        timestamp = datetime.strptime(match.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None

    status = int(match.group("status"))
    user = match.group("user")
    return AuthEvent(
        timestamp=timestamp.astimezone(UTC),
        ip=match.group("ip"),
        username=user if user != "-" else "-",
        outcome=SUCCESS if status < 400 else FAILURE,
        service="web",
        raw=line.strip(),
    )


def _is_login_path(path: str) -> bool:
    cleaned = path.split("?")[0].lower()
    return any(cleaned.startswith(prefix) for prefix in _LOGIN_PATHS)


def is_irrelevant_line(line: str) -> bool:
    """Satir taninan bir kaynaktan geliyor ama kimlik dogrulamayla ilgisiz mi?

    Uc durumu ayirmak gerekiyor:

    * **olay**        - ayristirildi, tespit motoruna gider.
    * **ilgisiz**     - bicim taniniyor, ama auth satiri degil
      (`Connection closed`, `GET /haberler`). Hata degil.
    * **bozuk**       - bicim taniniyor ama icerigi okunamiyor, ya da hic
      taninmiyor. Bunlar sayilir ve ornekleri saklanir.

    Ilgisiz satirlari bozuk saymak, saglikli bir logun yarisini
    "ayristirilamadi" gostermek olurdu - ve o zaman gercek bir bicim
    degisikligi gurultunun icinde kaybolurdu.
    """
    text = line.strip()
    ssh = _SSH.match(text)
    if ssh:
        body = ssh.group("body")
        return not (
            _SSH_FAILED.match(body) or _SSH_ACCEPTED.match(body) or _SSH_INVALID.match(body)
        )
    combined = _COMBINED.match(text)
    if combined:
        return not _is_login_path(combined.group("path"))
    return False


@dataclass(slots=True)
class ParseReport:
    """Bir log yiginin ayristirma sonucu."""

    events: list[AuthEvent]
    total_lines: int = 0
    skipped: list[str] = None  # type: ignore[assignment]
    ignored_count: int = 0

    def __post_init__(self) -> None:
        if self.skipped is None:
            self.skipped = []

    @property
    def parsed_count(self) -> int:
        return len(self.events)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped)


def parse_lines(lines: list[str], *, year_hint: int | None = None) -> ParseReport:
    """Satirlari ayristirir; taninmayanlari isaretleyerek doner."""
    year = year_hint or datetime.now(UTC).year
    events: list[AuthEvent] = []
    skipped: list[str] = []
    total = 0
    ignored = 0

    for line in lines:
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        total += 1
        event = parse_ssh(text, year_hint=year) or parse_json_line(text) or parse_combined(text)
        if event is not None:
            events.append(event)
        elif is_irrelevant_line(text):
            ignored += 1  # sshd satiri, ama kimlik dogrulamayla ilgisi yok
        else:
            skipped.append(text[:300])

    events.sort(key=lambda item: item.timestamp)
    return ParseReport(
        events=events, total_lines=total, skipped=skipped, ignored_count=ignored
    )
