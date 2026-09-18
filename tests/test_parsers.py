"""Log ayristirma testleri."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.geoip import classify, enrich
from app.core.parsers import FAILURE, SUCCESS, parse_lines


def test_ssh_basarisiz_deneme() -> None:
    line = (
        "Sep 17 03:12:01 srv01 sshd[4101]: Failed password for invalid user admin "
        "from 203.0.113.5 port 52344 ssh2"
    )
    event = parse_lines([line], year_hint=2026).events[0]
    assert event.ip == "203.0.113.5"
    assert event.username == "admin"
    assert event.outcome == FAILURE
    assert event.invalid_user is True
    assert event.timestamp == datetime(2026, 9, 17, 3, 12, 1, tzinfo=UTC)


def test_ssh_basarili_giris() -> None:
    line = "Sep 17 09:43:02 srv01 sshd[5216]: Accepted password for deniz from 198.51.100.7 port 44120 ssh2"
    event = parse_lines([line], year_hint=2026).events[0]
    assert event.outcome == SUCCESS
    assert event.username == "deniz"
    assert event.invalid_user is False


def test_ssh_invalid_user_satiri() -> None:
    line = "Sep 17 03:13:10 srv01 sshd[4250]: Invalid user test from 203.0.113.5 port 52360"
    event = parse_lines([line], year_hint=2026).events[0]
    assert event.outcome == FAILURE
    assert event.invalid_user is True


def test_auth_disi_sshd_satiri_bozuk_sayilmaz() -> None:
    """Saglikli bir auth.log'un yarisini 'ayristirilamadi' gostermek yanlis olurdu."""
    line = "Sep 17 03:12:19 srv01 sshd[4107]: Connection closed by 203.0.113.5 port 52374 [preauth]"
    report = parse_lines([line], year_hint=2026)
    assert report.parsed_count == 0
    assert report.skipped_count == 0
    assert report.ignored_count == 1


def test_gelecege_dusen_tarih_bir_yil_geri_alinir() -> None:
    """auth.log yil yazmaz.

    Aralik ayina ait bir satir ocak ayinda islendiginde, "icinde bulunulan yil"
    varsayimi tarihi gelecege atar. Gelecekten gelen bir olay kayan pencereyi
    bozardi; bu yuzden bir yil geri alinir.
    """
    line = "Dec 31 23:59:00 srv01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"
    event = parse_lines([line]).events[0]
    assert event.timestamp <= datetime.now(UTC)
    assert event.timestamp.month == 12


def test_json_satiri() -> None:
    line = '{"ts":"2026-09-17T11:00:01Z","ip":"203.0.113.9","user":"admin","event":"login_failed"}'
    event = parse_lines([line]).events[0]
    assert event.ip == "203.0.113.9"
    assert event.outcome == FAILURE
    assert event.service == "web"


def test_combined_yalnizca_giris_yollarini_sayar() -> None:
    """Her 401 bir brute-force denemesi degil."""
    giris = '203.0.113.77 - - [17/Sep/2026:14:30:00 +0000] "POST /login HTTP/1.1" 401 220 "-" "curl/8"'
    haber = '203.0.113.77 - - [17/Sep/2026:14:30:10 +0000] "GET /haberler HTTP/1.1" 200 5120 "-" "curl/8"'
    report = parse_lines([giris, haber])
    assert report.parsed_count == 1
    assert report.events[0].outcome == FAILURE


def test_bozuk_satir_atilmaz_isaretlenir() -> None:
    report = parse_lines(["bu satir hicbir bicime uymuyor"])
    assert report.parsed_count == 0
    assert report.skipped_count == 1
    assert "bu satir" in report.skipped[0]


@pytest.mark.parametrize(
    "bozuk",
    [
        '{"ts":"gecersiz-tarih","ip":"1.2.3.4","event":"login_failed"}',
        '{"ip":"1.2.3.4","event":"login_failed"}',
        "{bu json degil",
        '203.0.113.77 - - [gecersiz] "POST /login HTTP/1.1" 401 220 "-" "curl/8"',
    ],
)
def test_bozuk_bicimler_cokertmez(bozuk: str) -> None:
    report = parse_lines([bozuk])
    assert report.parsed_count == 0
    assert report.skipped_count == 1


def test_bos_ve_yorum_satirlari_sayilmaz() -> None:
    report = parse_lines(["", "   ", "# yorum"])
    assert report.total_lines == 0
    assert report.skipped_count == 0


def test_olaylar_zamana_gore_siralanir() -> None:
    """Tespit motoru sirali akis bekliyor; garanti burada veriliyor."""
    sonra = "Sep 17 03:15:00 srv01 sshd[2]: Failed password for root from 203.0.113.5 port 2 ssh2"
    once = "Sep 17 03:10:00 srv01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"
    events = parse_lines([sonra, once], year_hint=2026).events
    assert events[0].timestamp < events[1].timestamp


def test_ornek_dosya_uc_bicimi_de_kapsar(sample_log_lines: list[str]) -> None:
    report = parse_lines(sample_log_lines, year_hint=2026)
    assert report.parsed_count > 20
    assert {event.service for event in report.events} == {"ssh", "web"}
    # Dosyanin sonundaki bilerek bozuk satir.
    assert report.skipped_count == 1


# --- IP zenginlestirme ------------------------------------------------------


@pytest.mark.parametrize(
    ("ip", "beklenen"),
    [
        ("8.8.8.8", "public"),
        ("203.0.113.5", "documentation"),
        ("10.0.4.18", "private"),
        ("192.168.1.1", "private"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link-local"),
        ("cok-bozuk", "invalid"),
    ],
)
def test_ip_siniflandirma(ip: str, beklenen: str) -> None:
    assert classify(ip)[0] == beklenen


def test_geoip_veritabani_yoksa_cokmez() -> None:
    """GeoIP bir bonus; yoksa analiz etkilenmemeli."""
    info = enrich("8.8.8.8", db_path=None)
    assert info.scope == "public"
    assert info.country is None
