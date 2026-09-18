"""Kayan pencere ve yanlis pozitif ayirt etme testleri."""

from __future__ import annotations

from app.core.detector import (
    ACCOUNT_TAKEOVER,
    BRUTE_FORCE,
    DetectionConfig,
    detect,
)
from app.core.parsers import SUCCESS
from tests.conftest import event

CONFIG = DetectionConfig(threshold=5, window_seconds=60, cooldown_seconds=0)


def test_esik_altinda_alarm_yok() -> None:
    alerts = detect([event(index) for index in range(4)], CONFIG)
    assert alerts == []


def test_esige_ulasinca_alarm_uretilir() -> None:
    alerts = detect([event(index) for index in range(5)], CONFIG)
    assert len(alerts) == 1
    assert alerts[0].kind == BRUTE_FORCE
    assert alerts[0].attempt_count == 5
    assert alerts[0].ip == "203.0.113.5"


def test_pencere_disina_tasan_denemeler_sayilmaz() -> None:
    """5 deneme var ama 60 sn'lik pencereye hepsi birden sigmiyor."""
    offsets = [0, 30, 61, 95, 130]
    assert detect([event(offset) for offset in offsets], CONFIG) == []


def test_kayan_pencere_sabit_pencerenin_kacirdigini_yakalar() -> None:
    """Sabit pencerede sayac sifirlandigi icin bu dizi kacardi.

    0-55 arasi 4 deneme, 58-70 arasi 4 deneme. "Her 60 saniyede sifirla"
    mantiginda iki ayri pencerede 4'er deneme gorunur ve alarm uretilmez;
    oysa 58. saniyede son 60 saniyeye bakildiginda 5 deneme vardir.
    """
    offsets = [0, 20, 40, 55, 58, 62, 66, 70]
    alerts = detect([event(offset) for offset in offsets], CONFIG)
    assert alerts
    assert alerts[0].attempt_count >= 5


def test_farkli_ipler_ayri_sayilir() -> None:
    events = [event(index, ip="203.0.113.5") for index in range(3)]
    events += [event(index, ip="203.0.113.6") for index in range(3)]
    events.sort(key=lambda item: item.timestamp)
    assert detect(events, CONFIG) == []


def test_allowlist_ip_atlanir() -> None:
    config = DetectionConfig(threshold=5, window_seconds=60, allowlist=frozenset({"203.0.113.5"}))
    assert detect([event(index) for index in range(10)], config) == []


def test_soguma_suresi_tekrar_alarmi_engeller() -> None:
    config = DetectionConfig(threshold=5, window_seconds=60, cooldown_seconds=300)
    alerts = detect([event(index) for index in range(12)], config)
    assert len(alerts) == 1


# --- Yanlis pozitif ayirt etme ---------------------------------------------


def test_kullanici_tarama_yuksek_guven() -> None:
    """Farkli kullanici adlari + var olmayan hesaplar + sabit aralik = bot."""
    users = ["admin", "oracle", "root", "postgres", "test", "git"]
    events = [
        event(index * 3, username=user, invalid_user=user != "root")
        for index, user in enumerate(users)
    ]
    alert = detect(events, CONFIG)[0]
    assert alert.confidence == "high"
    assert len(alert.usernames) >= 3
    assert any("kullanici tarama" in reason for reason in alert.reasons)


def test_unutkan_kullanici_dusuk_guven() -> None:
    """Tek hesap, duzensiz aralik, daha once basarili giris: insan davranisi."""
    events = [
        event(0, ip="198.51.100.7", username="deniz", outcome=SUCCESS),
        event(600, ip="198.51.100.7", username="deniz"),
        event(604, ip="198.51.100.7", username="deniz"),
        event(627, ip="198.51.100.7", username="deniz"),
        event(631, ip="198.51.100.7", username="deniz"),
        event(650, ip="198.51.100.7", username="deniz"),
    ]
    alerts = detect(events, CONFIG)
    assert len(alerts) == 1
    alert = alerts[0]
    # Alarm yine de uretiliyor - silinmiyor, dusuk guvenle isaretleniyor.
    assert alert.confidence == "low"
    assert alert.usernames == ["deniz"]
    assert any("Tek kullanici" in reason for reason in alert.reasons)


def test_dusuk_guven_alarmi_yine_de_raporlanir() -> None:
    """Sessizce yutmak, gercek bir saldiriyi da yutma riski tasir."""
    events = [event(index * 7, username="deniz") for index in range(6)]
    alerts = detect(events, CONFIG)
    assert alerts
    assert alerts[0].confidence in {"low", "medium", "high"}


# --- Hesap ele gecirme -------------------------------------------------------


def test_basarisizliklardan_sonra_basari_takeover_isaretlenir() -> None:
    events = [event(index * 9, ip="192.0.2.44", username="hasan") for index in range(6)]
    events.append(event(54, ip="192.0.2.44", username="hasan", outcome=SUCCESS))
    alerts = detect(events, CONFIG)
    takeovers = [alert for alert in alerts if alert.kind == ACCOUNT_TAKEOVER]
    assert len(takeovers) == 1
    assert takeovers[0].compromised_user == "hasan"
    assert takeovers[0].confidence == "high"


def test_baska_kullaniciyla_basari_takeover_sayilmaz() -> None:
    """Basarisizliklar 'admin' icin, basari 'deploy' icin: ayni hesap degil."""
    events = [event(index * 9, ip="192.0.2.44", username="admin") for index in range(6)]
    events.append(event(54, ip="192.0.2.44", username="deploy", outcome=SUCCESS))
    alerts = detect(events, CONFIG)
    assert not [alert for alert in alerts if alert.kind == ACCOUNT_TAKEOVER]


def test_temiz_basari_alarm_uretmez() -> None:
    events = [event(0, ip="10.0.0.5", username="deploy", outcome=SUCCESS)]
    assert detect(events, CONFIG) == []


def test_bos_girdi_guvenli() -> None:
    assert detect([], CONFIG) == []
