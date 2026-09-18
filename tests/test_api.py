"""API uc noktasi testleri."""

from __future__ import annotations

from httpx import AsyncClient

BRUTE_LINES = [
    f"Sep 17 03:12:{second:02d} srv01 sshd[41{second:02d}]: Failed password for invalid user "
    f"{user} from 203.0.113.5 port 5234{second} ssh2"
    for second, user in enumerate(["admin", "oracle", "root", "postgres", "test", "git"], start=1)
]


async def test_health(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_esikler_seffaf_sunulur(client: AsyncClient) -> None:
    """Bir alarmin neden uretildigi, esikler gorulmeden tartisilamaz."""
    body = (await client.get("/config")).json()
    assert body["threshold"] == 5
    assert body["window_seconds"] == 60


async def test_ingest_alarm_uretir(client: AsyncClient) -> None:
    response = await client.post(
        "/ingest", json={"lines": BRUTE_LINES, "source": "test", "year_hint": 2026}
    )
    assert response.status_code == 201
    body = response.json()
    assert body["parsed_count"] == 6
    assert body["skipped_count"] == 0
    assert body["alert_count"] >= 1

    alert = body["alerts"][0]
    assert alert["ip"] == "203.0.113.5"
    assert alert["kind"] == "brute_force"
    assert alert["confidence"] == "high"
    assert alert["ip_scope"] == "documentation"  # RFC 5737 ornek adresi
    assert alert["reasons"]


async def test_bozuk_satirlar_sayilir_ve_saklanir(client: AsyncClient) -> None:
    """Sessizce atmak, bicimi degisen bir kaynagi gorunmez yapardi."""
    response = await client.post(
        "/ingest", json={"lines": [*BRUTE_LINES, "tamamen anlamsiz satir"], "year_hint": 2026}
    )
    body = response.json()
    assert body["skipped_count"] == 1
    assert "tamamen anlamsiz" in body["skipped_samples"][0]

    stored = await client.get(f"/batches/{body['batch_id']}/skipped")
    assert stored.status_code == 200
    assert stored.json()


async def test_dosya_yukleme(client: AsyncClient, sample_log_lines: list[str]) -> None:
    content = "\n".join(sample_log_lines).encode()
    response = await client.post(
        "/ingest/file",
        params={"year_hint": 2026},
        files={"file": ("sample-auth.log", content, "text/plain")},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["parsed_count"] > 20
    assert body["alert_count"] >= 2
    kinds = {alert["kind"] for alert in body["alerts"]}
    assert "possible_account_takeover" in kinds


async def test_bos_dosya_400(client: AsyncClient) -> None:
    response = await client.post(
        "/ingest/file", files={"file": ("bos.log", b"", "text/plain")}
    )
    assert response.status_code == 400


async def test_alerts_suzulebilir(client: AsyncClient) -> None:
    await client.post("/ingest", json={"lines": BRUTE_LINES, "year_hint": 2026})

    hepsi = await client.get("/alerts")
    assert hepsi.status_code == 200
    assert hepsi.json()

    ip_ile = await client.get("/alerts", params={"ip": "203.0.113.5"})
    assert all(item["ip"] == "203.0.113.5" for item in ip_ile.json())

    bos = await client.get("/alerts", params={"ip": "198.51.100.200"})
    assert bos.json() == []

    tur_ile = await client.get("/alerts", params={"kind": "brute_force"})
    assert all(item["kind"] == "brute_force" for item in tur_ile.json())


async def test_stats(client: AsyncClient) -> None:
    await client.post("/ingest", json={"lines": BRUTE_LINES, "year_hint": 2026})
    body = (await client.get("/stats")).json()
    assert body["total_events"] > 0
    assert body["total_failures"] > 0
    assert body["distinct_ips"] >= 1
    assert body["top_ips"][0]["failures"] > 0
    assert body["top_ips"][0]["scope"] in {"public", "documentation"}
    assert body["top_targeted_users"]


async def test_batches_listelenir(client: AsyncClient) -> None:
    await client.post("/ingest", json={"lines": BRUTE_LINES, "year_hint": 2026})
    body = (await client.get("/batches")).json()
    assert body
    assert body[0]["parsed_count"] >= 1


async def test_bos_govde_422(client: AsyncClient) -> None:
    assert (await client.post("/ingest", json={"lines": []})).status_code == 422


async def test_istekle_esik_gecici_olarak_degistirilebilir(client: AsyncClient) -> None:
    """Analist 'esigi 3 yapsam ne cikardi' diye bakabilmeli."""
    uc_satir = BRUTE_LINES[:3]
    varsayilan = (await client.post("/ingest", json={"lines": uc_satir, "year_hint": 2026})).json()
    assert varsayilan["alert_count"] == 0

    dusuk_esik = (
        await client.post(
            "/ingest", json={"lines": uc_satir, "year_hint": 2026, "threshold": 3}
        )
    ).json()
    assert dusuk_esik["alert_count"] == 1
