"""IP zenginlestirme.

Iki katmanli, ve **ag erisimi yok**:

1. Her zaman calisan sinif bilgisi: ozel ag, loopback, baglantiya ozel,
   ayrilmis ya da genel (RFC 1918 / 5735 / 4193). Ic agdan gelen bir brute-force
   ile internetten gelen ayni sey degildir - ilki cogu zaman ele gecirilmis bir
   istemci demektir.
2. `GEOIP_DB_PATH` ile bir MaxMind mmdb verilirse ulke/sehir bilgisi eklenir.
   `geoip2` kurulu degilse ya da dosya yoksa alan bos kalir; tarama etkilenmez.

Ucretsiz bir "IP sorgulama API'si" cagirmak bilincli olarak tercih edilmedi:
inceledigimiz saldirgan IP'lerini ucuncu bir tarafa gondermek, log analizinin
kendisini bir veri sizintisina cevirirdi.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True, slots=True)
class IpInfo:
    """Bir IP adresi hakkinda toplanan bilgi."""

    ip: str
    scope: str  # public | private | documentation | loopback | link-local | reserved | invalid
    version: int | None = None
    country: str | None = None
    city: str | None = None


# RFC 5737 (IPv4) ve RFC 3849 (IPv6): belgelerde ve orneklerde kullanilmak uzere
# ayrilmis bloklar. Python bunlari `is_private` sayiyor - teknik olarak dogru ama
# yaniltici: bu adresler ic agdan degil, ornek veriden gelir. Log analizinde bu
# ayrim onemli, cunku "ic agdan brute-force" ayri bir olay sinifidir.
_DOC_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def classify(ip: str) -> tuple[str, int | None]:
    """IP'yi kapsamina gore siniflar."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid", None
    if any(address in network for network in _DOC_NETWORKS if network.version == address.version):
        return "documentation", address.version
    if address.is_loopback:
        return "loopback", address.version
    if address.is_link_local:
        return "link-local", address.version
    if address.is_private:
        return "private", address.version
    if address.is_reserved or address.is_multicast:
        return "reserved", address.version
    return "public", address.version


@lru_cache(maxsize=1)
def _reader(db_path: str | None):  # noqa: ANN202 - geoip2 opsiyonel bagimlilik
    """MaxMind okuyucusunu bir kez acar; yoksa None doner."""
    if not db_path or not Path(db_path).exists():
        return None
    try:
        import geoip2.database  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        return geoip2.database.Reader(db_path)
    except OSError:
        return None


def enrich(ip: str, *, db_path: str | None = None) -> IpInfo:
    """IP'yi siniflar ve mumkunse cografi bilgiyle zenginlestirir."""
    scope, version = classify(ip)
    info = IpInfo(ip=ip, scope=scope, version=version)
    if scope != "public":
        # Ozel, ayrilmis ve dokumantasyon adreslerinin cografi karsiligi yok.
        return info

    reader = _reader(db_path)
    if reader is None:
        return info
    try:
        response = reader.city(ip)
    except Exception:  # noqa: BLE001 - geoip2 kendi hata sinifini tasiyor
        return info
    return IpInfo(
        ip=ip,
        scope=scope,
        version=version,
        country=response.country.iso_code,
        city=response.city.name,
    )
