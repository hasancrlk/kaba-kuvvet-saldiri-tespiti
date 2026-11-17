# 🚨 Kaba Kuvvet Saldırı Tespiti (AuthWatch)

<p align="center">
  <em>Kimlik Doğrulama Log Analizi ve Brute-Force Tespiti</em><br>
  <strong>Kayan zaman penceresi · yanlış pozitif ayıklama · hesap ele geçirme tespiti</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12+-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/Tespit-sliding%20window-red" alt="Sliding window">
  <img src="https://img.shields.io/badge/DB-PostgreSQL%20%7C%20SQLite-336791?logo=postgresql" alt="DB">
  <img src="https://img.shields.io/badge/Tests-48%20passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
</p>

---

## 🧭 Kısaca: Bu Proje Ne İşe Yarar?

Bir sunucuya her giriş denemesi log dosyasına bir satır olarak yazılır. Bu
araç o satırları okur ve birinin **şifre deneye deneye hesaba girmeye
çalışıp çalışmadığını** bulur. Bu saldırının adı "kaba kuvvet" ya da
brute-force'tur.

Asıl iş, iki durumu birbirinden ayırmaktır: şifresini unutup üç kez yanlış
yazan çalışan ile saniyede onlarca kullanıcı adı deneyen bot. İkisi de
"başarısız giriş" olarak görünür. AuthWatch her alarma bir **güven
seviyesi** (düşük / orta / yüksek) verir ve bu seviyeyi **neden** verdiğini
düz cümlelerle yazar. Bir dizi başarısız denemenin ardından gelen başarılı
giriş ayrıca işaretlenir, çünkü bu **hesabın ele geçirilmiş olabileceğini**
gösterir.

**Kimin işine yarar?** Sunucu yöneticilerinin, SOC / mavi takım analistlerinin
ve log analizini öğrenen siber güvenlik öğrencilerinin.

| Siz verirsiniz | Araç size verir |
|---|---|
| SSH `auth.log`, nginx/apache erişim logu ya da JSON satırları | Alarm listesi: saldıran IP, denenen kullanıcı adları, güven seviyesi, gerekçeler |
| İsterseniz eşik ("60 saniyede 5 deneme") ve hiç alarm üretilmeyecek IP'ler | IP ve kullanıcı bazında istatistik, okunamayan satırların dökümü |

### ⚡ 3 Adımda Kullanım

1. **Kurun ve başlatın:** `docker compose up --build`. Docker kullanmıyorsanız
   aşağıdaki [Kurulum](#-kurulum) bölümüne bakın. Arayüz
   http://localhost:8000/docs adresinde açılır.
2. **Depodaki örnek logu yükleyin:**
   ```bash
   curl -F "file=@data/sample-auth.log" "http://localhost:8000/ingest/file?year_hint=2026"
   ```
3. **Yüksek güvenli alarmlara bakın:**
   ```bash
   curl "http://localhost:8000/alerts?confidence=high"
   ```

Kendi sunucunuzda denemek için 2. adımdaki dosyayı `/var/log/auth.log` ile
değiştirmeniz yeterli.

---

## 📋 İçindekiler

- [Genel Bakış](#-genel-bakış)
- [Zor Kısım 1: Kayan Zaman Penceresi](#-zor-kısım-1-kayan-zaman-penceresi)
- [Zor Kısım 2: Unutkan Kullanıcı mı, Bot mu?](#-zor-kısım-2-unutkan-kullanıcı-mı-bot-mu)
- [Hesap Ele Geçirme Tespiti](#-hesap-ele-geçirme-tespiti)
- [Log Ayrıştırma: Üç Durum](#-log-ayrıştırma-üç-durum)
- [IP Zenginleştirme](#-ip-zenginleştirme)
- [Mimari](#-mimari)
- [Kurulum](#-kurulum)
- [API Referansı](#-api-referansı)
- [Testler](#-testler)
- [Proje Yapısı](#-proje-yapısı)
- [Bilinen Sınırlar](#-bilinen-sınırlar)

---

## 🏗 Genel Bakış

AuthWatch, SSH ve web uygulaması kimlik doğrulama loglarını işler, aynı IP'den
kısa sürede yapılan çok sayıda başarısız girişi tespit eder ve alarm üretir.

| Özellik | Açıklama |
|---|---|
| ⏱ **Kayan pencere** | `deque` ile O(n); sabit pencerenin kaçırdığını yakalar |
| 🎯 **Güven skoru** | Her alarm `low` / `medium` / `high` etiketiyle ve **gerekçeyle** gelir |
| 🔓 **Ele geçirme tespiti** | Başarısızlıklar ardından gelen başarılı giriş işaretlenir |
| 📄 **Üç log biçimi** | SSH `auth.log`, JSON satırları, nginx/apache combined |
| 🧾 **Bozuk satır muhasebesi** | Atılmaz — sayılır, örnekleri saklanır |
| 🌍 **IP zenginleştirme** | Kapsam sınıfı her zaman; ülke/şehir opsiyonel MaxMind ile |
| ⚙️ **Yapılandırılabilir eşik** | `X deneme / Y saniye`, allowlist, soğuma süresi |
| 📊 **İstatistik** | IP ve kullanıcı bazında toplama — veritabanında |
| 🐳 **Docker** | `docker compose up` ile PostgreSQL'li ortam |

---

## ⏱ Zor Kısım 1: Kayan Zaman Penceresi

### Sabit pencere neden yetmiyor?

"Her 60 saniyede sayacı sıfırla" yaklaşımı kolay yazılır ve **atlatılması da o
kadar kolaydır**. Eşik 5 ise saldırgan şunu yapar:

```
pencere 1                          pencere 2
├───────────────────────────┤      ├──────────────────────
     ✗  ✗  ✗  ✗  (4 deneme)         ✗  ✗  ✗  ✗  (4 deneme)
                         ↑ 55. sn   ↑ 62. sn

sabit pencere : iki ayrı pencerede 4'er deneme → ALARM YOK
kayan pencere : 62. sn'de son 60 sn'ye bak → 8 deneme → ALARM
```

Bu dizi depodaki testte birebir var
(`test_kayan_pencere_sabit_pencerenin_kacirdigini_yakalar`).

### Nasıl çalışıyor?

Her IP için bir `deque` tutulur. Yeni bir başarısız deneme geldiğinde:

```python
bucket.append(event)
while bucket and event.timestamp - bucket[0].timestamp > window:
    bucket.popleft()          # penceredan çıkanları at
if len(bucket) >= threshold:
    alarm_üret()
```

Maliyet doğrusal: her olay deque'e bir kez girer, bir kez çıkar. 1 milyon
satırlık bir `auth.log` için tek geçiş yeterli.

### Soğuma süresi

Eşik aşıldıktan sonra her yeni deneme yeni bir alarm üretseydi, 500 denemelik
bir saldırı 496 alarm demekti. `DETECT_COOLDOWN_SECONDS` (varsayılan 300 sn)
aynı IP için tekrarı susturur — saldırı biter, sonraki dalga yeniden raporlanır.

---

## 🧠 Zor Kısım 2: Unutkan Kullanıcı mı, Bot mu?

Eşiği geçen her yığın saldırı değildir. Parolasını unutmuş bir kullanıcı da 60
saniyede 6 kez deneyebilir. Fark, denemelerin **şeklinde**:

| Sinyal | İnsan | Bot | Puan etkisi |
|---|---|---|---:|
| Denenen kullanıcı adı sayısı | 1 | çoğu zaman çok | 3+ ise **+0.25**, 1 ise **−0.15**, yoksa nötr |
| Var olmayan kullanıcı (`invalid user`) | yok | sık | **+0.20** |
| Denemeler arası aralık | düzensiz | düzenli | ≥0.8 düzenlilik **+0.15**, ≤0.35 **−0.10** |
| Eşiğin kaç katı deneme | az | çok | 3× ise **+0.25** |
| Bu IP'den geçmiş başarılı giriş | genelde var | genelde yok | **−0.20** |

Düzenlilik, denemeler arası boşlukların **varyasyon katsayısından** hesaplanır:
bir insan 3 sn, sonra 12 sn, sonra 40 sn bekler; bot saat gibi gelir.

Toplam skor etiketlenir: `≥0.70` → **high**, `≥0.45` → **medium**, altı → **low**.

### Üç gerçek örnek (depodaki `data/sample-auth.log`)

```
203.0.113.5  →  5 farklı kullanıcı, 4'ü invalid, tam 3 sn aralıklarla
                confidence: high (0.95)
                "5 farkli kullanici adi denendi (kullanici tarama)."
                "4 deneme var olmayan kullanici adina yapildi."
                "Denemeler neredeyse sabit araliklarla geldi (otomasyon izi)."

198.51.100.7 →  tek hesap (deniz), 6/25/6/13 sn düzensiz aralık, aynı IP'den
                sabah başarılı giriş yapılmış
                confidence: low (0.0)
                "Tek kullanici adi - parolasini unutmus bir kullanici olabilir."
                "Bu IP daha once basariyla giris yapmis (bilinen kaynak)."

203.0.113.77 →  combined log, kullanıcı adı yok ("-"), 2 sn aralıklarla
                confidence: medium (0.5)
                "Log kullanici adi tasimiyor; hesap bazli sinyal degerlendirilemedi."
```

> **Kullanıcı adı taşımayan loglar.** Web erişim logunda kullanıcı alanı çoğu
> zaman `-` gelir. Bunu "tek kullanıcı" sayıp indirim uygulamak, gerçek bir bot
> yığınının puanını haksız yere düşürürdü — sinyal yoksa indirim de yok.

> **Düşük güvenli alarm silinmez.** Raporlanır, sadece `low` etiketlenir.
> Kendi kendine filtreleyen bir sistem, sessizce gerçek bir saldırıyı da
> yutabilir; kararı analist verir. Süzmek isteyen `GET /alerts?confidence=high`
> der.

---

## 🔓 Hesap Ele Geçirme Tespiti

Bir IP'den **aynı kullanıcı adına** arka arkaya başarısız denemeler gelip
ardından o hesapla başarılı giriş yapılırsa, bu ayrı bir alarm türüdür:

```
22:05:00  ✗ hasan    ┐
22:05:09  ✗ hasan    │
22:05:18  ✗ hasan    ├─ 6 başarısızlık
22:05:27  ✗ hasan    │
22:05:36  ✗ hasan    │
22:05:45  ✗ hasan    ┘
22:05:54  ✓ hasan    ← possible_account_takeover (confidence: high)
```

**Kullanıcı adı eşleşmesi şart.** `admin` hesabına 6 kez saldırılıp sonra
`deploy` ile normal bir giriş yapılması ele geçirme değildir; bunu eşleştirmek
her sabah işe gelen geliştiriciyi alarm konusu yapardı
(`test_baska_kullaniciyla_basari_takeover_sayilmaz`).

---

## 🧾 Log Ayrıştırma: Üç Durum

Çoğu ayrıştırıcı iki durum bilir: "anladım" ve "anlamadım". AuthWatch **üç**
durumu ayırır:

| Durum | Örnek | Sayılışı |
|---|---|---|
| **Olay** | `Failed password for root from 203.0.113.5` | `parsed_count` |
| **İlgisiz** | `Connection closed by ...` · `GET /haberler → 200` | `ignored_count` |
| **Bozuk** | `203.0.113.77 - - [gecersiz] "POST /login" 401` | `skipped_count` |

Neden önemli: sağlıklı bir `auth.log`'un yarısı auth satırı bile değildir.
Bunları "ayrıştırılamadı" saymak, **gerçek bir biçim değişikliğini gürültünün
içinde kaybetmek** demekti. Bozuk satırlar ise atılmaz — örnekleri saklanır ve
`GET /batches/{id}/skipped` ile okunur. Bir log kaynağının biçimi değiştiğinde
bunu görmenin tek yolu, neyi anlayamadığımızı kaydetmektir.

### Desteklenen biçimler

```
Sep 17 03:12:01 srv01 sshd[4101]: Failed password for invalid user admin from 203.0.113.5 port 52344 ssh2
{"ts":"2026-09-17T11:00:01Z","ip":"203.0.113.9","user":"admin","event":"login_failed"}
203.0.113.77 - - [17/Sep/2026:14:30:00 +0000] "POST /login HTTP/1.1" 401 220 "-" "curl/8"
```

Combined logda **yalnızca giriş yolları** (`/login`, `/signin`, `/auth`, …)
kimlik doğrulama sayılır. Her `401` bir brute-force denemesi değildir.

### `auth.log` yıl yazmaz

Syslog damgası yılsız gelir (`Sep 17 03:12:01`). Yıl verilmezse içinde
bulunulan yıl varsayılır — ama aralık/ocak geçişinde bu **gelecekte** bir tarih
üretir ve gelecekten gelen bir olay kayan pencereyi bozar. O durumda bir yıl
geri alınır. Eski bir dosya yüklüyorsanız `year_hint` ile açıkça verin.

---

## 🌍 IP Zenginleştirme

İki katmanlı ve **ağ erişimi yok**:

1. **Kapsam sınıfı** (her zaman): `public`, `private`, `documentation`,
   `loopback`, `link-local`, `reserved`, `invalid`. İç ağdan gelen bir
   brute-force ile internetten gelen aynı şey değildir — ilki çoğu zaman ele
   geçirilmiş bir istemci demektir.
2. **Ülke / şehir** (opsiyonel): `GEOIP_DB_PATH` ile bir MaxMind `mmdb`
   verilirse eklenir. `geoip2` kurulu değilse veya dosya yoksa alan boş kalır,
   analiz etkilenmez.

> RFC 5737 blokları (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) ayrı
> bir sınıf olarak `documentation` döner. Python bunları `is_private` sayar —
> teknik olarak doğru ama yanıltıcı: bu adresler iç ağdan değil, örnek veriden
> gelir.

**Ücretsiz bir "IP sorgulama API'si" bilerek kullanılmadı.** İncelediğimiz
saldırgan IP'lerini üçüncü bir tarafa göndermek, log analizinin kendisini bir
veri sızıntısına çevirirdi.

---

## 🧭 Mimari

```
                  ┌──────────────┐
                  │  app/api/    │  FastAPI
                  └──────┬───────┘
                         ▼
             ┌────────────────────────┐
             │ services/ingest_service│  satır limiti, kayıt, istatistik
             └───────────┬────────────┘
                         ▼
             ┌────────────────────────┐
             │ core/parsers.py        │  3 biçim · olay/ilgisiz/bozuk
             │ core/detector.py       │  kayan pencere + güven skoru
             │ core/geoip.py          │  kapsam sınıfı + opsiyonel GeoIP
             └───────────┬────────────┘
                         ▼
             ┌────────────────────────┐
             │ db/ (SQLAlchemy async) │  ingest_batches · auth_events
             │                        │  alerts · skipped_lines
             └────────────────────────┘
```

Tek bir olayın yolu:

```
ham satır ──► ayrıştır ──► ilgisiz mi? ──► say, geç
                  │
              zamana göre sırala
                  │
         başarısız mı? ──► IP'nin deque'ine ekle ──► pencereyi kaydır
                  │                                        │
                  │                              eşik aşıldı mı?
                  │                                        │
          başarılı mı? ──► önceki başarısızlıklara bak      ▼
                  │        (aynı kullanıcı?)          güven skoru hesapla
                  ▼                                        │
         possible_account_takeover                    alarm + gerekçe
```

---

## 🚀 Kurulum

```bash
git clone https://github.com/hasancrlk/kaba-kuvvet-saldiri-tespiti.git
cd kaba-kuvvet-saldiri-tespiti
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
uvicorn app.main:app --reload
```

Windows'ta sanal ortam: `.venv\Scripts\activate`

Arayüz: http://127.0.0.1:8000/docs

Docker ile (PostgreSQL dahil):

```bash
docker compose up --build
```

Örnek log dosyasıyla hemen deneyin:

```bash
curl -F "file=@data/sample-auth.log" "http://localhost:8000/ingest/file?year_hint=2026"
```

---

## 🔌 API Referansı

| Metot | Yol | Açıklama |
|---|---|---|
| `POST` | `/ingest` | JSON gövdesiyle log satırları yükler |
| `POST` | `/ingest/file` | Log dosyası yükler |
| `GET` | `/alerts` | Alarmları listeler (IP / tür / güven filtreli) |
| `GET` | `/stats` | IP ve kullanıcı bazında özet |
| `GET` | `/batches` | Yükleme geçmişi |
| `GET` | `/batches/{id}/skipped` | Ayrıştırılamayan satır örnekleri |
| `GET` | `/config` | Yürürlükteki eşikler |
| `GET` | `/health` | Sağlık kontrolü |

### POST /ingest

```bash
curl -X POST http://localhost:8000/ingest \
  -H "Content-Type: application/json" \
  -d '{"lines": ["Sep 17 03:12:01 srv01 sshd[4101]: Failed password for invalid user admin from 203.0.113.5 port 52344 ssh2"], "year_hint": 2026}'
```

```json
{
  "batch_id": 1,
  "source": "api",
  "total_lines": 33,
  "parsed_count": 30,
  "skipped_count": 1,
  "ignored_count": 2,
  "alert_count": 6,
  "created_at": "2026-09-18T11:40:12Z",
  "skipped_samples": ["bu satir hicbir bicime uymuyor"],
  "alerts": [
    {
      "id": 1,
      "kind": "brute_force",
      "ip": "203.0.113.5",
      "attempt_count": 5,
      "window_start": "2026-09-17T03:12:01Z",
      "window_end": "2026-09-17T03:12:13Z",
      "window_seconds": 12.0,
      "usernames": ["admin", "oracle", "postgres", "root", "test"],
      "confidence": "high",
      "confidence_score": 0.95,
      "reasons": [
        "5 farkli kullanici adi denendi (kullanici tarama).",
        "4 deneme var olmayan kullanici adina yapildi.",
        "Denemeler neredeyse sabit araliklarla geldi (otomasyon izi)."
      ],
      "service": "ssh",
      "ip_scope": "documentation"
    }
  ]
}
```

`threshold` ve `window_seconds` istek gövdesinde geçici olarak verilebilir —
analist "eşiği 3 yapsam ne çıkardı" diye bakabilsin diye.

| Durum | Ne zaman |
|---|---|
| `201` | Yükleme tamamlandı |
| `400` | Satır sınırı aşıldı, dosya boş ya da çok büyük |
| `422` | Gövde şeması geçersiz (örn. boş `lines`) |

### GET /alerts

```bash
curl "http://localhost:8000/alerts?confidence=high&kind=brute_force"
```

Filtreler: `ip`, `kind` (`brute_force` · `possible_account_takeover`),
`confidence` (`low` · `medium` · `high`), `limit`, `offset`.

### GET /stats

```json
{
  "total_events": 30,
  "total_failures": 26,
  "total_successes": 4,
  "distinct_ips": 6,
  "alert_count": 6,
  "top_ips": [
    { "ip": "203.0.113.5", "failures": 6, "successes": 0,
      "distinct_usernames": 5, "scope": "documentation",
      "first_seen": "2026-09-17T03:12:01Z", "last_seen": "2026-09-17T03:12:16Z" }
  ],
  "top_targeted_users": [
    { "username": "hasan", "failures": 6, "successes": 1, "distinct_ips": 1 }
  ]
}
```

Toplama **veritabanında** yapılır (`GROUP BY` + `SUM`). Milyonlarca satırı
Python'a çekip saymak, hem belleği hem süreyi gereksiz yere büyütürdü.

---

## 🧪 Testler

```bash
pytest
```

```bash
ruff check app tests
```

48 test; hiçbiri ağa çıkmaz, hiçbiri gerçek bir veritabanı sunucusu istemez.

| Dosya | Neyi doğruluyor |
|---|---|
| `test_detector.py` | **Kayan pencere** (sabit pencerenin kaçırdığı dizi dahil), eşik sınırları, allowlist, soğuma, **güven skoru ayrımı**, ele geçirme |
| `test_parsers.py` | Üç biçim, olay/ilgisiz/bozuk ayrımı, yıl düzeltmesi, sıralama garantisi, IP sınıflandırma |
| `test_api.py` | Uç noktalar, dosya yükleme, filtreler, istatistik, geçici eşik |

> Tespit kuralının testi ayrıca önemli: bu tür kod **sessizce bozulur**. Yanlış
> çalıştığında servis ayakta kalır, `200` döner, sadece artık alarm üretmez.

---

## 📁 Proje Yapısı

```
kaba-kuvvet-saldiri-tespiti/
├── app/
│   ├── core/
│   │   ├── parsers.py      # 3 log biçimi, olay/ilgisiz/bozuk ayrımı
│   │   ├── detector.py     # kayan pencere + güven skoru
│   │   └── geoip.py        # IP kapsamı + opsiyonel MaxMind
│   ├── services/ingest_service.py
│   ├── api/routes.py
│   ├── db/models.py · db/session.py
│   ├── schemas.py
│   ├── config.py
│   └── main.py
├── data/sample-auth.log    # üç senaryolu örnek yığın
├── tests/
├── Dockerfile · docker-compose.yml
└── .github/workflows/ci.yml
```

---

## 🧱 Bilinen Sınırlar

| Sınır | Neden / Sonuç |
|---|---|
| **Toplu (batch) analiz** | Yüklenen yığın tek seferde işlenir; yüklemeler arasında durum taşınmaz. Pencereye iki ayrı dosyadan yayılan bir saldırı bölünebilir. Akış (streaming) tespiti için durumun kalıcılaştırılması gerekir. |
| **Dağıtık brute-force görülmez** | Tespit IP bazlıdır. Her IP'den 2 deneme yapan bir botnet eşiği hiç geçmez; bunun için kullanıcı bazlı ya da ASN bazlı bir boyut gerekir. |
| **Proxy arkası IP** | `X-Forwarded-For` okunmaz; combined logdaki ilk alan neyse o kullanılır. Ters proxy arkasında tüm istekler tek IP'den gelmiş görünür. |
| **Saat dilimi** | SSH damgalarının UTC olduğu varsayılır. Yerel saatle yazan bir sunucunun logu kaydırılmadan yüklenirse pencere hesabı bozulur. |
| **Kimlik doğrulama yok** | Servisin kendisi açık; iç ağda ya da bir ters proxy arkasında çalıştırılmalı. Log verisi hassastır. |

---

## 📄 Lisans

MIT — bkz. [LICENSE](LICENSE).

---

<p align="center">
  <sub>Siber Güvenlik Staj Projesi · Ödev 2 — Kimlik Doğrulama Log Analizi ve Brute-Force Tespit Sistemi</sub>
</p>
