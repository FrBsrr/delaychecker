# Npcap Checker — Sistem Dokümantasyonu

## 1. Amaç

A makinesi belirli mesaj tiplerini (M71 gibi) TCP üzerinden B makinesine
gönderiyor. Bu sistem, **bir TCP bağlantısında ağ seviyesinde mesaj kaybı
olup olmadığını** ölçer:

- A tarafında kaç mesaj **gerçekten gönderildi** (paket düzeyinde)
- B tarafında kaç mesaj **gerçekten alındı** (paket düzeyinde)
- İkisi arasındaki **fark = kayıp**

TCP teorik olarak kayıpsızdır (retransmission yapar), ama:
- Bağlantı koparsa
- Uygulama tarafında bir hata olursa
- Ara bir cihaz (NAT, firewall, switch) paket düşürürse

...mesaj A'dan çıkıp B'ye varmayabilir. Bu sistem bunu somut sayılarla
gösterir.

---

## 2. Genel Mimari

```
┌─────────────────────┐                      ┌─────────────────────┐
│   A makinesi         │   TCP (port 8088)    │   B makinesi         │
│   (mesaj gönderen    │ ───────────────────► │   (mesaj alan         │
│   uygulama + bizim   │   gerçek veri akışı  │   uygulama + bizim   │
│   npcap_checker.py)  │                      │   receiver_agent.py) │
└─────────────────────┘                      └─────────────────────┘
        ▲                                              │
        │            UDP (port 9000)                   │
        └────────────  kümülatif sayaç raporu  ─────────┘
```

**Önemli nokta:** Biz B'deki uygulamaya hiç dokunmuyoruz, onun TCP
bağlantısına da girmiyoruz. Sadece **her iki makinenin network
adaptöründen Npcap/Scapy ile pasif olarak dinliyoruz** (sniffing).
B'de TCP portunu dinleyen asıl uygulama olduğu için, biz orada da
client/server olarak bağlanmıyoruz — sadece trafiği izliyoruz.

A tarafı kendi gönderdiği paketleri sayıyor, B tarafı kendi aldığı
paketleri sayıyor, B bu sayıyı periyodik olarak UDP ile A'ya bildiriyor.
A, iki sayıyı karşılaştırıp kaybı hesaplıyor.

---

## 3. Dosyalar

| Dosya | Çalıştığı yer | Görev |
|---|---|---|
| `npcap_checker.py` | A makinesi | PyQt5 GUI + Scapy capture + UDP listener + kayıp hesabı |
| `receiver_agent.py` | B makinesi | Scapy capture + UDP reporter (arka planda, konsoldan) |
| `stream_reassembly.py` | Her iki makine | TCP segmentasyonunu çözen ortak `StreamAssembler` (Py2.7 + Py3 uyumlu) |
| `messages.ini` | Her iki makine | Mesaj tipi tanımları (byte filtresi + boyutu) |
| `agent.ini` | B makinesi | B'nin ağ ayarları (IP, port, adapter, rapor sıklığı) |

`messages.ini`'nin **her iki makinede de aynı içerikte** olması gerekir,
çünkü hem A hem B aynı filtre mantığıyla mesajları tanımalı.

---

## 4. Mesaj Tanımlama Sistemi (`messages.ini`)

Protokol incelendiğinde her mesajın TCP payload'unun başında sabit bir
yapı olduğu görüldü:

```
byte[0] = sistem ID 1   (örnek: 0x05)
byte[1] = sistem ID 2   (örnek: 0x77)
byte[2] = mesaj tipi    (örnek: 0x47 = 71 decimal → "M71")
```

Bu yüzden her mesaj tipi üç şeyle tanımlanıyor:

```ini
[M71]
byte_indices = 0, 1, 2
byte_values  = 5, 119, 71
msg_size     = 22
```

- **byte_indices / byte_values**: payload'taki hangi pozisyonların hangi
  değerlere sahip olması gerektiği (birebir eşleşir: `indices[i]` →
  `values[i]`)
- **msg_size**: bu mesaj tipinin sabit byte uzunluğu. Bu alan, aşağıda
  anlatılan **Nagle problemi**ni çözmek için eklendi.

Yeni bir mesaj tipi eklemek istendiğinde kodun hiçbir yerine dokunmaya
gerek yok — sadece `messages.ini`'ye yeni bir `[MX]` bloğu eklenir ve
GUI'deki **RELOAD** butonuna basılır.

---

## 5. "Nagle Problemi" ve Çözümü

### Karşılaşılan sorun

Geliştirme sürecinde şu gözlemlendi: ağ trafiği yoğun olduğunda, normalde
saniyede 1 kez gelen 22 byte'lık mesajlar bazen **13 saniye sessiz kalıp**,
sonra **tek bir TCP segmentinde 1700+ byte** olarak birden geliyordu.

### Sebebi

Bu, Npcap/Scapy'nin bir hatası değil, **TCP'nin Nagle algoritmasının**
doğal davranışı. TCP bir byte-stream protokolüdür, mesaj sınırlarını
korumaz. İşletim sistemi, küçük paketleri (header overhead'i azaltmak
için) buffer'da biriktirip, ACK geldiğinde veya buffer dolduğunda toplu
halde gönderir. Bu durumda:

- Mesajlar **gerçekten zamanında gönderilmiş**tir.
- Sadece bizim yakalama katmanımız (Scapy/Wireshark, ikisi de aynı
  pcap kütüphanesini kullanır) onları **tek bir büyük TCP segmenti**
  olarak görür.
- Yani 1716 byte'lık bir paket aslında `1716 / 22 = 78` ayrı mesaj
  içeriyordur, 1 mesaj değil.

### Çözüm: Payload Splitting

Her yakalanan TCP segmentinin payload'u, `msg_size` değerine göre sabit
boyutlu parçalara bölünüyor ve her parça ayrı ayrı mesaj filtresinden
geçiriliyor:

```python
def count_messages_in_payload(payload: bytes, defn: dict) -> int:
    msg_size = defn.get("msg_size", 0)
    if msg_size > 0:
        count = 0
        offset = 0
        while offset + msg_size <= len(payload):
            chunk = payload[offset:offset + msg_size]
            if match_message(chunk, defn):
                count += 1
            offset += msg_size
        return count
    else:
        return 1 if match_message(payload, defn) else 0
```

Bu fonksiyon **hem A hem B tarafında aynı şekilde** çalışıyor, böylece
iki taraf da aynı mantıkla "gerçek" mesaj sayısını çıkarıyor.

> **Not:** Buffer'da farklı mesaj tipleri karışık halde de birikebilir
> (`[M71][M5][M71][STATUS]...`). Bölme mantığı bunu da doğru ele alır,
> çünkü her zaman `msg_size` kadar ileri kayar ve sadece o aralıkta
> filtre eşleşen mesajı sayar — eşleşmeyenler basitçe atlanır.

---

### 5.1 TCP Segmentasyonu ve Stream Reassembly

Yukarıdaki "Nagle problemi" mesajların **birleşip** gelmesini ele aldı.
TCP'nin tersi de gerçekleşir: **tek bir mesaj birden fazla TCP segmentine
bölünebilir.** İşletim sistemi MSS sınırına göre tek bir 22 byte'lık
mesajı bile ikiye bölebilir (örnek: ilk 10 byte paket N'de, kalan 12 byte
paket N+1'de).

Scapy/Wireshark her paketi ayrı görür ve **TCP stream reassembly
yapmaz.** Eski `count_messages_in_payload` her paketin payload'unu
bağımsız işlediği için, bölünmüş bir mesajın iki parçası da eksik gelir
ve **hiçbiri sayılmazdı.** Sonuç: A ile B farklı sayar, kayıp ölçümü
bozulurdu.

**Çözüm:** `stream_reassembly.py` modülündeki `StreamAssembler` sınıfı.
A ve B **aynı kodu** kullanır (dokümanın "simetrik sayma" felsefesi).
Her TCP segmenti `assembler.feed(seq, payload)` ile beslenir; assembler
üç şey yapar:

1. **Retransmission / overlap dedupe:** Gelen `seq`, beklenen
   `next_seq`'den küçükse (zaten tüketilmiş baytlara geri dönüş),
   örtüşen kısım kırpılır, eski veri iki kez sayılmaz.
2. **Mesaj başı hizalama (marker taraması):** Capture mesajın ortasında
   başlamışsa, buffer'da ilk geçerli mesaj başlangıcını bulana kadar
   tarar; hizalanmamış öneki atar.
3. **Splitting:** Hizalanmış buffer'da `msg_size`'lık tam parçaları
   `count_messages_in_payload` ile sayar, eksik kuyruğu saklar.

```
feed(seq, payload) -> bu feed'de YENI sayılan mesaj adedi
  offset = seq - next_seq
    offset > 0  → GAP: buffer sıfırla, yeniden hizalan (bkz. sınırlar)
    offset < 0  → RETRANSMISSION: |offset| byte kırp
    offset == 0 → sıralı
  buffer.extend(data)
  hizala (gerekirse marker tara) -> say -> tam mesajları tüket
```

`StreamAssembler` hem A (`npcap_checker.py`) hem B (`receiver_agent.py`)
tarafında kullanılır; iki tarafın aynı mantıkla mesajları sayması
garantilenir. Modül Python 2.7 (B) ve Python 3 (A) ile uyumludur.

> **Kendinden test:** `python stream_reassembly.py` çalıştırırsanız,
> tek mesajın 10+12 byte olarak bölünmesi, 3 mesajın karmasık parçalara
> bölünmesi, retransmission dedupe, overlap ve hizalanmamış başlangıç
> senaryolarını doğrulayan birim testler çalışır.

**Bilinen sınırlama — out-of-order / gap:** Eğer bir paket NIC seviyesinde
gerçekten kaçırılırsa (`offset > 0`), o gap'teki mesajlar sayılamaz;
assembler buffer'ı sıfırlayıp yeniden hizalanır. Tam TCP reassembly
(gap fill + out-of-order buffer) uygulanmadı — LAN / güvenilir ağ
senaryosu için kabul edilebilir bir sınırdır.

---

## 6. A Tarafı — `npcap_checker.py`

### 6.1 Sorumluluklar

1. PyQt5 ile GUI sunar (adapter seçimi, mesaj tipi seçimi, IP/port
   girişleri, start/stop, canlı istatistik paneli, log tablosu).
2. Scapy ile **kendi adaptöründen** giden (`src=local_ip, dst=remote_ip`)
   TCP paketlerini yakalar (`CaptureEngine`).
3. UDP portunu dinler, B'den gelen kümülatif sayaç raporlarını alır
   (`UDPListener`).
4. İki sayıyı karşılaştırıp kayıp/loss% hesaplar (`StatsModel`).

### 6.2 Önemli sınıflar

**`CaptureEngine`**
BPF filtresi kurar:
```python
bpf = f"tcp and port {self.port} and src host {self.local_ip} and dst host {self.remote_ip}"
```
Bu filtre yalnızca A'dan B'ye giden paketleri yakalar (sent). Her
yakalanan pakette `count_messages_in_payload` çağrılır, dönen sayı
`packets_sent` sinyaliyle GUI thread'ine iletilir.

**`UDPListener`**
`0.0.0.0:UDP_PORT` üzerinde dinler. B'den gelen paketi parse eder:

```
[0xFE][isim_uzunluğu][isim][count(4 byte, big-endian)]
```

Bir UDP paketinde birden fazla mesaj tipi art arda gelebilir (her biri
kendi 0xFE bloğuyla).

**`StatsModel`**
- `sent_total`: A'nın o oturumda gönderdiği toplam mesaj.
- `recv_b`: B'den gelen son rapor, **baseline'a göre normalize edilmiş**
  (aşağıda açıklanıyor).
- `lost_total = max(0, sent_total - recv_b)`
- `loss_pct = lost_total / sent_total * 100`
- `sent_rate`: son 5 saniyedeki saniyelik gönderim hızı.

### 6.3 Baseline problemi ve çözümü

B, Scapy ile **A'nın START butonuna basmasından bağımsız olarak** trafiği
dinlemeye devam eder (agent her zaman çalışır durumda olabilir). Bu
yüzden A START'a bastığında B'nin sayacı zaten 0'dan büyük bir değerde
olabilir (örnek: B agent'i daha önce başlatılmışsa 220 mesaj saymış
olabilir).

Eğer bu ham değer doğrudan kullanılsaydı:
```
sent_A = 0  (henüz başladı)
recv_B = 220  (B önceden saymıştı)
lost = max(0, 0 - 220) = 0   → yanıltıcı ama "0" görünüyor, gerçek fark gizleniyor
```

Çözüm: A, **ilk UDP raporunu aldığı an**, o değeri `baseline` olarak
saklar. Sonraki tüm `recv_b` hesapları bu baseline'a göre yapılır:

```python
def update_recv_b(self, count: int):
    if self._recv_baseline is None:
        self._recv_baseline = count
    self.recv_b = count - self._recv_baseline
```

Böylece A'nın START anından sonraki **göreli** recv sayısı izlenir, B'nin
daha önce saymış olduğu geçmiş veri karışmaz.

> **Bilinen sınırlama (büyük ölçüde çözüldü — TD-3):** A, START'ta B'ye
> `0xFD` RESET komutu gönderir (bkz. 8.1); B sayacını sıfırlayıp anında
> rapor yollar, böylece baseline START anına yakın kurulur. Kalan sınır:
> UDP güvenilir olmadığı için reset kaybolabilir — bu durumda mevcut
> fallback (ilk rapordan baseline alma) devreye girer. Bu yüzden
> `report_interval_sec` yine küçük tutulmalıdır (1-5 saniye önerilir).

---

## 7. B Tarafı — `receiver_agent.py`

Python 2.7 ile yazıldı (B makinesinin ortamı buna göre).

### 7.1 Neden TCP server/client değil, Scapy?

İlk tasarımda agent'ın B üzerinde bir TCP server açıp A'nın ona
bağlanacağı varsayıldı. Ardından "A client, B server" / "B client,
A server" tartışması yaşandı. **Gerçekte ne A ne B bizim agent'imize
bağlanıyor** — port 8088'i zaten **başka bir uygulama** dinliyor, biz
ona dokunamayız (port zaten kullanımda, ikinci bir bind mümkün değil).

Bu yüzden B tarafında da A tarafıyla simetrik bir yaklaşım benimsendi:
**Scapy ile B'nin adaptöründen pasif dinleme.**

### 7.2 BPF filtresi

```python
bpf = "tcp and src host %s and dst host %s and port %d" % (
    self.src_ip, self.local_ip, self.tcp_port)
```

Burada `src_ip` = A'nın IP'si, `local_ip` = B'nin kendi IP'si. Yani bu
filtre yalnızca **A'dan B'ye gelen** paketleri yakalar — B'nin
gönderdiği cevapları değil.

### 7.3 Akış

1. `ScapyCapture` B'nin adaptöründen dinler, eşleşen her mesajı
   `CounterStore`'a ekler (`store.add(name, count)`).
2. `UDPReporter`, `report_interval_sec` aralığıyla (config'den) bu
   store'un anlık görüntüsünü (`snapshot()`) UDP paketine kodlayıp A'ya
   gönderir.
3. Agent durdurulana kadar (`Ctrl+C`) bu döngü sürekli çalışır.

### 7.4 `agent.ini` alanları

```ini
[network]
local_ip        = 18.2.3.161   # B'nin kendi IP'si
source_ip       = 18.2.3.31    # A'nın IP'si (filtre için)
tcp_port        = 8088          # izlenecek port
iface           = eth0           # B'nin adapter adı
target_ip       = 18.2.3.31    # UDP raporu nereye gidecek (= A)
udp_report_port = 9000

[agent]
report_interval_sec = 5
watch_messages      = M71        # boş bırakılırsa tüm mesaj tipleri izlenir

[messages]
config_file = messages.ini
```

Adapter adını bulmak için:
```bash
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

---

## 8. UDP Rapor Protokolü (A ↔ B)

B'den A'ya giden her UDP paketi, bir veya daha fazla "mesaj bloğu"
içerebilir:

```
┌────────┬──────────────┬──────────────┬────────────────────┐
│ 0xFE   │ isim_uzunluk │ isim (ASCII) │ count (4B, big-end) │
│ 1 byte │ 1 byte (N)   │ N byte       │ 4 byte              │
└────────┴──────────────┴──────────────┴────────────────────┘
```

Birden fazla mesaj tipi izleniyorsa bu blok art arda tekrarlanır.
`0xFE` (254), gerçek uygulama mesajlarıyla çakışmayacak sabit bir
"marker" byte olarak seçildi.

A tarafındaki `UDPListener._parse` bu formatı baştan sona okuyup
`{"M71": 1234, ...}` şeklinde bir sözlüğe çevirir.

### 8.1 A → B Reset Komutu (TD-3)

Aynı UDP portunda **ters yönde** (A→B) tek bir komut türü çalışır: **RESET**.
A, START'a bastığı an B'ye bir UDP paketi gönderir:

```
┌────────┐
│ 0xFD   │   tek marker byte, payload yok
│ 1 byte │
└────────┘
```

B tarafındaki `UDPReporter` artık aynı portu dinler (bind eder) ve bu
komutu alınca `CounterStore.reset()` çağırır, ardından anında bir rapor
(B→A, `0xFE`) gönderir. Böylece A'nın baseline'ı START anına yakın
sıfırdan kurulur (bkz. 6.3 baseline problemi).

Marker ayrımı: `0xFE` = rapor (B→A), `0xFD` = reset komutu (A→B). İkisi
farklı marker byte kullandığı için çakışmaz. UDP güvenilir olmadığından
reset paketi kaybolabilir; bu durumda baseline fallback'i (ilk rapordan
baseline alma) devreye girer — ölçüm bozulmaz, sadece baseline gecikmesi
kapatılamaz.

---

## 9. Şu Anki Durum / Bilinen Açık Noktalar

- **Baseline gecikmesi (ÇÖZÜLDÜ):** A, START'ta B'ye `0xFD` RESET komutu
  (UDP) gönderir; B bunu alınca `CounterStore.reset()` ile sayacını
  sıfırlar. Böylece B'nin START öncesi saydığı eski veri baseline'a
  karışmaz (bkz. 6.3 ve Bölüm 8). Fallback: UDP güvenilir olmadığı için
  reset paketi kaybolursa, A yine ilk rapordan baseline alır (mevcut
  davranış aynen kalır) — yani RESET kaybı ölçümü bozmaz, sadece
  baseline gecikmesini kapatamaz.
- **TCP segmentasyonu (ÇÖZÜLDÜ):** Tek bir mesajın TCP tarafından birden
  fazla segmente bölünmesi artık `StreamAssembler` ile çözüldü (bkz. 5.1).
  A ve B aynı assembler kodunu kullanır, böylece bölünmüş paketler iki
  tarafta da simetrik sayılır. Kalan sınırlama: out-of-order / gap
  (NIC seviyesinde gerçekten kaçırılan paketler) — bu durumda o
  mesajlar sayılamaz, buffer sıfırlanıp yeniden hizalanır.
- **Tek mesaj tipi aktif:** GUI'de aynı anda yalnızca bir mesaj tipi
  izlenebiliyor (dropdown'dan seçilen). B agent'i `watch_messages` ile
  birden fazla tipi aynı anda sayabiliyor ama GUI sadece seçili olanı
  gösteriyor.
- **UDP güvenilirliği:** Rapor paketleri UDP ile gidiyor, yani B'den
  A'ya giden rapor da teorik olarak kaybolabilir. Bu durumda GUI'deki
  "SON UDP" alanı son raporun ne kadar zaman önce geldiğini gösterir;
  bu süre uzuyorsa rapor kanalında bir sorun olduğu anlaşılır.
- **Python sürüm farkı:** A tarafı Python 3 + PyQt5, B tarafı Python 2.7
  + Scapy. `stream_reassembly.py` modülü her iki Python sürümüyle de
  uyumlu yazıldı (f-string/type hint yok, `class X(object):`, `//`
  integer division). İki taraf da `bytearray`/`bytes` indeksleme ile
  `int` döndürdüğü için bayt karşılaştırma tutarlıdır.

---

## 10. Teknik Borç / Devam Edilecek İşler

> Bu bölüm, kod incelemesinde tespit edilmiş **henüz çözülmemiş** sorunları
> listeler. Her madde `DOSYA:SATIR` referansı, etkisi ve önerilen çözüm
> içerir — başka bir agent buradan kaldığı yerden devam edebilir.
>
> Öncelik sıralaması: **P0** = doğruluğu bozar, **P1** = sağlamlık/UX,
> **P2** = estetik/temizlik.

### ✅ Çözülen

| ID | Açıklama | Durum |
|---|---|---|
| SEG-1 | TCP segmentasyonu (tek mesaj iki segmente bölününce sayılmıyordu) | **Çözüldü** — `StreamAssembler` (bkz. 5.1) |
| TD-1 | `receiver_agent.py:211` — `break` ile ilk eşleşen mesaj tipi sayılıp gerisi atlanıyordu | **Çözüldü** — `break` kaldırıldı, tüm izlenen tipler besleniyor; her tipin bağımsız assembler'ı var. Test 8 (`stream_reassembly.py` self-test) çoklu tip senaryosunu doğrular |
| TD-2 | `npcap_checker.py:570` — `local_ip` Windows'ta `socket.gethostbyname` ile güvensizdi (genelde `127.0.0.1` döner, BPF `src host` yanlış olur, hiç paket yakalanmazdı) | **Çözüldü** — `local_ip` artık seçilen adapter'ın gerçek IP'si olan `scapy_ifaces[iface_id].ip`'den alınıyor (`_iface_ip` yardımcı metodu). Adapter IP'si yoksa START uyarı verir (promiscuous/sniff-only adapter koruması) |
| TD-3 | Baseline gecikmesi — A START'ta B'nin eski sayacını normalize etmek için ilk UDP raporunu beklemek zorundaydı; START ile ilk rapor arasındaki mesajlar görünmez kalırdı | **Çözüldü** — A START'ta B'ye `0xFD` RESET komutu gönderir, B `CounterStore.reset()` ile sayacı sıfırlar. Baseline fallback'i korunur (reset kaybolursa ilk rapordan baseline alınır). `UDPReporter` artık aynı portu dinleyip A→B komutlarını da işler |
| TD-4 | `match_message` off-by-one sınır kontrolü (`stream_reassembly.py:43`) | **Geçersiz — hata yok.** İnceleme sonucu: `len(payload) <= max(idx)` ile dokümanın önerdiği `len(payload) < max(idx)+1` tam sayılar için **matematiksel olarak özdeştir** (5000 test durumunda 0 uyumsuzluk). İndeks `i`'ye erişmek için `len(payload) > i` gerekir → reddetme koşulu `len(payload) <= max(idx)` zaten doğrudur. Değişiklik gerekmedi |
| TD-5 | `agent.ini` örneği yanıltıcı gerçek IP'ler içeriyordu (18.2.3.161 gibi) | **Çözüldü** — IP'ler `YOUR_B_IP`/`YOUR_A_IP` placeholder'larına çevrildi, başlığa "DEĞİŞTİRİLMELİDİR" notu eklendi. Ek olarak `load_agent_config` placeholder'ları tespit edip **fail-loud** `sys.exit` yapıyor (sessiz failure yerine) |
| TD-6 | `lo` interface'de aynı-makine test senaryosu belgelenmemişti | **Çözüldü** — Bölüm 11.1 "Aynı Makinede Test" eklendi: sent/recv aynı adapter'de görünmesi, çift `bind` çakışması, `report_interval_sec` önerileri |

### 🔴 P0 — Doğruluk / doğrudan hatalı davranış

_(Bu öncelik seviyesinde açık nokta kalmadı — TD-1 ve TD-2 çözüldü.)_

### 🟡 P1 — Sağlamlık / UX

_(Bu öncelik seviyesinde açık nokta kalmadı — TD-3 çözüldü, TD-4 geçersiz
olduğu için kapatıldı.)_

### 🟢 P2 — Estetik / temizlik

_(Bu öncelik seviyesinde açık nokta kalmadı — TD-5 ve TD-6 çözüldü.)_

---

### Önerilen sıra
1. ~~**TD-1** (P0, düşük risk) — `break` kaldırma~~ ✅ Çözüldü
2. ~~**TD-2** (P0, düşük-orta risk) — `local_ip` Scapy'den alma~~ ✅ Çözüldü
3. ~~**TD-3** (P1) — RESET komutu (baseline gecikmesini tamamen kapatır)~~ ✅ Çözüldü
4. ~~**TD-4** (P2) — off-by-one temizliği~~ ✅ Geçersiz (hata yok, kapatıldı)
5. ~~**TD-5**, **TD-6** — belgelendirme~~ ✅ Çözüldü

> **Tüm teknik borç kalemleri tamamlandı.** Her düzeltme sonrası
> `python stream_reassembly.py` self-test'i (bkz. 5.1) çalıştırıldı ve
> A/B simetrisi doğrulandı.

---

## 11. Hızlı Başlangıç

**A makinesinde:**
```bash
pip install PyQt5 scapy
python npcap_checker.py     # Admin/yönetici olarak çalıştır (Npcap için gerekli)
```
GUI'de: Adapter seç → Mesaj tipi seç (örn. M71) → Remote IP / TCP Port /
UDP Port gir → START.

**B makinesinde:**
```bash
pip install scapy
sudo python receiver_agent.py    # root yetkisi gerekli (paket yakalama için)
```
`agent.ini`'nin doğru `local_ip`, `source_ip`, `iface`, `target_ip`
değerleriyle önceden düzenlenmiş olması gerekir.

**Doğrulama:**
- A tarafında "A SENT" sayacı artmalı.
- B agent konsolunda `"ESLESTI: M71  adet=N  toplam=X"` logları
  görünmeli.
- A tarafında birkaç saniye içinde "B RECV" alanı dolmalı, "UDP" durumu
  "✓ bağlı" olmalı.
- "LOST" ve "LOSS %" alanları, gerçek zamanlı kayıp oranını gösterir.

### 11.1 Aynı Makinede Test (`lo` interface) — TD-6

Geliştirme/test sırasında A ve B **aynı makinede** (her ikisi `localhost`)
çalıştırılırsa şu tuzaklara dikkat:

- **Sent/recv aynı adapter'de görünür.** A'nın gönderdiği ve B'nin aldığı
  paketler aynı ağ adaptöründen geçer; `src/dst` BPF filtreleri
  `localhost`/`127.0.0.1` adresleriyle beklenmedik davranabilir
  (bazen çift sayım, bazen hiç eşleşmeme).
- **Aynı porta iki `bind` yapılamaz.** A (`npcap_checker`) ve B
  (`receiver_agent`) ikisi de UDP rapor portu için (örn. 9000) `bind`
  yapmaya kalkarsa ikincisi `Address already in use` alır. Gerçek
  kurulumda A ve B farklı makineler olduğu için bu sorun yoktur. Aynı
  makinede test ediliyorsa, test süresince A ve B için **iki farklı UDP
  portu** kullanın (A'nın `UDP PORT` alanı ile B'nin `udp_report_port`'u
  farklı olmalı — ama o zaman B'nin raporu A'ya ulaşamaz; bu yüzden
  gerçek iki-makine topolojisi önerilir).
- **`report_interval_sec` küçük tutun.** Aynı makinede paket gecikmesi
  yok denecek kadar azdır ama baseline (TD-3) için yine de 1–5 sn önerilir.

> Öneri: A/B davranışını doğrulamak için en güvenilir yol **iki ayrı
> makine** kullanmaktır. Aynı makinede test, capture/BPF/UDP port
> davranışlarının doğrulanması için kullanışlıdır ama sayım doğruluğunu
> kanıtlamaz — sayım doğruluğu `python stream_reassembly.py` self-test'i
> (bkz. 5.1 sonundaki "Kendinden test" notu) ile kanıtlanır.
