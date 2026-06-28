# -*- coding: utf-8 -*-
"""
stream_reassembly.py  -  A ve B tarafinda ORTAK kullanilan modul
---------------------------------------------------------------
Python 2.7 (B / receiver_agent.py) VE Python 3 (A / npcap_checker.py)
ile uyumludur. Bu yuzden:
  - f-string yok, type hint yok
  - class X(object):
  - // integer division
  - bytearray/bytes/struct ortak API

Gorevi
------
TCP byte-stream protokolunde tek bir mesaj birden fazla TCP segmentine
BOLUNEBILIR (isletim sistemi MSS/MSS-40 sinirina gore boler). Scapy her
paketi ayri gorur ve TCP stream reassembly yapmaz. Bu nedenle bir 22
byte'lik mesaj "ilk 10 byte paket N'de, kalan 12 byte paket N+1'de"
gelirse, eski count_messages_in_payload her iki parcada da eksik oldugu
icin HICBIRINI saymazdi. Sonuc: A ve B farkli sayar, kayip olcumu bozulur.

StreamAssembler bu sorunu cozer:
  1. SPLITTING  : birikmis buffer'da msg_size'lik tam parcalari sayar
  2. RETRANSMISSION / overlap dedupe: seq ile zaten tuketilmis/bytelari kirpar
  3. MESAJ BASI HIZALAMA (marker taramasi): capture mesajin ortasinda
     baslamissa, ilk gecerli mesaj baslangicini bulana kadar tarar

BILINEN SINIRLAMA: out-of-order / gap (offset > 0). Bir paket NIC seviyesinde
gercekten kacirilirsa aradaki mesajlar sayilamaz; buffer sifirlanir ve yeniden
hizalanir. LAN / guvenilir ag senaryosu icin kabul edilebilir.
"""

from __future__ import print_function


# =============================================================================
# Mesaj eslestirme (mevcut fonksiyonlarin merkezi kopyasi)
# =============================================================================
def match_message(payload, defn):
    """payload icinde defn'deki byte_indices pozisyonlarinda byte_values
    degerleri varsa True. payload bytes veya bytearray olmali."""
    idx = defn["byte_indices"]
    val = defn["byte_values"]
    if not payload or len(payload) <= max(idx):
        return False
    return all(payload[i] == v for i, v in zip(idx, val))


def count_messages_in_payload(payload, defn):
    """msg_size > 0 ise payload'u msg_size'lik parcalara boler ve her
    eslesen parca icin 1 sayar. msg_size == 0 ise tum payload'u tek
    mesaj olarak dener. Dokumantasyondaki snippet ile birebir aynidir."""
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


# =============================================================================
# Stream Assembler
# =============================================================================
class StreamAssembler(object):
    """Bir TCP akisini (tek yon, tek mesaj tipi) sirayla besler.
    Her feed(seq, payload) cagrisinda YENI sayilan mesaj adedini dondurur.

    defn: {"byte_indices":[...], "byte_values":[...], "msg_size":int}
    """

    def __init__(self, defn):
        self.defn = defn
        self.msg_size = defn.get("msg_size", 0)
        self._next_seq = None       # siradaki beklenen seq (buffer sonunun +1'i)
        self._buffer = bytearray()  # tuketilmemis birikmis byte'lar
        self._aligned = False       # buffer bir mesaj basinda mi?
        self.total_count = 0        # bu assembler'in toplam saydigi mesaj

    def feed(self, seq, payload):
        """Bir TCP segmentinin (seq, payload) degerlerini besler.
        Donus: bu cagrida YENI sayilan mesaj sayisi."""
        if not payload:
            return 0

        if self._next_seq is None:
            self._next_seq = seq

        offset = seq - self._next_seq

        if offset > 0:
            # GAP: aradan byte'lar kacirildi, buffer guvenilmez degil.
            # Reset + yeniden hizalanma (out-of-order/gap sinirlamasi).
            self._buffer = bytearray()
            self._aligned = False
            self._next_seq = seq
        elif offset < 0:
            # RETRANSMISSION / overlap: zaten tuketilmis byte'lari kirpar.
            overlap = -offset
            if overlap >= len(payload):
                # Tamami eski veri -> yoksay.
                return 0
            payload = payload[overlap:]
            # next_seq degismez: kalan byte'lar tam next_seq'den baslar.
        # offset == 0 -> sirali, mukemmel.

        self._buffer.extend(bytearray(payload))
        self._next_seq += len(payload)

        count = self._count_and_consume()
        self.total_count += count
        return count

    # -------------------------------------------------------------------------
    def _count_and_consume(self):
        if self.msg_size > 0:
            return self._count_fixed()
        return self._count_variable()

    def _count_fixed(self):
        size = self.msg_size

        # --- hizalama ---
        if not self._aligned:
            scan_limit = len(self._buffer) - size + 1
            found = -1
            for i in range(scan_limit):
                if match_message(self._buffer[i:i + size], self.defn):
                    found = i
                    break
            if found < 0:
                # Henuz hizalanamadi. Bir sonraki paket mesajin yarisini
                # tamamlayabilir; bu yuzde kuyruk (size-1) byte sakla.
                # Bellek buyumesini engellemek icin cap uygula.
                keep = min(len(self._buffer), size - 1)
                if keep < len(self._buffer):
                    self._buffer = self._buffer[len(self._buffer) - keep:]
                return 0
            # Hizalanmamis on eki at.
            self._buffer = self._buffer[found:]
            self._aligned = True

        # --- say + tuket ---
        count = count_messages_in_payload(self._buffer, self.defn)
        full = (len(self._buffer) // size) * size
        if full > 0:
            # Tam mesajlari tuket, eksik kuyrugu sakla.
            self._buffer = self._buffer[full:]
        return count

    def _count_variable(self):
        # msg_size == 0: butun buffer tek mesaj olarak denenir (STATUS vb.).
        count = count_messages_in_payload(self._buffer, self.defn)
        if count > 0:
            self._buffer = bytearray()
        return count


# =============================================================================
# Self-test:  python stream_reassembly.py
# =============================================================================
if __name__ == "__main__":
    DEFN = {
        "byte_indices": [0, 1, 2],
        "byte_values": [5, 119, 71],
        "msg_size": 22,
    }

    def make_msg(mid=71, total=22):
        return bytearray([5, 119, mid]) + bytearray([0] * (total - 3))

    MSG = make_msg()
    failures = []

    def check(name, cond):
        status = "OK " if cond else "FAIL"
        print("[%s] %s" % (status, name))
        if not cond:
            failures.append(name)

    # Test 1: tek mesaj 10 + 12 seklinde bolunmus
    a = StreamAssembler(DEFN)
    c1 = a.feed(1000, MSG[0:10])
    c2 = a.feed(1010, MSG[10:22])
    check("split 10+12 -> 1 mesaj", c1 == 0 and c2 == 1 and a.total_count == 1)

    # Test 2: tek pakette tam mesaj (eski davranisla ayni)
    b = StreamAssembler(DEFN)
    check("tek paket tam mesaj -> 1", b.feed(1000, MSG) == 1)

    # Test 3: 3 mesaj 50 byte'lik iki pakete karisik bolunmus
    blob = MSG + MSG + MSG  # 66 byte
    c = StreamAssembler(DEFN)
    cc1 = c.feed(2000, blob[0:50])
    cc2 = c.feed(2050, blob[50:66])
    check("3 mesaj (50+16 split) -> toplam 3",
          c.total_count == 3 and cc1 + cc2 == 3)

    # Test 4: retransmission iki kez sayilmamali
    d = StreamAssembler(DEFN)
    d.feed(3000, MSG)            # 1 mesaj, next_seq=3022
    dup = d.feed(3000, MSG)      # ayni seq yeniden -> tamamen eski
    check("retransmission dedupe -> 0", dup == 0 and d.total_count == 1)

    # Test 5: overlap (kismi retransmission). Gercek TCP'de ayni seq'ye
    # retransmission gelirse icerik orijinal akisla birebir ayni olur.
    #   Orijinal akis: MSG@4000 (seq 4000..4021).
    #   feed1(4000, MSG): 1 mesaj sayildi, next_seq=4022.
    #   feed2(4010, akis[10:44]): seq 4010..4043 = ilk MSG'nin son 12 byte'i
    #     + ikinci tam MSG. Ilk 12 byte overlap -> kirpar; kalan 22 byte =
    #     yeni tam mesaj -> 1 sayilir.
    full = MSG + MSG               # seq 4000..4043 boyunca orijinal akis
    e = StreamAssembler(DEFN)
    e.feed(4000, MSG)
    ov = e.feed(4010, full[10:44])
    check("overlap: yeni mesaj sayilir, eski kirpilir", ov == 1 and e.total_count == 2)

    # Test 6: degisken boyutlu (msg_size=0, STATUS gibi)
    sdefn = {"byte_indices": [0], "byte_values": [255], "msg_size": 0}
    s = StreamAssembler(sdefn)
    check("msg_size=0 tek blok -> 1", s.feed(5000, bytearray([255, 0, 0])) == 1)

    # Test 7: hizalanmamis baslangic (capture mesaj ortasinda basladi)
    g = StreamAssembler(DEFN)
    junk = bytearray([1, 2, 3, 4])   # 4 byte cop (mesaj basi degil)
    gc1 = g.feed(6000, junk)
    gc2 = g.feed(6004, MSG)          # ardindan tam mesaj
    check("cop + tam mesaj -> 1", gc1 == 0 and gc2 == 1 and g.total_count == 1)

    # Test 8: COKLU TIP (TD-1 simuluasyonu). receiver_agent._handle /
    # npcap_checker capture dongusu her mesaj tipi icin KENDI assembler'ini
    # besler. Tek bir paket/buffer'da karisik tipler ([M71][M5][M71]) varsa,
    # eski kod ilk eslesende break yapip digerlerini atliyordu. Dogru
    # davranis: her tip kendi bagimsiz assembler'iyla beslenince hepsi sayilir.
    DEFN_M5 = {
        "byte_indices": [0, 1, 2],
        "byte_values": [5, 119, 5],   # mesaj tipi 5 = "M5"
        "msg_size": 22,
    }
    M71_msg = make_msg(mid=71)        # [05 77 47 ...]
    M5_msg  = make_msg(mid=5)         # [05 77 05 ...]
    mixed_blob = M71_msg + M5_msg + M71_msg   # 66 byte: [M71][M5][M71]

    asm_m71 = StreamAssembler(DEFN)       # M71 icin
    asm_m5  = StreamAssembler(DEFN_M5)    # M5 icin

    # Ayni (seq, payload) iki assembler'a da beslenir (coklu tip izleme).
    asm_m71.feed(7000, mixed_blob)
    asm_m5.feed(7000, mixed_blob)

    check("coklu tip: M71 sayimi [M71][M5][M71] -> 2", asm_m71.total_count == 2)
    check("coklu tip: M5  sayimi [M71][M5][M71] -> 1", asm_m5.total_count == 1)

    print("")
    if failures:
        print("BA\u015eARISIZ testler:", failures)
        raise SystemExit(1)
    print("T\u00fcm testler gecti.")
