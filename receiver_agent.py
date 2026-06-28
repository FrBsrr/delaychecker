# -*- coding: utf-8 -*-
"""
receiver_agent.py  -  B makinesi  (Python 2.7 + Scapy)
-------------------------------------------------------
B'nin adapter'unden Scapy ile paket yakalar.
Toplu gelen paketleri msg_size'a gore boler, her mesaji ayri sayar.
Her N saniyede bir UDP ile A'ya kumulatif sayac gonderir.

Gereksinim : Python 2.7 + scapy  (pip install scapy)
             Linux: root/sudo yetkisi gerekli
Calistirma : sudo python receiver_agent.py [--config /path/to/agent.ini]
"""

import socket
import threading
import struct
import time
import logging
import ConfigParser
import argparse
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("agent")

DEFAULT_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.ini")
UDP_REPORT_ID  = 0xFE
UDP_COMMAND_ID = 0xFD   # A->B reset komutu (TD-3)

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import sniff, get_if_list
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    log.error("Scapy bulunamadi: pip install scapy")

from stream_reassembly import StreamAssembler


# =============================================================================
# Config
# =============================================================================
def load_agent_config(path):
    cfg = ConfigParser.ConfigParser()
    if not cfg.read(path):
        log.error("Config bulunamadi: %s", path)
        sys.exit(1)
    try:
        local_ip  = cfg.get("network",  "local_ip").strip()
        src_ip    = cfg.get("network",  "source_ip").strip()
        tcp_port  = cfg.getint("network", "tcp_port")
        iface     = cfg.get("network",  "iface").strip()
        target_ip = cfg.get("network",  "target_ip").strip()
        udp_port  = cfg.getint("network", "udp_report_port")
        interval  = cfg.getfloat("agent", "report_interval_sec")

        watch_raw = ""
        if cfg.has_option("agent", "watch_messages"):
            watch_raw = cfg.get("agent", "watch_messages").strip()
        watch = [x.strip() for x in watch_raw.split(",") if x.strip()]

        msg_path = os.path.join(os.path.dirname(os.path.abspath(path)), "messages.ini")
        if cfg.has_option("messages", "config_file"):
            raw = cfg.get("messages", "config_file").strip()
            msg_path = raw if os.path.isabs(raw) else \
                       os.path.join(os.path.dirname(os.path.abspath(path)), raw)

    except (ConfigParser.NoSectionError, ConfigParser.NoOptionError) as e:
        log.error("Config hatasi: %s", e)
        sys.exit(1)

    # TD-5: Placeholder degerler degistirilmemisse fail-loud yap. agent.ini
    # ornek degerleri YOUR_B_IP / YOUR_A_IP seklinde gelir; kullanici bunlari
    # kendi IP'leriyle degistirmeden calistirirsa BPF filtresi gecersiz olur
    # ve HIC paket yakalanmaz (sessiz failure). Burada acikca yakala.
    placeholders = {"local_ip": local_ip, "source_ip": src_ip, "target_ip": target_ip}
    missing = [k for k, v in placeholders.items() if v.startswith("YOUR_")]
    if missing:
        log.error(
            "agent.ini'de asagidaki alan(lar) hala placeholder degerinde:\n"
            "  %s\n"
            "Bunlari kendi IP degerlerinizle degistirin (agent.ini baslik "
            "notuna bakin).", ", ".join(missing))
        sys.exit(1)

    return dict(local_ip=local_ip, src_ip=src_ip, tcp_port=tcp_port,
                iface=iface, target_ip=target_ip, udp_port=udp_port,
                interval=interval, watch=watch, msg_path=msg_path)


def load_message_defs(path):
    cfg = ConfigParser.ConfigParser()
    cfg.read(path)
    result = {}
    for sec in cfg.sections():
        try:
            idx      = [int(x.strip()) for x in cfg.get(sec, "byte_indices").split(",")]
            val      = [int(x.strip()) for x in cfg.get(sec, "byte_values").split(",")]
            msg_size = 0
            if cfg.has_option(sec, "msg_size"):
                msg_size = int(cfg.get(sec, "msg_size").strip())
            if len(idx) == len(val):
                result[sec] = {
                    "byte_indices": idx,
                    "byte_values":  val,
                    "msg_size":     msg_size,
                }
        except Exception:
            pass
    if result:
        log.info("Yuklenen mesaj tanimlari:")
        for name, d in result.items():
            log.info("  [%s]  indices=%s  values=%s  msg_size=%d",
                     name, d["byte_indices"], d["byte_values"], d["msg_size"])
    return result


def match_message(data, defn):
    """Birim testler / harici kullanim icin re-export. Asil uygulama
    stream_reassembly.StreamAssembler uzerinden yapilir."""
    from stream_reassembly import match_message as _mm
    return _mm(data, defn)


def count_messages_in_payload(payload, defn):
    """Birim testler / harici kullanim icin re-export."""
    from stream_reassembly import count_messages_in_payload as _cm
    return _cm(payload, defn)


# =============================================================================
# Thread-safe sayac
# =============================================================================
class CounterStore(object):
    def __init__(self):
        self._lock   = threading.Lock()
        self._counts = {}

    def add(self, name, n):
        with self._lock:
            self._counts[name] = self._counts.get(name, 0) + n

    def snapshot(self):
        with self._lock:
            return dict(self._counts)

    def reset(self):
        # TD-3: A'nin START'ta gonderdigi RESET komutu buraya gelir.
        # Sayacilar 0'a duser; boylece B baseline problemi olmadan START
        # anindan itibaren dogru saymaya baslar.
        with self._lock:
            self._counts = {}


# =============================================================================
# Scapy Capture
# =============================================================================
class ScapyCapture(object):
    def __init__(self, iface, local_ip, src_ip, tcp_port, msg_defs, watch, store):
        self.iface    = iface
        self.local_ip = local_ip
        self.src_ip   = src_ip
        self.tcp_port = tcp_port
        self.msg_defs = msg_defs
        self.watch    = set(watch) if watch else set(msg_defs.keys())
        self.store    = store
        # Her mesaj tipi icin ayri stream assembler. Bir mesaj TCP tarafindan
        # birden fazla segmente bolunurse, assembler bu parcalari birlestirir
        # ve dogru sayar (splitting + retransmission dedupe + hizalama).
        self._assemblers = {}
        for name, defn in msg_defs.items():
            self._assemblers[name] = StreamAssembler(defn)
        self._stop    = threading.Event()
        self._pkt_no  = 0

    def start(self):
        t = threading.Thread(target=self._run)
        t.daemon = True
        t.name   = "scapy-cap"
        t.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        if not SCAPY_OK:
            log.error("Scapy yuklu degil.")
            return
        bpf = "tcp and src host %s and dst host %s and port %d" % (
            self.src_ip, self.local_ip, self.tcp_port)
        log.info("Capture basliyor | iface=%s | BPF: %s", self.iface, bpf)
        try:
            sniff(
                iface=self.iface,
                filter=bpf,
                prn=self._handle,
                stop_filter=lambda _: self._stop.is_set(),
                store=False,
            )
        except Exception as e:
            log.error("Scapy hata: %s", e)

    def _handle(self, pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        payload  = bytearray(bytes(pkt[Raw].load))
        seq      = int(pkt[TCP].seq)
        self._pkt_no += 1

        if self._pkt_no <= 3:
            log.info("PAKET #%d  len=%d  seq=%d  ilk8=%s",
                     self._pkt_no, len(payload), seq,
                     [hex(b) for b in payload[:8]])

        # TD-1:_once break'le ilk eslesen tipte cikiliyordu; bu yuzden tek
        # paket/buffer'daki [M71][M5][M71] gibi karisik tiplerden yalnizca
        # ilk gelen sayiliyordu. Her tipin KENDI bagimsiz assembler'i
        # oldugu icin (self._assemblers dict'i) hepsini beslemek guvenlidir
        # — bir tipin buffer'i digerini etkilemez.
        for name in self.watch:
            if name not in self.msg_defs:
                continue
            assembler = self._assemblers[name]
            count = assembler.feed(seq, payload)
            if count > 0:
                self.store.add(name, count)
                log.info("ESLESTI: %s  adet=%d  toplam=%d",
                         name, count, self.store.snapshot().get(name, 0))


# =============================================================================
# UDP Reporter (TD-3: A->B reset komutu da dinler)
# =============================================================================
class UDPReporter(object):
    def __init__(self, target_ip, udp_port, interval, store, listen_ip):
        self.target_ip = target_ip
        self.udp_port  = udp_port
        self.interval  = interval
        self.store     = store
        # TD-3: Ayni UDP portunu dinleyerek A'dan gelen RESET komutunu al.
        # reporter target_ip:udp_port'a sendto yapar (bind etmez), bu yuzden
        # ayni portta bir dinleyici acmak cakismaya neden olmaz.
        self.listen_ip = listen_ip
        self._stop     = threading.Event()
        self._sock     = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._reset_count = 0

    def start(self):
        t = threading.Thread(target=self._run)
        t.daemon = True
        t.name   = "udp-report"
        t.start()
        log.info("UDP reporter -> %s:%d  her %.1fs",
                 self.target_ip, self.udp_port, self.interval)

    def stop(self):
        self._stop.set()
        try: self._sock.close()
        except Exception: pass

    def _run(self):
        # TD-3: Ayni portta dinleyip A'dan RESET komutu bekler. bind gerekli
        # cunku A bu porta sendto ile komut gonderir. SO_REUSEADDR ile
        # yeniden baglanmalarda sorun cikmaz.
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.listen_ip, self.udp_port))
        except Exception as e:
            log.error("UDP bind hatasi (%s:%d): %s", self.listen_ip, self.udp_port, e)
            return
        self._sock.settimeout(self.interval)
        last_report = 0.0
        while not self._stop.is_set():
            # Once A'dan gelen komutlari tuket.
            self._drain_commands()
            now = time.time()
            if now - last_report >= self.interval:
                self._send_report()
                last_report = now
            # Bekleme dongusunu komut gelirse hemen kir.
            wait = self.interval - (now - last_report)
            if wait > 0:
                try:
                    self._sock.settimeout(wait)
                    data, addr = self._sock.recvfrom(self.__class__._LISTEN_BUF)
                    # Bloklayici recvfrom paketi tuketti; hemen uygula.
                    # (Bekleyen baska komut varsa bir sonraki _drain_commands alir.)
                    self._handle_command(data, addr)
                except socket.timeout:
                    pass
                except Exception as e:
                    if not self._stop.is_set():
                        log.warning("UDP dinleme hatasi: %s", e)

    _LISTEN_BUF = 4096

    def _drain_commands(self):
        """Non-blocking olarak bekleyen tum komutlari oku ve uygula."""
        self._sock.setblocking(False)
        try:
            while True:
                try:
                    data, addr = self._sock.recvfrom(self._LISTEN_BUF)
                except socket.error as e:
                    # EAGAIN / EWOULDBLOCK -> baska komut yok
                    import errno
                    if e.args[0] in (errno.EAGAIN, errno.EWOULDBLOCK, 10035):
                        break
                    raise
                self._handle_command(data, addr)
        finally:
            self._sock.setblocking(True)

    def _handle_command(self, data, addr):
        if not data:
            return
        marker = data[0]
        if marker == UDP_COMMAND_ID:
            # RESET komutu: A'nin START aninda sayac sifirlama istegi.
            self.store.reset()
            self._reset_count += 1
            log.info("RESET komutu alindi (A'dan) #%d | %s", self._reset_count, addr[0])
            # Reset hemen sonraki raporu tetikle ki A baseline'i hizlica alsin.
            self._send_report()
        # else: bilinmeyen / gurultu -> yoksay

    def _send_report(self):
        snap = self.store.snapshot()
        if not snap:
            log.debug("Sayac bos, rapor atlandi.")
            return
        payload = bytearray()
        for name, count in snap.items():
            byte_name = name.encode("ascii")
            payload.append(UDP_REPORT_ID)
            payload.append(len(byte_name))
            payload.extend(bytearray(byte_name))
            payload.extend(bytearray(struct.pack(">I", count)))
        try:
            self._sock.sendto(bytes(payload), (self.target_ip, self.udp_port))
            log.info("Rapor gonderildi -> %s:%d  |  %s",
                     self.target_ip, self.udp_port, dict(snap))
        except Exception as e:
            log.warning("UDP hata: %s", e)


# =============================================================================
# Main
# =============================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    args = ap.parse_args()

    if not SCAPY_OK:
        log.error("Scapy yuklu degil. Cikiliyor.")
        sys.exit(1)

    cfg      = load_agent_config(args.config)
    msg_defs = load_message_defs(cfg["msg_path"])

    if not msg_defs:
        log.error("Mesaj tanimi yuklenemedi.")
        sys.exit(1)

    log.info("Izlenenler : %s", cfg["watch"] or "tuumu")
    log.info("Local IP   : %s  Source IP: %s", cfg["local_ip"], cfg["src_ip"])
    log.info("TCP port   : %d  iface: %s", cfg["tcp_port"], cfg["iface"])

    store    = CounterStore()
    capture  = ScapyCapture(
        iface=cfg["iface"], local_ip=cfg["local_ip"], src_ip=cfg["src_ip"],
        tcp_port=cfg["tcp_port"], msg_defs=msg_defs,
        watch=cfg["watch"], store=store,
    )
    reporter = UDPReporter(cfg["target_ip"], cfg["udp_port"], cfg["interval"],
                           store, listen_ip=cfg["local_ip"])

    capture.start()
    reporter.start()

    log.info("Agent calisiyor. Ctrl+C ile durdur.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Durduruluyor...")
        capture.stop()
        reporter.stop()
        log.info("Son sayaclar: %s", store.snapshot())


if __name__ == "__main__":
    main()
