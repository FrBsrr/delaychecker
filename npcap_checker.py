"""
npcap_checker.py  -  A makinesi  (Python 3 + Scapy + PyQt5)
-------------------------------------------------------------
- Npcap ile TCP sent paketlerini yakalar, mesaj ID filtresiyle sayar.
- Toplu gelen paketleri msg_size'a gore boler, her mesaji ayri sayar.
- UDP soketi dinler: B'nin receiver_agent'indan gelen recv sayisini alir.
- Gercek kayip = sent_A - recv_B.

Gereksinimler:
  pip install PyQt5 scapy
  Windows: Npcap kurulu, admin yetkisi gerekli.
"""

import sys
import os
import time
import socket
import struct
import threading
import configparser
from collections import deque

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QLineEdit, QFrame, QSizePolicy,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QGroupBox,
)
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import sniff, get_if_list, ifaces as scapy_ifaces
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

from stream_reassembly import StreamAssembler

# ── Palette ────────────────────────────────────────────────────────────────
BG_DEEP   = "#0D1117"
BG_PANEL  = "#161B22"
BG_WIDGET = "#1E242D"
BORDER    = "#2D333B"
ACCENT_G  = "#39D353"
ACCENT_R  = "#F85149"
ACCENT_B  = "#58A6FF"
ACCENT_Y  = "#E3B341"
ACCENT_P  = "#BC8CFF"
TEXT_PRI  = "#E6EDF3"
TEXT_SEC  = "#8B949E"
TEXT_DIM  = "#484F58"

UDP_REPORT_ID  = 0xFE
UDP_COMMAND_ID = 0xFD   # A->B reset komutu (TD-3)
CONFIG_FILE   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "messages.ini")

GLOBAL_STYLE = f"""
QMainWindow, QWidget {{
    background-color: {BG_DEEP};
    color: {TEXT_PRI};
    font-family: "Consolas", "Courier New", monospace;
    font-size: 12px;
}}
#pnl_top {{
    background-color: {BG_PANEL};
    border-bottom: 1px solid {BORDER};
}}
QComboBox {{
    background-color: {BG_WIDGET};
    color: {TEXT_PRI};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 4px 10px;
    min-width: 180px;
}}
QComboBox:hover {{ border-color: {ACCENT_B}; }}
QComboBox::drop-down {{ border: none; width: 24px; }}
QComboBox::down-arrow {{
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid {TEXT_SEC};
    margin-right: 6px;
}}
QComboBox QAbstractItemView {{
    background-color: {BG_WIDGET};
    color: {TEXT_PRI};
    selection-background-color: {ACCENT_B}44;
    border: 1px solid {BORDER};
    outline: none;
}}
QLineEdit {{
    background-color: {BG_WIDGET};
    color: {TEXT_PRI};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 4px 10px;
}}
QLineEdit:focus {{ border-color: {ACCENT_B}; }}
QPushButton {{
    border-radius: 4px;
    font-size: 12px;
    font-weight: bold;
    padding: 5px 20px;
}}
QPushButton#btn_start {{
    background-color: {ACCENT_G}22; color: {ACCENT_G};
    border: 1px solid {ACCENT_G}88;
}}
QPushButton#btn_start:hover:!disabled {{ background-color: {ACCENT_G}44; border-color: {ACCENT_G}; }}
QPushButton#btn_start:disabled {{ background-color: {BG_WIDGET}; color: {TEXT_DIM}; border-color: {BORDER}; }}
QPushButton#btn_stop {{
    background-color: {ACCENT_R}22; color: {ACCENT_R};
    border: 1px solid {ACCENT_R}88;
}}
QPushButton#btn_stop:hover:!disabled {{ background-color: {ACCENT_R}44; border-color: {ACCENT_R}; }}
QPushButton#btn_stop:disabled {{ background-color: {BG_WIDGET}; color: {TEXT_DIM}; border-color: {BORDER}; }}
QPushButton#btn_reload {{
    background-color: {ACCENT_Y}22; color: {ACCENT_Y};
    border: 1px solid {ACCENT_Y}55;
    padding: 4px 12px; font-size: 11px;
}}
QPushButton#btn_reload:hover {{ background-color: {ACCENT_Y}44; }}
QFrame[frameShape="4"], QFrame[frameShape="5"] {{ color: {BORDER}; }}
QLabel#lbl_tag {{ color: {TEXT_SEC}; font-size: 10px; letter-spacing: 1px; }}
QGroupBox {{
    border: 1px solid {BORDER}; border-radius: 4px;
    margin-top: 8px; font-size: 10px;
    color: {TEXT_SEC}; letter-spacing: 1px;
}}
QGroupBox::title {{ subcontrol-origin: margin; padding: 0 6px; }}
QTableWidget {{
    background-color: {BG_PANEL};
    gridline-color: {BORDER};
    border: 1px solid {BORDER};
    border-radius: 4px;
    color: {TEXT_PRI};
}}
QTableWidget::item {{ padding: 3px 8px; }}
QTableWidget::item:selected {{ background-color: {ACCENT_B}33; }}
QHeaderView::section {{
    background-color: {BG_WIDGET}; color: {TEXT_SEC};
    border: none; border-right: 1px solid {BORDER};
    border-bottom: 1px solid {BORDER};
    padding: 4px 8px; font-size: 10px; letter-spacing: 0.5px;
}}
QScrollBar:vertical {{
    background: {BG_WIDGET}; width: 8px; border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER}; border-radius: 4px; min-height: 20px;
}}
"""


# ═══════════════════════════════════════════════════════════════════════════
# Config
# ═══════════════════════════════════════════════════════════════════════════
def load_message_config(path=CONFIG_FILE):
    cfg = configparser.ConfigParser()
    cfg.read(path)
    result = {}
    for sec in cfg.sections():
        try:
            idx      = [int(x.strip()) for x in cfg[sec]["byte_indices"].split(",")]
            val      = [int(x.strip()) for x in cfg[sec]["byte_values"].split(",")]
            msg_size = int(cfg[sec].get("msg_size", "0").strip())
            if len(idx) == len(val):
                result[sec] = {
                    "byte_indices": idx,
                    "byte_values":  val,
                    "msg_size":     msg_size,
                }
        except Exception:
            pass
    return result


# match_message / count_messages_in_payload artik stream_reassembly modulunde.
# CaptureEngine bir StreamAssembler tutar; tek mesajin TCP tarafindan birden
# fazla segmente bolunmesini (segmentasyon) bu assembler cozer.


# ═══════════════════════════════════════════════════════════════════════════
# Signals
# ═══════════════════════════════════════════════════════════════════════════
class AppSignals(QObject):
    packets_sent  = pyqtSignal(int, int)   # count, total_bytes
    udp_report    = pyqtSignal(dict)
    capture_error = pyqtSignal(str)


# ═══════════════════════════════════════════════════════════════════════════
# Capture Engine (A tarafı - sadece sent)
# ═══════════════════════════════════════════════════════════════════════════
class CaptureEngine:
    def __init__(self, iface, local_ip, remote_ip, port, msg_def, signals):
        self.iface     = iface
        self.local_ip  = local_ip
        self.remote_ip = remote_ip
        self.port      = int(port)
        self.msg_def   = msg_def
        self.signals   = signals
        self._assembler = StreamAssembler(msg_def)
        self._stop     = threading.Event()

    def start(self):
        self._stop.clear()
        threading.Thread(target=self._run, daemon=True, name="npcap").start()

    def stop(self):
        self._stop.set()

    def _run(self):
        try:
            bpf = (f"tcp and port {self.port} and "
                   f"src host {self.local_ip} and dst host {self.remote_ip}")
            sniff(
                iface=self.iface, filter=bpf,
                prn=self._handle,
                stop_filter=lambda _: self._stop.is_set(),
                store=False,
            )
        except Exception as e:
            self.signals.capture_error.emit(str(e))

    def _handle(self, pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return
        seq = int(pkt[TCP].seq)
        payload = bytes(pkt[Raw].load)
        count = self._assembler.feed(seq, payload)
        if count > 0:
            self.signals.packets_sent.emit(count, len(payload))


# ═══════════════════════════════════════════════════════════════════════════
# UDP Listener (B'den recv raporu)
# ═══════════════════════════════════════════════════════════════════════════
class UDPListener:
    BUF = 4096

    def __init__(self, udp_port: int, signals: AppSignals):
        self.udp_port = udp_port
        self.signals  = signals
        self._stop    = threading.Event()
        self._sock    = None

    def start(self):
        self._stop.clear()
        threading.Thread(target=self._run, daemon=True, name="udp-listen").start()

    def stop(self):
        self._stop.set()
        if self._sock:
            try: self._sock.close()
            except Exception: pass

    def _run(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind(("0.0.0.0", self.udp_port))
        except OSError as e:
            self.signals.capture_error.emit(f"UDP bind hatasi ({self.udp_port}): {e}")
            return
        self._sock.settimeout(1.0)
        while not self._stop.is_set():
            try:
                data, _ = self._sock.recvfrom(self.BUF)
                parsed = self._parse(data)
                if parsed:
                    self.signals.udp_report.emit(parsed)
            except socket.timeout:
                continue
            except Exception:
                if not self._stop.is_set():
                    break

    def _parse(self, data: bytes) -> dict:
        result = {}
        i = 0
        try:
            while i < len(data):
                if data[i] != UDP_REPORT_ID:
                    break
                i += 1
                name_len = data[i]; i += 1
                name  = data[i:i+name_len].decode("ascii", errors="replace")
                i += name_len
                count = struct.unpack(">I", data[i:i+4])[0]
                i += 4
                result[name] = count
        except Exception:
            pass
        return result


# ═══════════════════════════════════════════════════════════════════════════
# Stats
# ═══════════════════════════════════════════════════════════════════════════
class StatsModel:
    WINDOW = 5.0

    def __init__(self):
        self.reset()

    def reset(self):
        self.sent_total      = 0
        self.recv_b          = 0
        self._recv_baseline  = None
        self.udp_ok          = False
        self._last_udp_ts    = 0.0
        self._sent_ts: deque = deque()

    def add_sent(self, count: int, ts: float):
        self.sent_total += count
        for _ in range(count):
            self._sent_ts.append(ts)
        cutoff = ts - self.WINDOW
        while self._sent_ts and self._sent_ts[0] < cutoff:
            self._sent_ts.popleft()

    def update_recv_b(self, count: int):
        if self._recv_baseline is None:
            self._recv_baseline = count
        self.recv_b       = count - self._recv_baseline
        self._last_udp_ts = time.time()
        self.udp_ok       = True

    @property
    def lost_total(self):
        return max(0, self.sent_total - self.recv_b)

    @property
    def loss_pct(self):
        return 0.0 if self.sent_total == 0 else (self.lost_total / self.sent_total) * 100

    @property
    def sent_rate(self):
        return len(self._sent_ts) / self.WINDOW

    @property
    def udp_age(self):
        if not self.udp_ok:
            return "—"
        return f"{time.time() - self._last_udp_ts:.1f}s"


# ═══════════════════════════════════════════════════════════════════════════
# Main Window
# ═══════════════════════════════════════════════════════════════════════════
class NpcapChecker(QMainWindow):
    MAX_LOG = 300

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Npcap Checker")
        self.setMinimumSize(820, 580)

        self._msg_defs   = {}
        self._capture    = None
        self._udp_lstn   = None
        self._stats      = StatsModel()
        self._signals    = AppSignals()
        self._start_time = None
        self._active_msg = ""

        self._signals.packets_sent.connect(self._on_sent)
        self._signals.udp_report.connect(self._on_udp_report)
        self._signals.capture_error.connect(self._on_error)

        self._load_messages()
        self._build_ui()
        self.setStyleSheet(GLOBAL_STYLE)

        self._ui_timer = QTimer(self)
        self._ui_timer.setInterval(500)
        self._ui_timer.timeout.connect(self._refresh_stats)

    # ── config ────────────────────────────────────────────────────────────
    def _load_messages(self):
        self._msg_defs = load_message_config()

    # ── UI ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        main = QVBoxLayout(root)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)

        # ── top panel ────────────────────────────────────────────────────
        top = QWidget(); top.setObjectName("pnl_top")
        tl = QVBoxLayout(top)
        tl.setContentsMargins(14, 10, 14, 10)
        tl.setSpacing(8)

        def tag(txt, w=None):
            l = QLabel(txt); l.setObjectName("lbl_tag")
            if w: l.setFixedWidth(w)
            return l

        # Row 1: adapter | message | reload | START | STOP
        r1 = QHBoxLayout(); r1.setSpacing(8)

        self.combo_iface = QComboBox()
        self.combo_iface.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._populate_ifaces()

        self.combo_msg = QComboBox(); self.combo_msg.setFixedWidth(120)
        self._populate_msgs()

        self.btn_reload = QPushButton("↺ RELOAD")
        self.btn_reload.setObjectName("btn_reload")
        self.btn_reload.setFixedHeight(28)
        self.btn_reload.clicked.connect(self._reload_messages)

        self.btn_start = QPushButton("▶  START")
        self.btn_start.setObjectName("btn_start"); self.btn_start.setFixedHeight(30)

        self.btn_stop = QPushButton("■  STOP")
        self.btn_stop.setObjectName("btn_stop")
        self.btn_stop.setFixedHeight(30); self.btn_stop.setEnabled(False)

        r1.addWidget(tag("ADAPTER", 56)); r1.addWidget(self.combo_iface)
        r1.addSpacing(8)
        r1.addWidget(tag("MESSAGE", 60)); r1.addWidget(self.combo_msg)
        r1.addWidget(self.btn_reload)
        r1.addStretch()
        r1.addWidget(self.btn_start); r1.addWidget(self.btn_stop)

        div = QFrame(); div.setFrameShape(QFrame.HLine); div.setFrameShadow(QFrame.Plain)

        # Row 2: remote ip | tcp port | udp port
        r2 = QHBoxLayout(); r2.setSpacing(10)

        self.edit_ip = QLineEdit()
        self.edit_ip.setPlaceholderText("192.168.1.100"); self.edit_ip.setFixedHeight(28)

        self.edit_tcp_port = QLineEdit()
        self.edit_tcp_port.setPlaceholderText("8088")
        self.edit_tcp_port.setFixedWidth(90); self.edit_tcp_port.setFixedHeight(28)

        self.edit_udp_port = QLineEdit()
        self.edit_udp_port.setPlaceholderText("9000")
        self.edit_udp_port.setFixedWidth(90); self.edit_udp_port.setFixedHeight(28)

        def vsep():
            s = QFrame(); s.setFrameShape(QFrame.VLine)
            s.setFrameShadow(QFrame.Plain); s.setFixedHeight(20); return s

        r2.addWidget(tag("REMOTE IP", 66)); r2.addWidget(self.edit_ip)
        r2.addWidget(vsep())
        r2.addWidget(tag("TCP PORT", 60)); r2.addWidget(self.edit_tcp_port)
        r2.addWidget(vsep())
        r2.addWidget(tag("UDP PORT", 62)); r2.addWidget(self.edit_udp_port)
        r2.addStretch()

        tl.addLayout(r1); tl.addWidget(div); tl.addLayout(r2)
        main.addWidget(top)

        # ── stats ─────────────────────────────────────────────────────────
        sr = QHBoxLayout(); sr.setContentsMargins(14, 10, 14, 4); sr.setSpacing(12)

        def gb(title):
            g = QGroupBox(title); l = QVBoxLayout(g); l.setSpacing(4); return g, l

        g1, l1 = gb("SAYAC  (A sent vs B recv)")
        self.lbl_sent    = self._sl("A SENT",  "0")
        self.lbl_recv_b  = self._sl("B RECV",  "—",  ACCENT_P)
        self.lbl_lost    = self._sl("LOST",    "—",  ACCENT_R)
        self.lbl_losspct = self._sl("LOSS %",  "—",  ACCENT_Y)
        for w in [self.lbl_sent, self.lbl_recv_b, self.lbl_lost, self.lbl_losspct]:
            l1.addWidget(w)

        g2, l2 = gb(f"RATE  ({StatsModel.WINDOW:.0f}s pencere)")
        self.lbl_sent_rate = self._sl("SENT/s",  "0.00")
        self.lbl_udp_age   = self._sl("SON UDP", "—",   ACCENT_P)
        for w in [self.lbl_sent_rate, self.lbl_udp_age]:
            l2.addWidget(w)

        g3, l3 = gb("OTURUM")
        self.lbl_elapsed = self._sl("ELAPSED", "00:00:00")
        self.lbl_status  = self._sl("STATUS",  "IDLE",         TEXT_DIM)
        self.lbl_udp_ok  = self._sl("UDP",     "bekleniyor...", TEXT_DIM)
        for w in [self.lbl_elapsed, self.lbl_status, self.lbl_udp_ok]:
            l3.addWidget(w)

        sr.addWidget(g1); sr.addWidget(g2); sr.addWidget(g3); sr.addStretch()
        main.addLayout(sr)

        # ── log table ─────────────────────────────────────────────────────
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["ZAMAN", "KAYNAK", "YON", "ADET", "BOYUT"])
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.Stretch)
        for c in range(5): hh.setSectionResizeMode(c, QHeaderView.ResizeToContents)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(22)
        main.addWidget(self.table, stretch=1)

        self.btn_start.clicked.connect(self._on_start)
        self.btn_stop.clicked.connect(self._on_stop)

    def _sl(self, tag, val, color=TEXT_PRI):
        lbl = QLabel(); lbl.setTextFormat(Qt.RichText)
        self._upd(lbl, tag, val, color); return lbl

    def _upd(self, lbl, tag, val, color=TEXT_PRI):
        lbl.setText(
            f'<span style="color:{TEXT_SEC};font-size:10px;">{tag}&nbsp;&nbsp;</span>'
            f'<span style="color:{color};font-size:13px;">{val}</span>'
        )

    # ── populate ──────────────────────────────────────────────────────────
    def _populate_ifaces(self):
        self.combo_iface.clear()
        if not SCAPY_OK:
            self.combo_iface.addItem("Scapy bulunamadi"); return
        try:
            for iface_id, iface in scapy_ifaces.items():
                try:
                    ip    = iface.ip if iface.ip else "no ip"
                    desc  = iface.description if iface.description else iface_id
                    label = f"{desc} — {ip}"
                    self.combo_iface.addItem(label, userData=iface_id)
                except Exception:
                    self.combo_iface.addItem(str(iface_id), userData=iface_id)
        except Exception:
            for iface in get_if_list():
                self.combo_iface.addItem(iface, userData=iface)

    def _populate_msgs(self):
        self.combo_msg.clear()
        for name in self._msg_defs:
            self.combo_msg.addItem(name)

    def _iface_ip(self, iface_id):
        # TD-2: Secilen adapter'in IP'sini guvenle cek. _populate_ifaces iki
        # yol kullanir: (1) scapy_ifaces dict'i (iface.ip) ya da (2) fallback
        # olarak get_if_list() (userData=iface_id plain string, .ip yok).
        # Her iki durumda da KeyError/AttributeError firlatmamali.
        try:
            return scapy_ifaces[iface_id].ip
        except (KeyError, AttributeError):
            return None

    def _reload_messages(self):
        self._load_messages()
        cur = self.combo_msg.currentText()
        self._populate_msgs()
        idx = self.combo_msg.findText(cur)
        if idx >= 0: self.combo_msg.setCurrentIndex(idx)

    # ── start / stop ──────────────────────────────────────────────────────
    def _on_start(self):
        if not SCAPY_OK:
            QMessageBox.critical(self, "Hata", "Scapy kurulu degil.\npip install scapy")
            return

        remote_ip = self.edit_ip.text().strip()
        tcp_port  = self.edit_tcp_port.text().strip()
        udp_port  = self.edit_udp_port.text().strip()
        iface     = self.combo_iface.currentData()
        msg_name  = self.combo_msg.currentText()

        if not remote_ip or not tcp_port or not udp_port:
            QMessageBox.warning(self, "Eksik", "Remote IP, TCP Port ve UDP Port girilmeli.")
            return
        if msg_name not in self._msg_defs:
            QMessageBox.warning(self, "Mesaj yok", "Gecerli mesaj tipi secin.")
            return

        # TD-2: Secilen adapter'in GERCEK IP'sini Scapy'den al.
        # socket.gethostbyname(socket.gethostname()) Windows'ta cogunlukla
        # 127.0.0.1 ya da sanal adapter IP'si doner -> BPF "src host" yanlis
        # olur -> HIC paket yakalanmaz (sessiz, hata da firlatilmaz). Cozum:
        # scapy_ifaces[iface_id].ip. _populate_ifaces de ayni kaynagi kullanir.
        local_ip = self._iface_ip(iface)
        if not local_ip:
            # Adapter'in IP'si yok (promiscuous / sadece-sniff adapter) ->
            # BPF "src host" bos olur, yine HIC paket yakalanmaz. Kullaniciyi
            # uyar ve baska adapter secmesini iste.
            QMessageBox.warning(
                self, "Adapter IP yok",
                "Secilen adapter'in bir IP adresi yok (promiscuous / "
                "sadece-sniff adapter olabilir).\n\n"
                "BPF filtresi 'src host <IP>' bos olacagi icin HIC paket "
                "yakalanamaz.\n\nLutfen IP'si olan bir adapter secin.")
            return

        self._active_msg = msg_name
        self._stats.reset()
        self._start_time = time.time()
        self.table.setRowCount(0)

        self._capture = CaptureEngine(
            iface=iface, local_ip=local_ip, remote_ip=remote_ip,
            port=tcp_port, msg_def=self._msg_defs[msg_name],
            signals=self._signals,
        )
        self._capture.start()

        self._udp_lstn = UDPListener(int(udp_port), self._signals)
        self._udp_lstn.start()

        # TD-3: B'ye RESET komutu gonder, boylece B'nin sayaci A'nin START
        # aninda sifirlansin. Bu baseline gecikmesini (Bölüm 6.3) ortadan
        # kaldirir: reset gelirse B 0'dan saymaya baslar, A'nin baseline
        # yakalamasi anlik olur. UDP guvenilir degil; reset kaybolursa mevcut
        # baseline fallback'i (ilk rapordan baseline alma) devreye girer.
        # Listener onceden baslatildi ki B'nin reset'e karsilik gonderdigi
        # raporu kacirmayalim.
        self._send_reset(remote_ip, int(udp_port))

        self._ui_timer.start()
        self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True)
        self._controls_enabled(False)
        self._upd(self.lbl_status, "STATUS", "CAPTURING", ACCENT_G)
        self._upd(self.lbl_udp_ok, "UDP", "bekleniyor...", ACCENT_Y)

    def _on_stop(self):
        if self._capture:  self._capture.stop();  self._capture = None
        if self._udp_lstn: self._udp_lstn.stop(); self._udp_lstn = None
        self._ui_timer.stop()
        self.btn_stop.setEnabled(False); self.btn_start.setEnabled(True)
        self._controls_enabled(True)
        self._upd(self.lbl_status, "STATUS", "STOPPED", ACCENT_R)

    def _send_reset(self, remote_ip, udp_port):
        # TD-3: A'nin START aninda B'ye gonderdigi RESET komutu. UDP tek
        # marker byte (0xFD) icerir. B bunu alinca CounterStore sifirlanir.
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(bytes([UDP_COMMAND_ID]), (remote_ip, udp_port))
        except Exception:
            # UDP guvenilir degil; reset kaybolursa baseline fallback'i calisir.
            # Sessizce gec: START'i iptal etmemeli.
            pass
        finally:
            if sock:
                try: sock.close()
                except Exception: pass

    def _controls_enabled(self, en):
        for w in [self.combo_iface, self.combo_msg, self.edit_ip,
                  self.edit_tcp_port, self.edit_udp_port, self.btn_reload]:
            w.setEnabled(en)

    # ── packet handlers ───────────────────────────────────────────────────
    def _on_sent(self, count: int, total_bytes: int):
        ts = time.time()
        self._stats.add_sent(count, ts)
        self._log_row(
            ts=ts, source="Npcap",
            direction="→ SENT",
            count=count,
            size=total_bytes,
            color=ACCENT_G,
        )

    def _on_udp_report(self, report: dict):
        msg = self._active_msg
        if msg in report:
            self._stats.update_recv_b(report[msg])
            self._upd(self.lbl_udp_ok, "UDP", "✓ bagli", ACCENT_G)
            detail = "  ".join(f"{k}={v}" for k, v in report.items())
            self._log_row(
                ts=time.time(), source="UDP / B",
                direction="← REPORT",
                count=report[msg],
                size=0,
                color=ACCENT_P,
            )

    def _log_row(self, ts, source, direction, count, size, color):
        if self.table.rowCount() >= self.MAX_LOG:
            self.table.removeRow(0)
        row = self.table.rowCount()
        self.table.insertRow(row)
        size_str  = f"{size} B" if size else "—"
        count_str = str(count)
        qc = QColor(color)
        for col, txt in enumerate([
            time.strftime("%H:%M:%S", time.localtime(ts)),
            source, direction, count_str, size_str,
        ]):
            it = QTableWidgetItem(txt)
            it.setForeground(qc)
            it.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, col, it)
        self.table.scrollToBottom()

    # ── stats refresh ─────────────────────────────────────────────────────
    def _refresh_stats(self):
        s  = self._stats
        lc = ACCENT_G if s.loss_pct < 1 else (ACCENT_Y if s.loss_pct < 10 else ACCENT_R)

        self._upd(self.lbl_sent,      "A SENT",  str(s.sent_total))
        recv_str = str(s.recv_b)   if s.udp_ok else "—"
        lost_str = str(s.lost_total) if s.udp_ok else "—"
        pct_str  = f"{s.loss_pct:.1f} %" if s.udp_ok else "—"
        self._upd(self.lbl_recv_b,    "B RECV",  recv_str,  ACCENT_P)
        self._upd(self.lbl_lost,      "LOST",    lost_str,  ACCENT_R)
        self._upd(self.lbl_losspct,   "LOSS %",  pct_str,   lc)
        self._upd(self.lbl_sent_rate, "SENT/s",  f"{s.sent_rate:.2f}")
        self._upd(self.lbl_udp_age,   "SON UDP", s.udp_age, ACCENT_P)

        if self._start_time:
            e = int(time.time() - self._start_time)
            h, r = divmod(e, 3600); m, sec = divmod(r, 60)
            self._upd(self.lbl_elapsed, "ELAPSED", f"{h:02d}:{m:02d}:{sec:02d}")

    def _on_error(self, msg: str):
        self._on_stop()
        QMessageBox.critical(self, "Hata", msg)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = NpcapChecker()
    win.show()
    sys.exit(app.exec_())
