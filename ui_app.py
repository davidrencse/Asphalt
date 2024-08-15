"""
Asphalt UI app (PySide6) that runs the full pipeline:
Capture -> Decode -> Display

Run:
  python ui_app.py
"""
import json
import os
import sys
import threading
import subprocess
import time
from datetime import datetime, timezone

try:
    from PySide6 import QtCore, QtWidgets, QtGui
except Exception as exc:
    raise SystemExit("PySide6 is required to run this UI. Install it with: pip install PySide6") from exc

try:
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    _HAS_MPL = True
except Exception:
    Figure = None
    FigureCanvas = None
    _HAS_MPL = False

def _resolve_project_root() -> str:
    """Return project root for both source and PyInstaller builds."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS  # type: ignore[attr-defined]
    return os.path.dirname(os.path.abspath(__file__))

PROJECT_ROOT = _resolve_project_root()
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from analysis.engine import AnalysisEngine
from analysis.registry import create_analyzer
from capture.decoder import PacketDecoder
from capture.icapture_backend import CaptureConfig
from models.packet import RawPacket
from pcap_loader.pcap_reader import PcapReader
from pcap_loader.pcapng_reader import PcapngReader


BG_MAIN = "#000000"
BG_PANEL = "#0a0a0a"
BG_HEADER = "#050505"
BG_CARD = "#101010"
FG_TEXT = "#ffffff"
FG_MUTED = "#c7c7c7"
ACCENT = "#ffffff"
ACCENT_BTN_BG = "#ffffff"
ACCENT_BTN_FG = "#000000"
WARN = "#e0e0e0"
GOOD = "#4caf50"
WARN_BADGE = "#ffb300"
BAD = "#e53935"
INFO_BADGE = "#9e9e9e"
BORDER_DARK = "#111111"
TITLEBAR_BG = "#050505"
TITLEBAR_BTN_BG = "#0d0d0d"
TITLEBAR_BTN_HOVER = "#1a1a1a"
TITLEBAR_BTN_DANGER = "#3a0c0c"
TITLEBAR_BTN_DANGER_HOVER = "#5a1414"

DROP_RATE_WARN = 1.0
DROP_RATE_BAD = 5.0
HANDSHAKE_WARN_LO = 85.0
HANDSHAKE_GOOD_LO = 95.0
RETX_WARN = 1.0
RETX_BAD = 3.0
RST_WARN = 1.0
RST_BAD = 3.0
SCAN_PORTS_WARN = 100
ARP_CONFLICT_WARN = 1
NXDOMAIN_SPIKE_WARN = True
ABNORMAL_RST_RATIO_THRESHOLD = 20.0

DEFAULT_ANALYZERS = [
    "capture_health",
    "global_stats",
    "protocol_mix",
    "flow_summary",
    "tcp_handshakes",
    "tcp_reliability",
    "tcp_performance",
    "abnormal_activity",
    "scan_signals",
    "arp_lan_signals",
    "dns_anomalies",
    "packet_chunks",
    "time_series",
    "throughput_peaks",
    "packet_size_stats",
    "l2_l3_breakdown",
    "top_entities",
    "flow_analytics",
]

REQUIRED_UI_ANALYZERS = {
    "global_stats",
    "capture_health",
    "tcp_reliability",
    "protocol_mix",
    "flow_analytics",
}

_PCAP_MAGIC = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def _extract_json_array(text: str):
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("No JSON array found in output")
    return json.loads(text[start:end + 1])


def _run_capture_direct(backend: str, interface: str, duration: int, limit: int):
    if backend != "scapy":
        raise RuntimeError("Only scapy backend is supported.")
    try:
        from capture.scapy_backend import ScapyBackend
    except Exception as exc:
        raise RuntimeError(f"Failed to import scapy backend: {exc}") from exc

    capture_backend = ScapyBackend()
    config = CaptureConfig(interface=interface, filter=None, buffer_size=10000)

    decoder = PacketDecoder()
    records = []
    decoded_count = 0
    start_time = datetime.now().timestamp()
    session_id = None

    try:
        session_id = capture_backend.start(config)
        idle_start = datetime.now().timestamp()
        while True:
            now = datetime.now().timestamp()
            if duration and (now - start_time) >= duration:
                break

            packets = capture_backend.get_packets(session_id, count=100)
            if not packets:
                time.sleep(0.01)
                # Avoid hanging forever when limit is set but no packets arrive
                if duration <= 0 and limit > 0 and (now - start_time) > 10:
                    break
                continue

            idle_start = now
            for pkt in packets:
                raw = RawPacket(
                    packet_id=decoded_count + 1,
                    timestamp_us=int(pkt["ts"] * 1_000_000),
                    captured_length=len(pkt["data"]),
                    original_length=pkt.get("wirelen", len(pkt["data"])),
                    link_type=1,
                    data=pkt["data"],
                    pcap_ref="live:0:0",
                )
                decoded = decoder.decode(raw)
                records.append(decoded.to_dict())
                decoded_count += 1
                if limit > 0 and decoded_count >= limit:
                    return records
    finally:
        if session_id:
            try:
                capture_backend.stop(session_id)
            except Exception:
                pass

    return records


def run_capture(backend: str, interface: str, duration: int, limit: int):
    env = os.environ.copy()
    env["PYTHONPATH"] = SRC_DIR

    cmd = [
        sys.executable,
        os.path.join(PROJECT_ROOT, "run.py"),
        "capture-decode",
        "--format",
        "json",
    ]

    if interface:
        cmd += ["--interface", interface]
    if duration > 0:
        cmd += ["--duration", str(duration)]
    if limit > 0:
        cmd += ["--limit", str(limit)]

    timeout = None
    if duration and duration > 0:
        timeout = duration + 10
    elif limit and limit > 0:
        timeout = 30

    try:
        # Prefer direct capture to avoid subprocess hangs.
        return _run_capture_direct("scapy", interface, duration, limit)
    except Exception:
        pass

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=PROJECT_ROOT, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("capture timed out") from exc
    if result.returncode != 0:
        msg = (result.stderr or result.stdout or "capture failed").strip()
        raise RuntimeError(msg)

    output = (result.stdout or "").strip()
    if not output:
        return []

    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return _extract_json_array(output)


def get_default_scapy_iface():
    try:
        from scapy.arch.windows import get_windows_if_list
    except Exception:
        return ""

    win_ifaces = get_windows_if_list()
    preferred = None
    for iface in win_ifaces:
        name = (iface.get("name") or "").lower()
        desc = (iface.get("description") or "").lower()
        ips = iface.get("ips") or []
        guid = iface.get("guid")
        if not guid or not ips:
            continue
        if "wi-fi" in name or "wireless" in desc:
            preferred = iface
            break
    if not preferred:
        for iface in win_ifaces:
            desc = (iface.get("description") or "").lower()
            ips = iface.get("ips") or []
            guid = iface.get("guid")
            if guid and ips and "wan miniport" not in desc:
                preferred = iface
                break
    if not preferred:
        return ""
    return rf"\Device\NPF_{preferred.get('guid')}"


def _select_reader(filepath: str):
    lower = filepath.lower()
    if lower.endswith(".pcapng"):
        return PcapngReader
    if lower.endswith(".pcap"):
        return PcapReader

    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
    except OSError as exc:
        raise RuntimeError(f"Failed to open file: {exc}") from exc

    if magic == _PCAPNG_MAGIC:
        return PcapngReader
    if magic in _PCAP_MAGIC:
        return PcapReader

    raise RuntimeError("Unsupported capture file format")


def _build_analyzers(
    analyzer_names,
    bucket_ms: int,
    chunk_size: int,
    scan_port_threshold: int,
    rst_ratio_threshold: float,
):
    analyzers = []
    for name in analyzer_names:
        if name == "time_series":
            analyzers.append(create_analyzer(name, bucket_ms=bucket_ms))
        elif name == "packet_chunks":
            analyzers.append(create_analyzer(name, chunk_size=chunk_size))
        elif name == "abnormal_activity":
            analyzers.append(create_analyzer(
                name,
                scan_port_threshold=scan_port_threshold,
                rst_ratio_threshold=rst_ratio_threshold,
            ))
        else:
            analyzers.append(create_analyzer(name))
    return analyzers


def _decode_capture_file(
    filepath: str,
    analyzer_names=None,
    bucket_ms: int = 1000,
    chunk_size: int = 200,
    scan_port_threshold: int = SCAN_PORTS_WARN,
    rst_ratio_threshold: float = 0.2,
):
    reader_cls = _select_reader(filepath)
    decoder = PacketDecoder()
    packets = []
    capture_info = {}

    analyzers = None
    engine = None
    if analyzer_names:
        analyzers = _build_analyzers(
            analyzer_names,
            bucket_ms=bucket_ms,
            chunk_size=chunk_size,
            scan_port_threshold=scan_port_threshold,
            rst_ratio_threshold=rst_ratio_threshold,
        )
        engine = AnalysisEngine(analyzers, capture_path=filepath, capture_info=capture_info)

    with reader_cls(filepath) as reader:
        try:
            capture_info = reader.get_session_info()
        except Exception:
            capture_info = {}
        if engine:
            engine.context.capture_info = capture_info or {}

        for packet in reader:
            decoded = decoder.decode(packet)
            record = decoded.to_dict()
            packets.append(record)
            if engine:
                engine.process_packet(decoded)

    analysis = engine.finalize().to_dict() if engine else {}
    return packets, analysis


def run_analysis(
    packets,
    bucket_ms: int = 1000,
    chunk_size: int = 200,
    scan_port_threshold: int = SCAN_PORTS_WARN,
    rst_ratio_threshold: float = 0.2,
):
    analyzers = _build_analyzers(
        DEFAULT_ANALYZERS,
        bucket_ms=bucket_ms,
        chunk_size=chunk_size,
        scan_port_threshold=scan_port_threshold,
        rst_ratio_threshold=rst_ratio_threshold,
    )
    engine = AnalysisEngine(analyzers)
    for packet in packets:
        engine.process_packet_dict(packet)
    return engine.finalize().to_dict()


def _fmt_number(value, digits=2):
    if value is None:
        return "n/a"
    try:
        return f"{float(value):.{digits}f}".rstrip("0").rstrip(".")
    except (TypeError, ValueError):
        return "n/a"


def _fmt_count(value):
    if value is None:
        return "n/a"
    try:
        return f"{int(round(float(value))):,}"
    except (TypeError, ValueError):
        return "n/a"


def _fmt_bps(value):
    if value is None:
        return "n/a"
    try:
        units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"]
        v = float(value)
        idx = 0
        while v >= 1000 and idx < len(units) - 1:
            v /= 1000
            idx += 1
        return f"{_fmt_number(v, 2)} {units[idx]}"
    except (TypeError, ValueError):
        return "n/a"


def _fmt_pps(value):
    if value is None:
        return "n/a"
    try:
        units = ["pps", "Kpps", "Mpps", "Gpps"]
        v = float(value)
        idx = 0
        while v >= 1000 and idx < len(units) - 1:
            v /= 1000
            idx += 1
        return f"{_fmt_number(v, 2)} {units[idx]}"
    except (TypeError, ValueError):
        return "n/a"


def _fmt_bytes(value):
    if value is None:
        return "n/a"
    try:
        units = ["B", "KB", "MB", "GB"]
        v = float(value)
        idx = 0
        while v >= 1024 and idx < len(units) - 1:
            v /= 1024
            idx += 1
        digits = 0 if idx == 0 else 2
        return f"{_fmt_number(v, digits)} {units[idx]}"
    except (TypeError, ValueError):
        return "n/a"


def _fmt_ts_utc(ts_us):
    if ts_us is None:
        return "n/a"
    try:
        dt = datetime.fromtimestamp(ts_us / 1_000_000)
        return dt.strftime("%I:%M:%S %p").lstrip("0")
    except (TypeError, ValueError, OSError):
        return "n/a"


def _fmt_pct(value):
    if value is None:
        return "n/a"
    try:
        return f"{float(value):.2f}%"
    except (TypeError, ValueError):
        return "n/a"


def _fmt_duration_us(value):
    if value is None:
        return "n/a"
    try:
        us = float(value)
        if us < 1_000:
            return f"{_fmt_number(us, 0)} us"
        if us < 1_000_000:
            return f"{_fmt_number(us / 1_000, 2)} ms"
        return f"{_fmt_number(us / 1_000_000, 2)} s"
    except (TypeError, ValueError):
        return "n/a"


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

class AsphaltApp(QtWidgets.QMainWindow):
    ui_call = QtCore.Signal(object)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Asphalt")
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.Window)
        self.resize(1280, 860)
        self.has_mpl = _HAS_MPL
        self._drag_pos = None

        self.latest_packets = []
        self.latest_analysis = {}
        self._packet_search_cache = []
        self._capture_stop_flag = threading.Event()
        self._last_capture_note = ""
        self._home_progress_timer = None
        self._capture_started_at = None
        self._capture_duration_s = 0
        self._home_progress_mode = "idle"

        self.ui_call.connect(lambda fn: fn())
        self._build_ui()

    def _build_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        outer = QtWidgets.QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        chrome = QtWidgets.QFrame()
        chrome.setObjectName("chrome")
        chrome_layout = QtWidgets.QVBoxLayout(chrome)
        chrome_layout.setContentsMargins(1, 1, 1, 1)
        chrome_layout.setSpacing(0)
        outer.addWidget(chrome)

        self.title_bar = self._build_title_bar()
        chrome_layout.addWidget(self.title_bar)

        # Initialize stat labels first (needed by info cards)
        self.stat_packets = self._value_label("0")
        self.stat_ip = self._value_label("0 / 0")
        self.stat_l4 = self._value_label("0 / 0")
        self.stat_flows = self._value_label("0")
        self.stat_rst = self._value_label("-")
        self.stat_drops = self._value_label("-")
        self.stat_top_proto = self._value_label("-")
        self.analysis_protocol = self._value_label("-")
        self.analysis_bytes = self._value_label("-")
        self.analysis_handshake = self._value_label("-")
        self.analysis_chunks = self._value_label("-")
        self.analysis_eth = self._value_label("-")
        self.analysis_dns = self._value_label("-")
        self.analysis_unique_ips = self._value_label("-")
        
        # Header Navigation (like reference image)
        header_nav = self._build_header_nav()
        chrome_layout.addWidget(header_nav)
        
        # Info Cards Row (restored to header)
        info_cards_row = self._build_info_cards_row()
        chrome_layout.addWidget(info_cards_row)

        body = QtWidgets.QFrame()
        body.setObjectName("body")
        body.setStyleSheet("""
            QFrame#body {
                background-color: %s;
                background-image: 
                    linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
                background-size: 40px 40px;
            }
        """ % BG_MAIN)
        body_layout = QtWidgets.QVBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)
        chrome_layout.addWidget(body, 1)

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent; border: none;")
        body_layout.addWidget(scroll)

        content = QtWidgets.QWidget()
        scroll.setWidget(content)
        root = QtWidgets.QVBoxLayout(content)
        root.setContentsMargins(40, 40, 40, 40)
        root.setSpacing(30)

        # Central Branding Section (like reference image)
        branding_section = self._build_branding_section()
        root.addWidget(branding_section, 0, QtCore.Qt.AlignCenter)

        # Home status text (capture state)
        self.home_status_label = QtWidgets.QLabel("CAPTURE UNINITIALIZED")
        self.home_status_label.setStyleSheet("""
            color: %s;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        """ % FG_MUTED)
        root.addWidget(self.home_status_label, 0, QtCore.Qt.AlignCenter)

        # Utilities Container - All utilities clearly visible
        utilities_container = QtWidgets.QWidget()
        utilities_layout = QtWidgets.QGridLayout(utilities_container)
        utilities_layout.setSpacing(20)
        
        # Capture Panel
        capture_panel = self._build_capture_panel()
        utilities_layout.addWidget(capture_panel, 0, 0)
        
        # Decode Panel
        decode_panel = self._build_decode_panel()
        utilities_layout.addWidget(decode_panel, 0, 1)
        
        # Analyze Panel
        analyze_panel = self._build_analyze_panel()
        utilities_layout.addWidget(analyze_panel, 0, 2)
        
        # Stats Panel
        stats_panel = self._build_stats_panel()
        utilities_layout.addWidget(stats_panel, 1, 0, 1, 3)
        
        root.addWidget(utilities_container)

        # OSI filter controls (for packet overview)
        self.osi_l2_eth = QtWidgets.QCheckBox("Ethernet")
        self.osi_l2_arp = QtWidgets.QCheckBox("ARP")
        self.osi_l3_ipv4 = QtWidgets.QCheckBox("IPv4")
        self.osi_l3_ipv6 = QtWidgets.QCheckBox("IPv6")
        self.osi_l4_tcp = QtWidgets.QCheckBox("TCP")
        self.osi_l4_udp = QtWidgets.QCheckBox("UDP")
        self.osi_app_dns = QtWidgets.QCheckBox("DNS")
        self.osi_clear_btn = QtWidgets.QPushButton("Clear")
        self.osi_clear_btn.setObjectName("overviewClearBtn")
        self.osi_clear_btn.setCursor(QtCore.Qt.PointingHandCursor)
        self.osi_clear_btn.setStyleSheet(
            "QPushButton { background-color: %s; color: %s; border: 1px solid %s; padding: 4px 10px; border-radius: 8px; }"
            % (ACCENT_BTN_BG, ACCENT_BTN_FG, BORDER_DARK)
        )

        # Packet overview section
        overview_box, overview_layout = self._make_section("PACKET OVERVIEW")
        overview_controls = QtWidgets.QHBoxLayout()
        overview_controls.addWidget(QtWidgets.QLabel("Group by"))
        self.group_ip_btn = QtWidgets.QPushButton("IP Version")
        self.group_ip_btn.setCheckable(True)
        self.group_l4_btn = QtWidgets.QPushButton("L4 Protocol")
        self.group_l4_btn.setCheckable(True)
        self.group_ip_btn.setChecked(True)
        group_buttons = QtWidgets.QButtonGroup(self)
        group_buttons.setExclusive(True)
        group_buttons.addButton(self.group_ip_btn)
        group_buttons.addButton(self.group_l4_btn)
        overview_btn_style = (
            "QPushButton { background-color: %s; color: %s; border: 1px solid %s; padding: 4px 10px; border-radius: 8px; }"
            "QPushButton:checked { background-color: %s; color: %s; }"
            % (BG_HEADER, FG_TEXT, BORDER_DARK, ACCENT_BTN_BG, ACCENT_BTN_FG)
        )
        self.group_ip_btn.setStyleSheet(overview_btn_style)
        self.group_l4_btn.setStyleSheet(overview_btn_style)
        overview_check_style = (
            "QCheckBox { color: %s; }"
            "QCheckBox::indicator { width: 14px; height: 14px; }"
            "QCheckBox::indicator:unchecked { background: %s; border: 1px solid %s; border-radius: 4px; }"
            "QCheckBox::indicator:checked { background: %s; border: 1px solid %s; border-radius: 4px; }"
            % (FG_TEXT, BG_HEADER, INFO_BADGE, ACCENT_BTN_BG, INFO_BADGE)
        )
        for cb in (
            self.osi_l2_eth, self.osi_l2_arp,
            self.osi_l3_ipv4, self.osi_l3_ipv6,
            self.osi_l4_tcp, self.osi_l4_udp,
            self.osi_app_dns,
        ):
            cb.setStyleSheet(overview_check_style)
        overview_controls.addWidget(self.group_ip_btn)
        overview_controls.addWidget(self.group_l4_btn)
        overview_controls.addSpacing(10)
        overview_controls.addWidget(self.osi_l2_eth)
        overview_controls.addWidget(self.osi_l2_arp)
        overview_controls.addWidget(self.osi_l3_ipv4)
        overview_controls.addWidget(self.osi_l3_ipv6)
        overview_controls.addWidget(self.osi_l4_tcp)
        overview_controls.addWidget(self.osi_l4_udp)
        overview_controls.addWidget(self.osi_app_dns)
        overview_controls.addWidget(self.osi_clear_btn)
        overview_controls.addStretch(1)
        overview_layout.addLayout(overview_controls)

        self.packet_overview = QtWidgets.QTreeWidget()
        self.packet_overview.setColumnCount(8)
        self.packet_overview.setHeaderLabels(["No.", "Time", "Source", "Destination", "Protocol", "Length", "OSI", "Info"])
        self.packet_overview.setRootIsDecorated(True)
        self.packet_overview.setAlternatingRowColors(True)
        self.packet_overview.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        self.packet_overview.setMinimumHeight(280)
        self._packet_overview_resized = False
        self._packet_overview_loaded_ids = set()
        self._packet_group_cache = {"ip": None, "l4": None}
        header = self.packet_overview.header()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QtWidgets.QHeaderView.ResizeToContents)
        self.packet_overview.setTextElideMode(QtCore.Qt.ElideNone)
        overview_layout.addWidget(self.packet_overview)
        root.addWidget(overview_box)

        # Tabs for detailed views
        self.main_tabs = QtWidgets.QTabWidget()
        self.main_tabs.setStyleSheet(
            "QTabWidget::pane { border: 0; }"
            "QTabBar::tab { background: %s; color: %s; padding: 6px 10px; }"
            "QTabBar::tab:selected { background: %s; color: %s; }" % (BG_HEADER, FG_TEXT, BG_PANEL, ACCENT)
        )
        root.addWidget(self.main_tabs, 1)

        self.raw_data_tab = QtWidgets.QWidget()
        self.tech_info_tab = QtWidgets.QWidget()
        self.dashboard_tab = QtWidgets.QWidget()
        self.packet_tab = QtWidgets.QWidget()

        self.main_tabs.addTab(self.raw_data_tab, "Raw Data")
        self.main_tabs.addTab(self.tech_info_tab, "Technical Information")
        self.main_tabs.addTab(self.dashboard_tab, "Dashboard")
        self.main_tabs.addTab(self.packet_tab, "Packets")

        self._build_raw_data_tab()
        self._build_technical_info_tab()
        self._build_dashboard_tab()
        self._build_packet_tab()
        
        # Footer (like reference image)
        footer = self._build_footer()
        chrome_layout.addWidget(footer)

        self._apply_theme()
        self._init_home_progress_timer()
        self.group_ip_btn.clicked.connect(lambda _checked=False: self.refresh_packet_overview())
        self.group_l4_btn.clicked.connect(lambda _checked=False: self.refresh_packet_overview())
        self.packet_overview.itemClicked.connect(self._on_packet_overview_click)
        self.packet_overview.itemExpanded.connect(self._on_packet_overview_expand)
        for cb in [
            self.osi_l2_eth, self.osi_l2_arp,
            self.osi_l3_ipv4, self.osi_l3_ipv6,
            self.osi_l4_tcp, self.osi_l4_udp,
            self.osi_app_dns,
        ]:
            cb.stateChanged.connect(self.refresh_packet_overview)
        self.osi_clear_btn.clicked.connect(self._clear_packet_overview_settings)

    def _build_header_nav(self):
        """Build header navigation in row/column layout."""
        nav_frame = QtWidgets.QFrame()
        nav_frame.setObjectName("headerNav")
        nav_frame.setFixedHeight(80)
        nav_frame.setStyleSheet("""
            QFrame#headerNav {
                background-color: %s;
                border-bottom: 1px solid %s;
            }
        """ % (BG_HEADER, BORDER_DARK))
        
        layout = QtWidgets.QHBoxLayout(nav_frame)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(30)
        
        # CAPTURE
        capture_label = QtWidgets.QLabel("CAPTURE")
        capture_label.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        """ % FG_TEXT)
        layout.addWidget(capture_label)
        
        # ANALYZE
        analyze_label = QtWidgets.QLabel("ANALYZE")
        analyze_label.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        """ % FG_TEXT)
        layout.addWidget(analyze_label)
        
        # UTILITIES
        utils_label = QtWidgets.QLabel("UTILITIES")
        utils_label.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        """ % FG_TEXT)
        layout.addWidget(utils_label)
        
        layout.addStretch()
        
        # SESSION
        session_label = QtWidgets.QLabel("SESSION [0]")
        session_label.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        """ % FG_TEXT)
        layout.addWidget(session_label)
        
        # Session grid (8 boxes)
        session_grid = QtWidgets.QWidget()
        grid_layout = QtWidgets.QGridLayout(session_grid)
        grid_layout.setSpacing(4)
        grid_layout.setContentsMargins(0, 0, 0, 0)
        self.session_boxes = []
        for i in range(8):
            box = QtWidgets.QFrame()
            box.setFixedSize(20, 20)
            box.setStyleSheet("background-color: %s; border: 1px solid %s;" % (BG_PANEL, BORDER_DARK))
            self.session_boxes.append(box)
            grid_layout.addWidget(box, i // 4, i % 4)
        layout.addWidget(session_grid)
        
        return nav_frame
    
    def _build_info_cards_row(self):
        """Build info cards in two rows in header."""
        cards_frame = QtWidgets.QFrame()
        cards_frame.setObjectName("infoCards")
        cards_frame.setStyleSheet("""
            QFrame#infoCards {
                background-color: %s;
                border-bottom: 1px solid %s;
            }
        """ % (BG_HEADER, BORDER_DARK))
        
        main_layout = QtWidgets.QVBoxLayout(cards_frame)
        main_layout.setContentsMargins(20, 10, 20, 10)
        main_layout.setSpacing(10)
        
        # First row
        row1 = QtWidgets.QHBoxLayout()
        row1.setSpacing(15)
        row1.addStretch()
        row1.addWidget(self._stat_block("Packets", self.stat_packets, width=150))
        row1.addWidget(self._stat_block("RST %%", self.stat_rst, width=150))
        row1.addWidget(self._stat_block("IPv4 / IPv6", self.stat_ip, width=150))
        row1.addWidget(self._stat_block("Drops", self.stat_drops, width=150))
        row1.addWidget(self._stat_block("TCP / UDP", self.stat_l4, width=150))
        row1.addWidget(self._stat_block("Top Protocol", self.stat_top_proto, width=150))
        row1.addWidget(self._stat_block("Flows", self.stat_flows, width=150))
        row1.addStretch()
        main_layout.addLayout(row1)
        
        # Second row
        row2 = QtWidgets.QHBoxLayout()
        row2.setSpacing(15)
        row2.addStretch()
        row2.addWidget(self._stat_block("Protocol Mix", self.analysis_protocol, width=150))
        row2.addWidget(self._stat_block("Ethernet Connections", self.analysis_eth, width=150))
        row2.addWidget(self._stat_block("Bytes Captured", self.analysis_bytes, width=150))
        row2.addWidget(self._stat_block("DNS Connections", self.analysis_dns, width=150))
        row2.addWidget(self._stat_block("TCP Handshakes", self.analysis_handshake, width=150))
        row2.addWidget(self._stat_block("Packet Chunks", self.analysis_chunks, width=150))
        row2.addWidget(self._stat_block("Unique IPs", self.analysis_unique_ips, width=150))
        row2.addStretch()
        main_layout.addLayout(row2)
        
        return cards_frame
    
    def _build_branding_section(self):
        """Build central branding section with L-bracket accents."""
        branding = QtWidgets.QFrame()
        branding.setObjectName("brandingSection")
        branding.setStyleSheet("""
            QFrame#brandingSection {
                background-color: %s;
                border: 2px solid %s;
                padding: 40px;
            }
        """ % (BG_PANEL, ACCENT))
        
        layout = QtWidgets.QVBoxLayout(branding)
        layout.setSpacing(10)
        layout.setAlignment(QtCore.Qt.AlignCenter)
        
        title = QtWidgets.QLabel("ASPHALT.NETWORK")
        title.setStyleSheet("""
            color: %s;
            font-size: 48px;
            font-weight: 700;
            letter-spacing: 4px;
            text-transform: uppercase;
        """ % FG_TEXT)
        layout.addWidget(title, 0, QtCore.Qt.AlignCenter)

        self.branding_progress = QtWidgets.QProgressBar()
        self.branding_progress.setRange(0, 100)
        self.branding_progress.setValue(0)
        self.branding_progress.setTextVisible(False)
        self.branding_progress.setFixedWidth(420)
        self.branding_progress.setFixedHeight(6)
        self.branding_progress.setStyleSheet("""
            QProgressBar {
                background-color: %s;
                border: 1px solid %s;
            }
            QProgressBar::chunk {
                background-color: %s;
            }
        """ % (BG_MAIN, BORDER_DARK, ACCENT))
        layout.addWidget(self.branding_progress, 0, QtCore.Qt.AlignCenter)
        
        tagline = QtWidgets.QLabel("IP.AXIS.NETWORK.DIAGNOSTICS")
        tagline.setStyleSheet("""
            color: %s;
            font-size: 14px;
            letter-spacing: 2px;
            text-transform: uppercase;
        """ % FG_MUTED)
        layout.addWidget(tagline, 0, QtCore.Qt.AlignCenter)
        
        return branding

    def _init_home_progress_timer(self):
        if self._home_progress_timer is not None:
            return
        self._home_progress_timer = QtCore.QTimer(self)
        self._home_progress_timer.setInterval(100)
        self._home_progress_timer.timeout.connect(self._update_home_progress)

    def _start_home_progress(self, duration_s: int, limit: int):
        if not hasattr(self, "branding_progress"):
            return
        self._capture_started_at = time.time()
        self._capture_duration_s = max(0, int(duration_s or 0))
        if self._capture_duration_s > 0:
            self._home_progress_mode = "time"
            self.branding_progress.setRange(0, 100)
            self.branding_progress.setValue(0)
        else:
            self._home_progress_mode = "busy"
            self.branding_progress.setRange(0, 0)  # indeterminate
        if self._home_progress_timer:
            self._home_progress_timer.start()
