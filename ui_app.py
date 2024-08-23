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

    def _stop_home_progress(self):
        if not hasattr(self, "branding_progress"):
            return
        if self._home_progress_timer:
            self._home_progress_timer.stop()
        if self._home_progress_mode == "time":
            self.branding_progress.setRange(0, 100)
            self.branding_progress.setValue(100)
        else:
            self.branding_progress.setRange(0, 100)
            self.branding_progress.setValue(100)
        self._home_progress_mode = "idle"

    def _update_home_progress(self):
        if not hasattr(self, "branding_progress"):
            return
        if self._home_progress_mode == "time":
            if not self._capture_started_at or self._capture_duration_s <= 0:
                return
            elapsed = time.time() - self._capture_started_at
            pct = int(min(100, max(0, (elapsed / self._capture_duration_s) * 100.0)))
            self.branding_progress.setValue(pct)
    
    def _build_capture_panel(self):
        """Build capture utility panel."""
        panel = QtWidgets.QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: %s;
                border: 1px solid %s;
            }
        """ % (BG_PANEL, BORDER_DARK))
        
        layout = QtWidgets.QVBoxLayout(panel)
        layout.setContentsMargins(20, 15, 20, 20)
        layout.setSpacing(15)
        
        header = QtWidgets.QLabel("CAPTURE")
        header.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 8px 0px;
            border-bottom: 1px solid %s;
        """ % (FG_TEXT, BORDER_DARK))
        layout.addWidget(header)
        
        # Interface
        iface_label = QtWidgets.QLabel("INTERFACE")
        iface_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(iface_label)
        default_iface = get_default_scapy_iface()
        self.interface_edit = QtWidgets.QLineEdit(default_iface)
        self.interface_edit.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        layout.addWidget(self.interface_edit)
        
        # Duration
        dur_label = QtWidgets.QLabel("DURATION (s)")
        dur_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(dur_label)
        self.duration_edit = QtWidgets.QLineEdit("10")
        self.duration_edit.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        layout.addWidget(self.duration_edit)
        
        # Limit
        limit_label = QtWidgets.QLabel("PACKET LIMIT")
        limit_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(limit_label)
        self.limit_edit = QtWidgets.QLineEdit("1000")
        self.limit_edit.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        layout.addWidget(self.limit_edit)
        
        # Filter
        filter_label = QtWidgets.QLabel("FILTER (BPF)")
        filter_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(filter_label)
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("tcp port 80")
        self.filter_edit.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        self.filter_edit.textChanged.connect(self.apply_filter)
        layout.addWidget(self.filter_edit)
        
        # Buttons
        btn_layout = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("START")
        self.start_btn.setStyleSheet("background-color: %s; color: %s; border: 1px solid %s; padding: 10px; font-weight: 600; text-transform: uppercase;" % (ACCENT_BTN_BG, ACCENT_BTN_FG, ACCENT))
        self.start_btn.clicked.connect(self.start_capture)
        btn_layout.addWidget(self.start_btn)
        
        self.stop_btn = QtWidgets.QPushButton("STOP")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("background-color: transparent; color: %s; border: 1px solid %s; padding: 10px; font-weight: 600; text-transform: uppercase;" % (FG_TEXT, BORDER_DARK))
        self.stop_btn.clicked.connect(self.stop_capture)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)
        
        # Status
        self.status_label = QtWidgets.QLabel("IDLE")
        self.status_label.setStyleSheet("color: %s; font-size: 11px;" % WARN)
        layout.addWidget(self.status_label)

        # Export
        export_layout = QtWidgets.QHBoxLayout()
        self.download_btn = QtWidgets.QPushButton("EXPORT CAPTURE")
        self.download_btn.setEnabled(False)
        self.download_btn.setStyleSheet("background-color: transparent; color: %s; border: 1px solid %s; padding: 8px; font-weight: 600; text-transform: uppercase;" % (FG_TEXT, BORDER_DARK))
        self.download_btn.clicked.connect(self.download_capture)
        export_layout.addWidget(self.download_btn)

        self.export_analysis_btn = QtWidgets.QPushButton("EXPORT ANALYSIS")
        self.export_analysis_btn.setEnabled(False)
        self.export_analysis_btn.setStyleSheet("background-color: transparent; color: %s; border: 1px solid %s; padding: 8px; font-weight: 600; text-transform: uppercase;" % (FG_TEXT, BORDER_DARK))
        self.export_analysis_btn.clicked.connect(self.export_analysis)
        export_layout.addWidget(self.export_analysis_btn)
        layout.addLayout(export_layout)
        
        return panel
    
    def _build_decode_panel(self):
        """Build decode utility panel."""
        panel = QtWidgets.QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: %s;
                border: 1px solid %s;
            }
        """ % (BG_PANEL, BORDER_DARK))
        
        layout = QtWidgets.QVBoxLayout(panel)
        layout.setContentsMargins(20, 15, 20, 20)
        layout.setSpacing(15)
        
        header = QtWidgets.QLabel("DECODE")
        header.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 8px 0px;
            border-bottom: 1px solid %s;
        """ % (FG_TEXT, BORDER_DARK))
        layout.addWidget(header)
        
        file_label = QtWidgets.QLabel("PCAP/PCAPNG FILE")
        file_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(file_label)
        
        file_layout = QtWidgets.QHBoxLayout()
        self.decode_file_edit = QtWidgets.QLineEdit()
        self.decode_file_edit.setPlaceholderText("Select file...")
        self.decode_file_edit.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        file_layout.addWidget(self.decode_file_edit)
        
        browse_btn = QtWidgets.QPushButton("BROWSE")
        browse_btn.setStyleSheet("background-color: %s; color: %s; border: 1px solid %s; padding: 8px; font-weight: 600; text-transform: uppercase;" % (ACCENT_BTN_BG, ACCENT_BTN_FG, ACCENT))
        browse_btn.clicked.connect(self._browse_decode_file)
        file_layout.addWidget(browse_btn)
        layout.addLayout(file_layout)
        
        format_label = QtWidgets.QLabel("OUTPUT FORMAT")
        format_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(format_label)
        self.format_combo = QtWidgets.QComboBox()
        self.format_combo.addItems(["JSON", "TABLE"])
        self.format_combo.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        layout.addWidget(self.format_combo)
        
        self.decode_btn = QtWidgets.QPushButton("DECODE")
        self.decode_btn.setStyleSheet("background-color: %s; color: %s; border: 1px solid %s; padding: 10px; font-weight: 600; text-transform: uppercase;" % (ACCENT_BTN_BG, ACCENT_BTN_FG, ACCENT))
        self.decode_btn.clicked.connect(self._decode_file)
        layout.addWidget(self.decode_btn)
        
        return panel
    
    def _build_analyze_panel(self):
        """Build analyze utility panel."""
        panel = QtWidgets.QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: %s;
                border: 1px solid %s;
            }
        """ % (BG_PANEL, BORDER_DARK))
        
        layout = QtWidgets.QVBoxLayout(panel)
        layout.setContentsMargins(20, 15, 20, 20)
        layout.setSpacing(15)
        
        header = QtWidgets.QLabel("ANALYZE")
        header.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 8px 0px;
            border-bottom: 1px solid %s;
        """ % (FG_TEXT, BORDER_DARK))
        layout.addWidget(header)
        
        file_label = QtWidgets.QLabel("PCAP/PCAPNG FILE")
        file_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(file_label)
        
        file_layout = QtWidgets.QHBoxLayout()
        self.analyze_file_edit = QtWidgets.QLineEdit()
        self.analyze_file_edit.setPlaceholderText("Select file...")
        self.analyze_file_edit.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        file_layout.addWidget(self.analyze_file_edit)
        
        browse_btn = QtWidgets.QPushButton("BROWSE")
        browse_btn.setStyleSheet("background-color: %s; color: %s; border: 1px solid %s; padding: 8px; font-weight: 600; text-transform: uppercase;" % (ACCENT_BTN_BG, ACCENT_BTN_FG, ACCENT))
        browse_btn.clicked.connect(self._browse_analyze_file)
        file_layout.addWidget(browse_btn)
        layout.addLayout(file_layout)
        
        analyzers_label = QtWidgets.QLabel("ANALYZERS")
        analyzers_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(analyzers_label)
        
        # Analyzers list (scrollable)
        from analysis.registry import list_analyzers
        analyzers_list = QtWidgets.QListWidget()
        analyzers_list.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        analyzers_list.setSelectionMode(QtWidgets.QAbstractItemView.MultiSelection)
        for analyzer in sorted(list_analyzers()):
            item = QtWidgets.QListWidgetItem(analyzer)
            item.setCheckState(QtCore.Qt.Checked)
            analyzers_list.addItem(item)
        analyzers_list.setMaximumHeight(150)
        layout.addWidget(analyzers_list)
        self.analyzers_list = analyzers_list
        
        bucket_label = QtWidgets.QLabel("BUCKET SIZE (ms)")
        bucket_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(bucket_label)
        self.bucket_ms_edit = QtWidgets.QLineEdit("1000")
        self.bucket_ms_edit.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        layout.addWidget(self.bucket_ms_edit)
        
        self.analyze_btn = QtWidgets.QPushButton("ANALYZE")
        self.analyze_btn.setStyleSheet("background-color: %s; color: %s; border: 1px solid %s; padding: 10px; font-weight: 600; text-transform: uppercase;" % (ACCENT_BTN_BG, ACCENT_BTN_FG, ACCENT))
        self.analyze_btn.clicked.connect(self._analyze_file)
        layout.addWidget(self.analyze_btn)
        
        return panel
    
    def _build_stats_panel(self):
        """Build top domains display panel."""
        panel = QtWidgets.QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: %s;
                border: 1px solid %s;
            }
        """ % (BG_PANEL, BORDER_DARK))
        
        layout = QtWidgets.QVBoxLayout(panel)
        layout.setContentsMargins(20, 15, 20, 20)
        layout.setSpacing(15)
        
        header = QtWidgets.QLabel("STATISTICS")
        header.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 8px 0px;
            border-bottom: 1px solid %s;
        """ % (FG_TEXT, BORDER_DARK))
        layout.addWidget(header)
        
        stats_grid = QtWidgets.QGridLayout()
        stats_grid.setSpacing(20)
        
        # Placeholder stats (top domain + upload/download + empty slots)
        self.top_domain_labels = [
            self._value_label("-"),
            self._value_label("-"),
            self._value_label("-"),
            self._value_label("-"),
            self._value_label("-"),
            self._value_label("-"),
            self._value_label("-"),
            self._value_label("-"),
        ]

        stats_grid.addWidget(self._stat_block("TOP DOMAIN", self.top_domain_labels[0]), 0, 0)
        stats_grid.addWidget(self._stat_block("UPLOAD / DOWNLOAD", self.top_domain_labels[1]), 0, 1)
        stats_grid.addWidget(self._stat_block("DOWNLOAD / UPLOAD SPEED", self.top_domain_labels[2]), 0, 2)
        stats_grid.addWidget(self._stat_block("SEARCH QUERIES", self.top_domain_labels[3]), 0, 3)
        stats_grid.addWidget(self._stat_block("NETWORK QUALITY", self.top_domain_labels[4]), 1, 0)
        stats_grid.addWidget(self._stat_block("UNUSUAL PORTS", self.top_domain_labels[5]), 1, 1)
        stats_grid.addWidget(self._stat_block("TOP EXTERNAL IP", self.top_domain_labels[6]), 1, 2)
        stats_grid.addWidget(self._stat_block("—", self.top_domain_labels[7]), 1, 3)
        
        layout.addLayout(stats_grid)
        
        return panel
    
    def _build_footer_legacy(self):
        """Build footer like reference image."""
        footer = QtWidgets.QFrame()
        footer.setObjectName("footer")
        footer.setStyleSheet("""
            QFrame#footer {
                background-color: %s;
                border-top: 1px solid %s;
            }
        """ % (BG_HEADER, BORDER_DARK))
        
        layout = QtWidgets.QHBoxLayout(footer)
        layout.setContentsMargins(40, 15, 40, 15)
        layout.setSpacing(40)
        
        # Left: Logo and brand
        left_section = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left_section)
        left_layout.setSpacing(5)
        
        logo_label = QtWidgets.QLabel("⚙")
        logo_label.setStyleSheet("font-size: 24px;")
        left_layout.addWidget(logo_label)
        
        trademark_label = QtWidgets.QLabel("TRADEMARK")
        trademark_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase;" % FG_MUTED)
        left_layout.addWidget(trademark_label)
        
        brand_label = QtWidgets.QLabel("ASPHALT.NETWORK")
        brand_label.setStyleSheet("color: %s; font-size: 14px; font-weight: 600; text-transform: uppercase;" % FG_TEXT)
        left_layout.addWidget(brand_label)
        
        layout.addWidget(left_section)
        
        # Middle: Company info
        middle_section = QtWidgets.QWidget()
        middle_layout = QtWidgets.QVBoxLayout(middle_section)
        middle_layout.setSpacing(4)
        
        company_label = QtWidgets.QLabel("COMPANY")
        company_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase;" % FG_MUTED)
        middle_layout.addWidget(company_label)
        
        company_value = QtWidgets.QLabel("ASPHALT.NETWORK.STUDIO")
        company_value.setStyleSheet("color: %s; font-size: 11px;" % FG_TEXT)
        middle_layout.addWidget(company_value)
        
        date_label = QtWidgets.QLabel("DATE")
        date_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase; margin-top: 5px;" % FG_MUTED)
        middle_layout.addWidget(date_label)
        
        self.footer_date = QtWidgets.QLabel(datetime.now().strftime("%d/%m/%Y"))
        self.footer_date.setStyleSheet("color: %s; font-size: 11px;" % FG_TEXT)
        middle_layout.addWidget(self.footer_date)
        
        time_label = QtWidgets.QLabel("TIME")
        time_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase; margin-top: 5px;" % FG_MUTED)
        middle_layout.addWidget(time_label)
        
        self.footer_time = QtWidgets.QLabel(datetime.now().strftime("%H:%M:%S"))
        self.footer_time.setStyleSheet("color: %s; font-size: 11px;" % FG_TEXT)
        middle_layout.addWidget(self.footer_time)
        
        # Update time every second
        timer = QtCore.QTimer(self)
        timer.timeout.connect(lambda: self.footer_time.setText(datetime.now().strftime("%H:%M:%S")))
        timer.start(1000)
        
        layout.addWidget(middle_section)
        
        # Right: Description
        right_section = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_section)
        right_layout.setSpacing(4)
        
        desc_label = QtWidgets.QLabel("DESCRIPTION")
        desc_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase;" % FG_MUTED)
        right_layout.addWidget(desc_label)
        
        desc_text = QtWidgets.QLabel(
            "ASPHALT is a production-grade network diagnostics platform combining "
            "Wireshark-level packet capture capabilities with an opinionated analytics "
            "and diagnostics layer. It provides full-fidelity packet capture, real-time "
            "protocol decoding, configurable analysis pipelines, and a unified diagnostic UI."
        )
        desc_text.setStyleSheet("color: %s; font-size: 9px; line-height: 1.4;" % FG_MUTED)
        desc_text.setWordWrap(True)
        desc_text.setMaximumWidth(400)
        right_layout.addWidget(desc_text)
        
        layout.addWidget(right_section)
        
        # Far right: Copyright
        copyright_section = QtWidgets.QWidget()
        copyright_layout = QtWidgets.QVBoxLayout(copyright_section)
        copyright_layout.setSpacing(4)
        
        note_label = QtWidgets.QLabel("NOTE")
        note_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase;" % FG_MUTED)
        copyright_layout.addWidget(note_label)
        
        copyright_text = QtWidgets.QLabel(
            "CONTENTS OF THIS APPLICATION ARE THE PROPERTY OF ASPHALT.NETWORK.STUDIO. "
            "NO PART OF THIS SITE MAY BE REPRODUCED WITHOUT CONSENT. "
            "COPYRIGHT © 2024. ALL RIGHTS RESERVED."
        )
        copyright_text.setStyleSheet("color: %s; font-size: 9px; line-height: 1.4;" % FG_MUTED)
        copyright_text.setWordWrap(True)
        copyright_text.setMaximumWidth(300)
        copyright_layout.addWidget(copyright_text)
        
        layout.addWidget(copyright_section)
        layout.addStretch()
        
        return footer

    def _build_footer(self):
        """Build compact footer."""
        footer = QtWidgets.QFrame()
        footer.setObjectName("footer")
        footer.setStyleSheet("""
            QFrame#footer {
                background-color: %s;
                border-top: 1px solid %s;
            }
        """ % (BG_HEADER, BORDER_DARK))

        layout = QtWidgets.QHBoxLayout(footer)
        layout.setContentsMargins(40, 10, 40, 10)
        layout.setSpacing(30)

        left_section = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left_section)
        left_layout.setSpacing(4)

        date_label = QtWidgets.QLabel("DATE")
        date_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase;" % FG_MUTED)
        left_layout.addWidget(date_label)

        self.footer_date = QtWidgets.QLabel(datetime.now().strftime("%d/%m/%Y"))
        self.footer_date.setStyleSheet("color: %s; font-size: 11px;" % FG_TEXT)
        left_layout.addWidget(self.footer_date)

        time_label = QtWidgets.QLabel("TIME")
        time_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase; margin-top: 5px;" % FG_MUTED)
        left_layout.addWidget(time_label)

        self.footer_time = QtWidgets.QLabel(datetime.now().strftime("%H:%M:%S"))
        self.footer_time.setStyleSheet("color: %s; font-size: 11px;" % FG_TEXT)
        left_layout.addWidget(self.footer_time)

        timer = QtCore.QTimer(self)
        timer.timeout.connect(lambda: self.footer_time.setText(datetime.now().strftime("%H:%M:%S")))
        timer.start(1000)

        layout.addWidget(left_section)

        right_section = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_section)
        right_layout.setSpacing(4)

        desc_label = QtWidgets.QLabel("DESCRIPTION")
        desc_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase;" % FG_MUTED)
        right_layout.addWidget(desc_label)

        desc_text = QtWidgets.QLabel(
            "ASPHALT is a production-grade network diagnostics platform combining "
            "Wireshark-level packet capture capabilities with an opinionated analytics "
            "and diagnostics layer. It provides full-fidelity packet capture, real-time "
            "protocol decoding, configurable analysis pipelines, and a unified diagnostic UI."
        )
        desc_text.setStyleSheet("color: %s; font-size: 9px; line-height: 1.4;" % FG_MUTED)
        desc_text.setWordWrap(True)
        desc_text.setMaximumWidth(420)
        right_layout.addWidget(desc_text)

        layout.addWidget(right_section)
        layout.addStretch()

        return footer
    
    def _browse_decode_file(self):
        """Browse for decode file."""
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select PCAP/PCAPNG File", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        if file_path:
            self.decode_file_edit.setText(file_path)
    
    def _browse_analyze_file(self):
        """Browse for analyze file."""
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select PCAP/PCAPNG File", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        if file_path:
            self.analyze_file_edit.setText(file_path)
    
    def _decode_file(self):
        """Decode selected file."""
        file_path = (self.decode_file_edit.text() or "").strip()
        if not file_path:
            QtWidgets.QMessageBox.warning(self, "Error", "Please select a file")
            return

        if hasattr(self, "decode_btn"):
            self.decode_btn.setEnabled(False)
        if hasattr(self, "analyze_btn"):
            self.analyze_btn.setEnabled(False)

        self.status_label.setText(f"Decoding {os.path.basename(file_path)}...")
        thread = threading.Thread(target=self._decode_file_thread, args=(file_path,), daemon=True)
        thread.start()
    
    def _analyze_file(self):
        """Analyze selected file."""
        file_path = (self.analyze_file_edit.text() or "").strip()
        if not file_path:
            QtWidgets.QMessageBox.warning(self, "Error", "Please select a file")
            return
        
        selected_analyzers = []
        for i in range(self.analyzers_list.count()):
            item = self.analyzers_list.item(i)
            if item.checkState() == QtCore.Qt.Checked:
                selected_analyzers.append(item.text())
        
        if not selected_analyzers:
            QtWidgets.QMessageBox.warning(self, "Error", "Please select at least one analyzer")
            return
        
        bucket_ms = _safe_int(self.bucket_ms_edit.text()) or 1000

        if hasattr(self, "analyze_btn"):
            self.analyze_btn.setEnabled(False)
        if hasattr(self, "decode_btn"):
            self.decode_btn.setEnabled(False)

        self.status_label.setText(f"Analyzing {os.path.basename(file_path)}...")
        thread = threading.Thread(
            target=self._analyze_file_thread,
            args=(file_path, selected_analyzers, bucket_ms),
            daemon=True,
        )
        thread.start()

    def _decode_file_thread(self, file_path: str):
        try:
            thresholds = self._get_thresholds()
            packets, analysis = _decode_capture_file(
                file_path,
                analyzer_names=DEFAULT_ANALYZERS,
                bucket_ms=1000,
                chunk_size=200,
                scan_port_threshold=int(thresholds["scan_ports_warn"]),
                rst_ratio_threshold=float(thresholds["abnormal_rst_ratio"]) / 100.0,
            )
            self.latest_packets = packets
            self.latest_analysis = analysis
            self._packet_search_cache = self._build_packet_search_cache(packets)
            self._packet_search_cache_id = id(packets)
            self._packet_search_cache_len = len(packets)
            self.ui_call.emit(self.refresh_all)
            self.ui_call.emit(
                lambda: self.status_label.setText(f"Decoded {len(packets)} packets from file")
            )
        except Exception as exc:
            msg = str(exc)
            self.ui_call.emit(lambda: self.status_label.setText(msg))
            self.ui_call.emit(lambda: QtWidgets.QMessageBox.critical(self, "Decode failed", msg))
        finally:
            if hasattr(self, "decode_btn"):
                self.ui_call.emit(lambda: self.decode_btn.setEnabled(True))
            if hasattr(self, "analyze_btn"):
                self.ui_call.emit(lambda: self.analyze_btn.setEnabled(True))

    def _analyze_file_thread(self, file_path: str, selected_analyzers, bucket_ms: int):
        try:
            thresholds = self._get_thresholds()
            analyzer_names = list(dict.fromkeys(list(selected_analyzers) + list(REQUIRED_UI_ANALYZERS)))
            packets, analysis = _decode_capture_file(
                file_path,
                analyzer_names=analyzer_names,
                bucket_ms=bucket_ms,
                chunk_size=200,
                scan_port_threshold=int(thresholds["scan_ports_warn"]),
                rst_ratio_threshold=float(thresholds["abnormal_rst_ratio"]) / 100.0,
            )
            self.latest_packets = packets
            self.latest_analysis = analysis
            self._packet_search_cache = self._build_packet_search_cache(packets)
            self._packet_search_cache_id = id(packets)
            self._packet_search_cache_len = len(packets)
            self.ui_call.emit(self.refresh_all)
            self.ui_call.emit(
                lambda: self.status_label.setText(
                    f"Analyzed {len(packets)} packets with {len(selected_analyzers)} analyzers"
                )
            )
        except Exception as exc:
            msg = str(exc)
            self.ui_call.emit(lambda: self.status_label.setText(msg))
            self.ui_call.emit(lambda: QtWidgets.QMessageBox.critical(self, "Analyze failed", msg))
        finally:
            if hasattr(self, "analyze_btn"):
                self.ui_call.emit(lambda: self.analyze_btn.setEnabled(True))
            if hasattr(self, "decode_btn"):
                self.ui_call.emit(lambda: self.decode_btn.setEnabled(True))
    
    def _build_title_bar(self):
        bar = QtWidgets.QFrame()
        bar.setObjectName("titlebar")
        bar.setFixedHeight(36)

        layout = QtWidgets.QHBoxLayout(bar)
        layout.setContentsMargins(10, 0, 8, 0)
        layout.setSpacing(8)

        title = QtWidgets.QLabel("Asphalt")
        title.setObjectName("titlebarTitle")
        layout.addWidget(title)
        layout.addStretch(1)

        self.btn_min = QtWidgets.QPushButton("_")
        self.btn_min.setObjectName("titlebarBtn")
        self.btn_min.setFixedSize(36, 24)
        self.btn_min.clicked.connect(self.showMinimized)

        self.btn_max = QtWidgets.QPushButton("[]")
        self.btn_max.setObjectName("titlebarBtn")
        self.btn_max.setFixedSize(36, 24)
        self.btn_max.clicked.connect(self._toggle_max_restore)

        self.btn_close = QtWidgets.QPushButton("X")
        self.btn_close.setObjectName("titlebarClose")
        self.btn_close.setFixedSize(36, 24)
        self.btn_close.clicked.connect(self.close)

        layout.addWidget(self.btn_min)
        layout.addWidget(self.btn_max)
        layout.addWidget(self.btn_close)

        bar.mousePressEvent = self._titlebar_mouse_press
        bar.mouseMoveEvent = self._titlebar_mouse_move
        bar.mouseReleaseEvent = self._titlebar_mouse_release
        bar.mouseDoubleClickEvent = self._titlebar_mouse_double_click
        return bar

    def _toggle_max_restore(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()
        self._update_window_controls()

    def _update_window_controls(self):
        if self.isMaximized():
            self.btn_max.setText("O")
        else:
            self.btn_max.setText("[]")

    def _titlebar_mouse_press(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def _titlebar_mouse_move(self, event):
        if event.buttons() & QtCore.Qt.LeftButton and self._drag_pos is not None:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def _titlebar_mouse_release(self, event):
        self._drag_pos = None
        event.accept()

    def _titlebar_mouse_double_click(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            self._toggle_max_restore()
            event.accept()

    def changeEvent(self, event):
        if event.type() == QtCore.QEvent.WindowStateChange:
            self._update_window_controls()
        super().changeEvent(event)

    def _resolve_scapy_interface(self, requested):
        try:
            from capture.scapy_backend import ScapyBackend
        except Exception:
            return requested
        try:
            backend = ScapyBackend()
            interfaces = backend.list_interfaces()
        except Exception:
            return requested

        if not interfaces:
            return requested

        req = (requested or "").strip()
        if req and req.startswith(r"\Device\NPF_"):
            return req

        # Try match by display name / description / name
        for iface in interfaces:
            name = (iface.get("name") or "").strip()
            display = (iface.get("display_name") or "").strip()
            desc = (iface.get("description") or "").strip()
            if req and (req.lower() == name.lower() or req.lower() == display.lower() or req.lower() == desc.lower()):
                return name
            if req and req.lower() in desc.lower():
                return name

        # Fallback: first interface with IPs (non-loopback)
        for iface in interfaces:
            name = iface.get("name") or ""
            ips = iface.get("ips") or []
            if name.startswith(r"\Device\NPF_") and ips and "127.0.0.1" not in ips:
                return name

        # Final fallback: first NPF interface
        for iface in interfaces:
            name = iface.get("name") or ""
            if name.startswith(r"\Device\NPF_"):
                return name

        return requested

    def _list_scapy_interfaces(self):
        try:
            from capture.scapy_backend import ScapyBackend
        except Exception:
            return []
        try:
            backend = ScapyBackend()
            interfaces = backend.list_interfaces()
        except Exception:
            return []
        names = []
        for iface in interfaces:
            name = iface.get("name") or ""
            ips = iface.get("ips") or []
            if name.startswith(r"\Device\NPF_") and "127.0.0.1" not in ips:
                names.append(name)
        if not names:
            for iface in interfaces:
                name = iface.get("name") or ""
                if name.startswith(r"\Device\NPF_"):
                    names.append(name)
        return names

    def _apply_theme(self):
        palette = self.palette()
        palette.setColor(QtGui.QPalette.Window, QtGui.QColor(BG_MAIN))
        palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(FG_TEXT))
        palette.setColor(QtGui.QPalette.Base, QtGui.QColor(BG_PANEL))
        palette.setColor(QtGui.QPalette.Text, QtGui.QColor(FG_TEXT))
        palette.setColor(QtGui.QPalette.Button, QtGui.QColor(BG_PANEL))
        palette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor(FG_TEXT))
        self.setPalette(palette)
        self.setStyleSheet(
            "QFrame#chrome { background: %s; border: 1px solid %s; }"
            "QFrame#body { background: %s; }"
            "QFrame#titlebar { background: %s; }"
            "QLabel#titlebarTitle { color: %s; font-weight: 600; }"
            "QPushButton#titlebarBtn { background: %s; color: %s; border: 1px solid %s; }"
            "QPushButton#titlebarBtn:hover { background: %s; }"
            "QPushButton#titlebarClose { background: %s; color: %s; border: 1px solid %s; }"
            "QPushButton#titlebarClose:hover { background: %s; }"
            "QPushButton#overviewClearBtn { background: %s; color: %s; border: 1px solid %s; padding: 4px 10px; }"
            "QPushButton#overviewClearBtn:hover { background: %s; }"
            % (
                BG_MAIN,
                BORDER_DARK,
                BG_MAIN,
                TITLEBAR_BG,
                FG_TEXT,
                TITLEBAR_BTN_BG,
                FG_TEXT,
                BORDER_DARK,
                TITLEBAR_BTN_HOVER,
                TITLEBAR_BTN_DANGER,
                FG_TEXT,
                BORDER_DARK,
                TITLEBAR_BTN_DANGER_HOVER,
                ACCENT_BTN_BG,
                ACCENT_BTN_FG,
                BORDER_DARK,
                BG_CARD,
            )
        )

    def _get_global_totals(self, analysis):
        gs = analysis.get("global_results", {}).get("global_stats", {})
        totals = {}
        if isinstance(gs, dict):
            raw_totals = gs.get("totals")
            if isinstance(raw_totals, dict):
                totals.update(raw_totals)
            else:
                # normalize from flat keys
                if "packets_total" in gs:
                    totals["packets"] = gs.get("packets_total")
                if "bytes_captured_total" in gs:
                    totals["bytes_captured"] = gs.get("bytes_captured_total")
                if "bytes_original_total" in gs:
                    totals["bytes_original"] = gs.get("bytes_original_total")
                if "duration_us" in gs:
                    totals["duration_us"] = gs.get("duration_us")

            ip_versions = gs.get("ip_versions") or gs.get("distributions", {}).get("ip_versions")
            if isinstance(ip_versions, dict):
                totals["ipv4_packets"] = ip_versions.get("4") or ip_versions.get(4)
                totals["ipv6_packets"] = ip_versions.get("6") or ip_versions.get(6)

            l4 = gs.get("l4_protocols") or gs.get("distributions", {}).get("l4_protocols")
            if isinstance(l4, dict):
                totals["tcp_packets"] = l4.get("TCP") or l4.get("tcp")
                totals["udp_packets"] = l4.get("UDP") or l4.get("udp")

        # fallback to engine stats
        stats = analysis.get("stats", {})
        if isinstance(stats, dict):
            totals.setdefault("packets", stats.get("packets_total"))
            totals.setdefault("bytes_captured", stats.get("bytes_captured_total"))
            totals.setdefault("bytes_original", stats.get("bytes_original_total"))
            totals.setdefault("duration_us", stats.get("duration_us"))

        return totals

    def _compute_totals_from_packets(self, packets):
        totals = {
            "packets": 0,
            "bytes_captured": 0,
            "bytes_original": 0,
            "ipv4_packets": 0,
            "ipv6_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "duration_us": 0,
        }
        if not packets:
            return totals

        first_ts = None
        last_ts = None
        for pkt in packets:
            if not isinstance(pkt, dict):
                continue
            totals["packets"] += 1
            totals["bytes_captured"] += int(pkt.get("captured_length") or 0)
            totals["bytes_original"] += int(pkt.get("original_length") or 0)
            ip_version = pkt.get("ip_version")
            if ip_version == 4:
                totals["ipv4_packets"] += 1
            elif ip_version == 6:
                totals["ipv6_packets"] += 1
            l4 = (pkt.get("l4_protocol") or "").upper()
            if l4 == "TCP" or pkt.get("ip_protocol") == 6:
                totals["tcp_packets"] += 1
            elif l4 == "UDP" or pkt.get("ip_protocol") == 17:
                totals["udp_packets"] += 1
            ts = pkt.get("timestamp_us")
            if ts is None:
                continue
            try:
                ts_val = int(ts)
            except (TypeError, ValueError):
                continue
            if first_ts is None or ts_val < first_ts:
                first_ts = ts_val
            if last_ts is None or ts_val > last_ts:
                last_ts = ts_val

        if first_ts is not None and last_ts is not None:
            totals["duration_us"] = max(0, last_ts - first_ts)
        return totals

    def _label(self, text):
        label = QtWidgets.QLabel(text)
        label.setStyleSheet("color: %s;" % FG_MUTED)
        return label

    def _value_label(self, text=""):
        label = QtWidgets.QLabel(text)
        label.setStyleSheet("color: %s; font-weight: 600;" % FG_TEXT)
        label.setWordWrap(True)
        return label

    def _stat_block(self, title, value_label, width=None):
        frame = QtWidgets.QFrame()
        frame.setStyleSheet("background-color: %s;" % BG_PANEL)
        if width:
            frame.setFixedWidth(width)
        layout = QtWidgets.QVBoxLayout(frame)
        layout.setContentsMargins(8, 6, 8, 6)
        title_label = QtWidgets.QLabel(title)
        title_label.setStyleSheet("color: %s;" % FG_MUTED)
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        return frame

    def _make_section(self, title):
        box = QtWidgets.QGroupBox(title)
        box.setStyleSheet("""
            QGroupBox {
                color: %s;
                font-weight: 600;
                font-size: 12px;
                text-transform: uppercase;
                border: 1px solid %s;
                margin-top: 6px;
                background-color: %s;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 4px;
                color: %s;
                font-weight: 600;
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
        """ % (FG_TEXT, BORDER_DARK, BG_PANEL, FG_TEXT))
        layout = QtWidgets.QVBoxLayout(box)
        layout.setContentsMargins(10, 10, 10, 10)
        return box, layout

    def _make_scroll_page(self):
        page = QtWidgets.QWidget()
        outer = QtWidgets.QVBoxLayout(page)
        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)
        content = QtWidgets.QWidget()
        scroll.setWidget(content)
        vbox = QtWidgets.QVBoxLayout(content)
        vbox.setContentsMargins(10, 10, 10, 10)
        vbox.setSpacing(10)
        return page, vbox

    def _make_kv_table(self, min_rows=10):
        table = QtWidgets.QTableWidget(0, 2)
        table.setHorizontalHeaderLabels(["Key", "Value"])
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        table.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        table.setMinimumHeight(min_rows * 24 + 32)
        return table

    def _make_table(self, columns, min_rows=10):
        table = QtWidgets.QTableWidget(0, len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        table.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        table.setMinimumHeight(min_rows * 24 + 32)
        return table

    def _set_kv_rows(self, table, rows):
        table.setRowCount(0)
        for row in rows:
            r = table.rowCount()
            table.insertRow(r)
            table.setItem(r, 0, QtWidgets.QTableWidgetItem(str(row[0])))
            table.setItem(r, 1, QtWidgets.QTableWidgetItem(str(row[1])))

    def _set_dynamic_rows(self, table, items, columns=None):
        if columns is None:
            keys = set()
            for item in items:
                if isinstance(item, dict):
                    keys.update(item.keys())
            columns = sorted(keys) if keys else ["value"]
        table.setColumnCount(len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.setRowCount(0)
        for item in items:
            r = table.rowCount()
            table.insertRow(r)
            if isinstance(item, dict):
                for idx, col in enumerate(columns):
                    table.setItem(r, idx, QtWidgets.QTableWidgetItem(str(item.get(col, ""))))
            else:
                table.setItem(r, 0, QtWidgets.QTableWidgetItem(str(item)))

    def _set_json_text(self, editor, obj):
        try:
            editor.setPlainText(json.dumps(obj, indent=2))
        except Exception:
            editor.setPlainText(str(obj))

    def _make_json_panel(self, title):
        box, layout = self._make_section(title)
        editor = QtWidgets.QPlainTextEdit()
        editor.setReadOnly(True)
        editor.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        layout.addWidget(QtWidgets.QLabel("Complete analyzer output for verification and debugging."))
        layout.addWidget(editor)
        return box, editor
    def _build_raw_data_tab(self):
        layout = QtWidgets.QVBoxLayout(self.raw_data_tab)
        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)

        content = QtWidgets.QWidget()
        scroll.setWidget(content)
        vbox = QtWidgets.QVBoxLayout(content)
        vbox.setContentsMargins(10, 10, 10, 10)
        vbox.setSpacing(10)

        self.raw_cards = {}

        # Capture health
        box, box_layout = self._make_section("Capture health and integrity")
        grid = QtWidgets.QGridLayout()
        box_layout.addLayout(grid)
        self.raw_cards["capture_quality"] = self._info_card_var("Capture Quality")
        self.raw_cards["decode_health"] = self._info_card_var("Decode Health")
        self.raw_cards["filtering"] = self._info_card_var("Filtering and Sampling")
        grid.addWidget(self.raw_cards["capture_quality"], 0, 0)
        grid.addWidget(self.raw_cards["decode_health"], 0, 1)
        grid.addWidget(self.raw_cards["filtering"], 0, 2)
        vbox.addWidget(box)

        # Thresholds
        box, box_layout = self._make_section("Thresholds")
        form = QtWidgets.QFormLayout()
        form.setLabelAlignment(QtCore.Qt.AlignLeft)
        form.setFormAlignment(QtCore.Qt.AlignTop)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(6)
        box_layout.addLayout(form)

        self.threshold_inputs = {}
        self.threshold_inputs["drop_warn"] = self._make_threshold_spin(DROP_RATE_WARN, 0, 100, 0.1, 2)
        form.addRow(self._label("Drop rate warn (%)"), self.threshold_inputs["drop_warn"])
        self.threshold_inputs["drop_bad"] = self._make_threshold_spin(DROP_RATE_BAD, 0, 100, 0.1, 2)
        form.addRow(self._label("Drop rate bad (%)"), self.threshold_inputs["drop_bad"])
        self.threshold_inputs["handshake_warn"] = self._make_threshold_spin(HANDSHAKE_WARN_LO, 0, 100, 0.5, 2)
        form.addRow(self._label("Handshake warn >= (%)"), self.threshold_inputs["handshake_warn"])
        self.threshold_inputs["handshake_good"] = self._make_threshold_spin(HANDSHAKE_GOOD_LO, 0, 100, 0.5, 2)
        form.addRow(self._label("Handshake good >= (%)"), self.threshold_inputs["handshake_good"])
        self.threshold_inputs["retrans_warn"] = self._make_threshold_spin(RETX_WARN, 0, 100, 0.1, 2)
        form.addRow(self._label("Retransmission warn (%)"), self.threshold_inputs["retrans_warn"])
        self.threshold_inputs["retrans_bad"] = self._make_threshold_spin(RETX_BAD, 0, 100, 0.1, 2)
        form.addRow(self._label("Retransmission bad (%)"), self.threshold_inputs["retrans_bad"])
        self.threshold_inputs["rst_warn"] = self._make_threshold_spin(RST_WARN, 0, 100, 0.1, 2)
        form.addRow(self._label("RST warn (%)"), self.threshold_inputs["rst_warn"])
        self.threshold_inputs["rst_bad"] = self._make_threshold_spin(RST_BAD, 0, 100, 0.1, 2)
        form.addRow(self._label("RST bad (%)"), self.threshold_inputs["rst_bad"])
        self.threshold_inputs["scan_ports_warn"] = self._make_threshold_int(SCAN_PORTS_WARN, 1, 100000, 1)
        form.addRow(self._label("Scan ports warn (count)"), self.threshold_inputs["scan_ports_warn"])
        self.threshold_inputs["arp_conflict_warn"] = self._make_threshold_int(ARP_CONFLICT_WARN, 0, 100000, 1)
        form.addRow(self._label("ARP conflict warn (count)"), self.threshold_inputs["arp_conflict_warn"])
        self.threshold_inputs["nxdomain_warn"] = QtWidgets.QCheckBox("Enable NXDOMAIN spike warning")
        self.threshold_inputs["nxdomain_warn"].setChecked(bool(NXDOMAIN_SPIKE_WARN))
        form.addRow(self._label("NXDOMAIN spike warn"), self.threshold_inputs["nxdomain_warn"])
        self.threshold_inputs["abnormal_rst_ratio"] = self._make_threshold_spin(ABNORMAL_RST_RATIO_THRESHOLD, 0, 100, 0.5, 2)
        form.addRow(self._label("Abnormal RST ratio threshold (%)"), self.threshold_inputs["abnormal_rst_ratio"])
        vbox.addWidget(box)

        # Traffic overview
        box, box_layout = self._make_section("Traffic overview")
        grid = QtWidgets.QGridLayout()
        box_layout.addLayout(grid)
        self.raw_cards["throughput"] = self._info_card_var("Throughput")
        self.raw_cards["packet_sizes"] = self._info_card_var("Packet Size Stats")
        self.raw_cards["l2l3"] = self._info_card_var("L2/L3 Breakdown")
        grid.addWidget(self.raw_cards["throughput"], 0, 0)
        grid.addWidget(self.raw_cards["packet_sizes"], 0, 1)
        grid.addWidget(self.raw_cards["l2l3"], 0, 2)
        vbox.addWidget(box)

        # Top entities
        box, box_layout = self._make_section("Top entities")
        grid = QtWidgets.QGridLayout()
        box_layout.addLayout(grid)
        self.raw_cards["top_talkers"] = self._info_card_var("Top Talkers")
        self.raw_cards["top_macs"] = self._info_card_var("Top MAC Addresses")
        self.raw_cards["top_ports"] = self._info_card_var("Top Ports and Services")
        grid.addWidget(self.raw_cards["top_talkers"], 0, 0)
        grid.addWidget(self.raw_cards["top_macs"], 0, 1)
        grid.addWidget(self.raw_cards["top_ports"], 0, 2)
        vbox.addWidget(box)

        # Flow analytics
        box, box_layout = self._make_section("Flow analytics")
        grid = QtWidgets.QGridLayout()
        box_layout.addLayout(grid)
        self.raw_cards["flow_summary"] = self._info_card_var("Flow Summary")
        self.raw_cards["flow_heavy"] = self._info_card_var("Heavy Hitters")
        self.raw_cards["flow_states"] = self._info_card_var("Flow States")
        grid.addWidget(self.raw_cards["flow_summary"], 0, 0)
        grid.addWidget(self.raw_cards["flow_heavy"], 0, 1)
        grid.addWidget(self.raw_cards["flow_states"], 0, 2)
        vbox.addWidget(box)

        # TCP health
        box, box_layout = self._make_section("TCP health")
        grid = QtWidgets.QGridLayout()
        box_layout.addLayout(grid)
        self.raw_cards["tcp_handshake"] = self._info_card_var("TCP Handshakes")
        self.raw_cards["tcp_reliability"] = self._info_card_var("TCP Reliability")
        self.raw_cards["tcp_performance"] = self._info_card_var("TCP Performance")
        grid.addWidget(self.raw_cards["tcp_handshake"], 0, 0)
        grid.addWidget(self.raw_cards["tcp_reliability"], 0, 1)
        grid.addWidget(self.raw_cards["tcp_performance"], 0, 2)
        vbox.addWidget(box)

        # Security signals
        box, box_layout = self._make_section("Security signals")
        grid = QtWidgets.QGridLayout()
        box_layout.addLayout(grid)
        self.raw_cards["scan_signals"] = self._info_card_var("Scan Signals")
        self.raw_cards["arp_lan"] = self._info_card_var("ARP / LAN Signals")
        self.raw_cards["dns_anomalies"] = self._info_card_var("DNS Anomalies")
        grid.addWidget(self.raw_cards["scan_signals"], 0, 0)
        grid.addWidget(self.raw_cards["arp_lan"], 0, 1)
        grid.addWidget(self.raw_cards["dns_anomalies"], 0, 2)
        vbox.addWidget(box)

        # Other analyzers (fallback)
        box, box_layout = self._make_section("Other analyzers")
        self.raw_other_table = self._make_kv_table(min_rows=12)
        box_layout.addWidget(self.raw_other_table)
        vbox.addWidget(box)
