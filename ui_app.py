"""
Asphalt local UI app (Tkinter) that runs the full pipeline:
Capture -> Decode -> Display

Run:
  python ui_app.py
"""
import json
import os
import sys
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timezone
try:
    import matplotlib
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    _HAS_MPL = True
except Exception:
    Figure = None
    FigureCanvasTkAgg = None
    _HAS_MPL = False

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from analysis.engine import AnalysisEngine
from analysis.registry import create_analyzer


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


def _extract_json_array(text: str):
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("No JSON array found in output")
    return json.loads(text[start:end + 1])


def run_capture(backend: str, interface: str, duration: int, limit: int):
    env = os.environ.copy()
    env["PYTHONPATH"] = SRC_DIR

    cmd = [
        sys.executable,
        os.path.join(PROJECT_ROOT, "run.py"),
        "capture-decode",
        "--backend",
        backend,
        "--format",
        "json",
    ]

    if interface:
        cmd += ["--interface", interface]
    if duration > 0:
        cmd += ["--duration", str(duration)]
    if limit > 0:
        cmd += ["--limit", str(limit)]

    result = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=PROJECT_ROOT)
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


def run_analysis(packets, bucket_ms: int = 1000, chunk_size: int = 200):
    analyzer_names = [
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
    analyzers = []
    for name in analyzer_names:
        if name == "time_series":
            analyzers.append(create_analyzer(name, bucket_ms=bucket_ms))
        elif name == "packet_chunks":
            analyzers.append(create_analyzer(name, chunk_size=chunk_size))
        else:
            analyzers.append(create_analyzer(name))
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
        dt = datetime.fromtimestamp(ts_us / 1_000_000, tz=timezone.utc)
        return dt.strftime("%H:%M:%S.%f")[:-3] + "Z"
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


class AsphaltApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Asphalt")
        self.geometry("1200x820")
        self.configure(bg=BG_MAIN)
        self.has_mpl = _HAS_MPL

        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        self.style.configure("TCombobox", fieldbackground=BG_PANEL, background=BG_PANEL, foreground=FG_TEXT)
        self.style.configure("Treeview", background=BG_PANEL, fieldbackground=BG_PANEL, foreground=FG_TEXT)
        self.style.configure("Treeview.Heading", background=BG_HEADER, foreground=FG_TEXT)
        self.style.configure("TNotebook", background=BG_PANEL, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=BG_HEADER, foreground=FG_TEXT, padding=(10, 6))
        self.style.map("TNotebook.Tab", background=[("selected", BG_PANEL)], foreground=[("selected", ACCENT)])
        self.style.configure("TScrollbar", background=BG_PANEL, troughcolor=BG_MAIN, arrowcolor=FG_TEXT)

        self.rows = []
        self.table_visible = True
        self.latest_packets = []
        self.latest_analysis = {}

        self._build_ui()

    def _build_ui(self):
        container = tk.Frame(self, bg=BG_MAIN)
        container.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(container, bg=BG_MAIN, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.content = tk.Frame(self.canvas, bg=BG_MAIN)
        self.canvas.create_window((0, 0), window=self.content, anchor="nw")
        self.content.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        header = tk.Frame(self.content, bg=BG_MAIN)
        header.pack(fill="x", padx=20, pady=(20, 10))

        title = tk.Label(header, text="Asphalt Live Decode", fg=FG_TEXT, bg=BG_MAIN,
                         font=("Segoe UI", 20, "bold"))
        title.pack(anchor="w")

        subtitle = tk.Label(header, text="Capture -> Decode -> UI (local)", fg=FG_MUTED, bg=BG_MAIN)
        subtitle.pack(anchor="w")

        controls = tk.Frame(self.content, bg=BG_PANEL)
        controls.pack(fill="x", padx=20, pady=10)

        tk.Label(controls, text="Backend", fg=FG_MUTED, bg=BG_PANEL).grid(row=0, column=0, padx=8, pady=8)
        self.backend_var = tk.StringVar(value="dummy")
        backend = ttk.Combobox(controls, textvariable=self.backend_var, values=["dummy", "scapy"], width=10)
        backend.grid(row=0, column=1, padx=8, pady=8)

        tk.Label(controls, text="Interface", fg=FG_MUTED, bg=BG_PANEL).grid(row=0, column=2, padx=8, pady=8)
        self.interface_var = tk.StringVar(value="dummy0")
        tk.Entry(controls, textvariable=self.interface_var, width=20).grid(row=0, column=3, padx=8, pady=8)

        tk.Label(controls, text="Duration (s)", fg=FG_MUTED, bg=BG_PANEL).grid(row=0, column=4, padx=8, pady=8)
        self.duration_var = tk.StringVar(value="3")
        tk.Entry(controls, textvariable=self.duration_var, width=6).grid(row=0, column=5, padx=8, pady=8)

        tk.Label(controls, text="Limit", fg=FG_MUTED, bg=BG_PANEL).grid(row=0, column=6, padx=8, pady=8)
        self.limit_var = tk.StringVar(value="50")
        tk.Entry(controls, textvariable=self.limit_var, width=6).grid(row=0, column=7, padx=8, pady=8)

        self.start_btn = tk.Button(controls, text="Start", command=self.start_capture, bg=ACCENT_BTN_BG, fg=ACCENT_BTN_FG)
        self.start_btn.grid(row=0, column=8, padx=8, pady=8)

        self.download_btn = tk.Button(controls, text="Download", command=self.download_capture,
                                       bg=BG_PANEL, fg=FG_TEXT, state="disabled")
        self.download_btn.grid(row=0, column=9, padx=8, pady=8)

        tk.Label(controls, text="Filter", fg=FG_MUTED, bg=BG_PANEL).grid(row=1, column=0, padx=8, pady=8)
        self.filter_var = tk.StringVar()
        filter_entry = tk.Entry(controls, textvariable=self.filter_var, width=35)
        filter_entry.grid(row=1, column=1, columnspan=3, padx=8, pady=8, sticky="w")
        filter_entry.bind("<KeyRelease>", lambda e: self.apply_filter())

        self.status_var = tk.StringVar(value="Idle")
        status = tk.Label(controls, textvariable=self.status_var, fg=WARN, bg=BG_PANEL)
        status.grid(row=1, column=4, columnspan=5, padx=8, pady=8, sticky="w")

        stats = tk.Frame(self.content, bg=BG_MAIN)
        stats.pack(fill="x", padx=20, pady=(0, 10))

        self.stat_packets = tk.StringVar(value="0")
        self.stat_ip = tk.StringVar(value="0 / 0")
        self.stat_l4 = tk.StringVar(value="0 / 0")
        self.stat_flows = tk.StringVar(value="0")
        self.analysis_protocol = tk.StringVar(value="-")
        self.analysis_abnormal = tk.StringVar(value="-")
        self.analysis_handshake = tk.StringVar(value="-")
        self.analysis_chunks = tk.StringVar(value="-")
        self.analysis_capture_quality = tk.StringVar(value="-")
        self.analysis_decode_health = tk.StringVar(value="-")
        self.analysis_filtering = tk.StringVar(value="-")
        self.analysis_throughput = tk.StringVar(value="-")
        self.analysis_packet_sizes = tk.StringVar(value="-")
        self.analysis_l2l3 = tk.StringVar(value="-")
        self.analysis_top_talkers = tk.StringVar(value="-")
        self.analysis_top_macs = tk.StringVar(value="-")
        self.analysis_top_ports = tk.StringVar(value="-")
        self.analysis_flow_summary = tk.StringVar(value="-")
        self.analysis_flow_heavy = tk.StringVar(value="-")
        self.analysis_flow_states = tk.StringVar(value="-")
        self.analysis_tcp_handshake = tk.StringVar(value="-")
        self.analysis_tcp_reliability = tk.StringVar(value="-")
        self.analysis_tcp_performance = tk.StringVar(value="-")
        self.analysis_scan_signals = tk.StringVar(value="-")
        self.analysis_arp_lan = tk.StringVar(value="-")
        self.analysis_dns_anomalies = tk.StringVar(value="-")

        self._stat_block(stats, "Packets", self.stat_packets, 0)
        self._stat_block(stats, "IPv4 / IPv6", self.stat_ip, 1)
        self._stat_block(stats, "TCP / UDP", self.stat_l4, 2)
        self._stat_block(stats, "Flows", self.stat_flows, 3)

        analysis = tk.Frame(self.content, bg=BG_MAIN)
        analysis.pack(fill="x", padx=20, pady=(0, 10))

        self._analysis_block(analysis, "Protocol Mix", self.analysis_protocol, 0)
        self._analysis_block(analysis, "Abnormal Activity", self.analysis_abnormal, 1)
        self._analysis_block(analysis, "TCP Handshakes", self.analysis_handshake, 2)
        self._analysis_block(analysis, "Packet Chunks", self.analysis_chunks, 3)

        self._build_raw_data_heuristics_section()
        self._build_technical_information_section()
        self._build_simplified_dashboard_section()
        self._build_packet_table()

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _stat_block(self, parent, label, var, column):
        block = tk.Frame(parent, bg=BG_PANEL, padx=12, pady=8)
        block.grid(row=0, column=column, padx=8, pady=4, sticky="ew")
        tk.Label(block, text=label, fg=FG_MUTED, bg=BG_PANEL).pack(anchor="w")
        tk.Label(block, textvariable=var, fg=FG_TEXT, bg=BG_PANEL, font=("Segoe UI", 12, "bold")).pack(anchor="w")

    def _analysis_block(self, parent, label, var, column):
        block = tk.Frame(parent, bg=BG_PANEL, padx=12, pady=8)
        block.grid(row=0, column=column, padx=8, pady=4, sticky="ew")
        tk.Label(block, text=label, fg=FG_MUTED, bg=BG_PANEL).pack(anchor="w")
        tk.Label(block, textvariable=var, fg=FG_TEXT, bg=BG_PANEL, font=("Segoe UI", 10, "bold"),
                 justify="left", wraplength=220).pack(anchor="w")

    def _collapsible_section(self, parent, title, summary):
        frame = tk.Frame(parent, bg=BG_PANEL, bd=1, relief="flat")
        header = tk.Frame(frame, bg=BG_HEADER)
        header.pack(fill="x")

        title_label = tk.Label(header, text=title, fg=ACCENT, bg=BG_HEADER, font=("Segoe UI", 10, "bold"))
        title_label.pack(side="left", padx=10, pady=6)

        summary_label = tk.Label(header, text=summary, fg=FG_MUTED, bg=BG_HEADER)
        summary_label.pack(side="left", padx=10)

        toggle = tk.Label(header, text="+", fg=FG_TEXT, bg=BG_HEADER, font=("Segoe UI", 12, "bold"))
        toggle.pack(side="right", padx=10)

        body = tk.Frame(frame, bg=BG_PANEL)
        body.pack(fill="x", padx=10, pady=10)

        def _toggle():
            if body.winfo_viewable():
                body.pack_forget()
                toggle.config(text="+")
            else:
                body.pack(fill="x", padx=10, pady=10)
                toggle.config(text="-")

        header.bind("<Button-1>", lambda e: _toggle())
        title_label.bind("<Button-1>", lambda e: _toggle())
        summary_label.bind("<Button-1>", lambda e: _toggle())
        toggle.bind("<Button-1>", lambda e: _toggle())

        return frame, body

    def _info_card(self, parent, title, lines, column, row):
        card = tk.Frame(parent, bg=BG_CARD, padx=10, pady=8, bd=1, relief="flat")
        card.grid(row=row, column=column, padx=8, pady=6, sticky="nsew")
        tk.Label(card, text=title, fg=FG_MUTED, bg=BG_CARD, font=("Segoe UI", 9, "bold")).pack(anchor="w")
        for line in lines:
            tk.Label(card, text=line, fg=FG_TEXT, bg=BG_CARD, font=("Segoe UI", 9)).pack(anchor="w")
        return card

    def _info_card_var(self, parent, title, var, column, row):
        card = tk.Frame(parent, bg=BG_CARD, padx=10, pady=8, bd=1, relief="flat")
        card.grid(row=row, column=column, padx=8, pady=6, sticky="nsew")
        tk.Label(card, text=title, fg=FG_MUTED, bg=BG_CARD, font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(card, textvariable=var, fg=FG_TEXT, bg=BG_CARD,
                 font=("Segoe UI", 9), justify="left", wraplength=320).pack(anchor="w")
        return card

    def _build_raw_data_heuristics_section(self):
        section = tk.Frame(self.content, bg=BG_MAIN)
        section.pack(fill="x", padx=20, pady=10)

        frame, body = self._collapsible_section(
            section,
            "Raw Data Heuristics",
            "Capture Health Â· Traffic Overview Â· Entities Â· Flows Â· TCP Â· Security"
        )
        frame.pack(fill="x", pady=6)

        container = tk.Frame(body, bg=BG_PANEL)
        container.pack(fill="x")
        self._build_capture_health_section(container)
        self._build_extra_sections(container)

    def _build_capture_health_section(self, parent):
        section = tk.Frame(parent, bg=BG_MAIN)
        section.pack(fill="x", pady=6)

        frame, body = self._collapsible_section(
            section,
            "Capture health and integrity",
            "Capture Quality · Decode Health · Filtering and Sampling"
        )
        frame.pack(fill="x", pady=6)

        grid = tk.Frame(body, bg=BG_PANEL)
        grid.pack(fill="x")

        self._info_card_var(grid, "Capture Quality", self.analysis_capture_quality, 0, 0)
        self._info_card_var(grid, "Decode Health", self.analysis_decode_health, 1, 0)
        self._info_card_var(grid, "Filtering and Sampling", self.analysis_filtering, 2, 0)

        for c in range(3):
            grid.grid_columnconfigure(c, weight=1)

    def _build_extra_sections(self, parent):
        sections = tk.Frame(parent, bg=BG_MAIN)
        sections.pack(fill="x", pady=6)

        frame, body = self._collapsible_section(
            sections,
            "Traffic overview",
            "Throughput · Packet Size Stats · L2/L3 Breakdown"
        )
        frame.pack(fill="x", pady=6)
        grid = tk.Frame(body, bg=BG_PANEL)
        grid.pack(fill="x")
        self._info_card_var(grid, "Throughput", self.analysis_throughput, 0, 0)
        self._info_card_var(grid, "Packet Size Stats", self.analysis_packet_sizes, 1, 0)
        self._info_card_var(grid, "L2/L3 Breakdown", self.analysis_l2l3, 2, 0)
        for c in range(3):
            grid.grid_columnconfigure(c, weight=1)

        frame, body = self._collapsible_section(
            sections,
            "Top entities",
            "Top Talkers · Top MAC Addresses · Top Ports and Services"
        )
        frame.pack(fill="x", pady=6)
        grid = tk.Frame(body, bg=BG_PANEL)
        grid.pack(fill="x")
        self._info_card_var(grid, "Top Talkers", self.analysis_top_talkers, 0, 0)
        self._info_card_var(grid, "Top MAC Addresses", self.analysis_top_macs, 1, 0)
        self._info_card_var(grid, "Top Ports and Services", self.analysis_top_ports, 2, 0)
        for c in range(3):
            grid.grid_columnconfigure(c, weight=1)

        frame, body = self._collapsible_section(
            sections,
            "Flow analytics",
            "Summary · Heavy hitters · Flow states"
        )
        frame.pack(fill="x", pady=6)
        grid = tk.Frame(body, bg=BG_PANEL)
        grid.pack(fill="x")
        self._info_card_var(grid, "Flow Summary", self.analysis_flow_summary, 0, 0)
        self._info_card_var(grid, "Heavy Hitters", self.analysis_flow_heavy, 1, 0)
        self._info_card_var(grid, "Flow States", self.analysis_flow_states, 2, 0)
        for c in range(3):
            grid.grid_columnconfigure(c, weight=1)

        frame, body = self._collapsible_section(
            sections,
            "TCP health and behavior",
            "Handshake Detail · Reliability Indicators · TCP Performance Signals"
        )
        frame.pack(fill="x", pady=6)
        grid = tk.Frame(body, bg=BG_PANEL)
        grid.pack(fill="x")
        self._info_card_var(grid, "Handshake Detail", self.analysis_tcp_handshake, 0, 0)
        self._info_card_var(grid, "Reliability Indicators", self.analysis_tcp_reliability, 1, 0)
        self._info_card_var(grid, "TCP Performance Signals", self.analysis_tcp_performance, 2, 0)
        for c in range(3):
            grid.grid_columnconfigure(c, weight=1)

        frame, body = self._collapsible_section(
            sections,
            "Security and anomaly signals",
            "Scan-like Behavior · DNS Anomalies · ARP and LAN Attacks"
        )
        frame.pack(fill="x", pady=6)
        grid = tk.Frame(body, bg=BG_PANEL)
        grid.pack(fill="x")
        self._info_card_var(grid, "Scan-like Behavior", self.analysis_scan_signals, 0, 0)
        self._info_card_var(grid, "DNS Anomalies", self.analysis_dns_anomalies, 1, 0)
        self._info_card_var(grid, "ARP and LAN Attacks", self.analysis_arp_lan, 2, 0)
        for c in range(3):
            grid.grid_columnconfigure(c, weight=1)

    def _build_technical_information_section(self):
        section = tk.Frame(self.content, bg=BG_MAIN)
        section.pack(fill="x", padx=20, pady=10)

        frame, body = self._collapsible_section(
            section,
            "Technical Information",
            "Detailed analyzer outputs"
        )
        frame.pack(fill="x", pady=6)

        self.tech_notebook = ttk.Notebook(body)
        self.tech_notebook.pack(fill="both", expand=True)

        tab_names = [
            "Capture Quality",
            "Traffic Overview",
            "Protocol Mix",
            "Flow Analytics",
            "TCP Health",
            "Top Entities",
            "Security Signals",
            "Time Series & Chunking",
        ]
        self.tech_tabs = {}
        self.tech_tab_canvases = {}
        for name in tab_names:
            tab = tk.Frame(self.tech_notebook, bg=BG_PANEL)
            self.tech_notebook.add(tab, text=name)

            canvas = tk.Canvas(tab, bg=BG_PANEL, highlightthickness=0)
            scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
            canvas.configure(yscrollcommand=scrollbar.set)
            scrollbar.pack(side="right", fill="y")
            canvas.pack(side="left", fill="both", expand=True)

            inner = tk.Frame(canvas, bg=BG_PANEL)
            window_id = canvas.create_window((0, 0), window=inner, anchor="nw")

            def _on_inner_configure(event, c=canvas):
                c.configure(scrollregion=c.bbox("all"))

            def _on_canvas_configure(event, c=canvas, w=window_id):
                c.itemconfigure(w, width=event.width)

            inner.bind("<Configure>", _on_inner_configure)
            canvas.bind("<Configure>", _on_canvas_configure)

            self.tech_tabs[name] = inner
            self.tech_tab_canvases[name] = canvas

        self._build_ti_capture_quality()
        self._build_ti_traffic_overview()
        self._build_ti_protocol_mix()
        self._build_ti_flow_analytics()
        self._build_ti_tcp_health()
        self._build_ti_top_entities()
        self._build_ti_security_signals()
        self._build_ti_time_series_chunking()

    def _build_simplified_dashboard_section(self):
        section = tk.Frame(self.content, bg=BG_MAIN)
        section.pack(fill="x", padx=20, pady=10)

        frame, body = self._collapsible_section(
            section,
            "Simplified Dashboard",
            "Executive summary · Key charts · Diagnostics"
        )
        frame.pack(fill="x", pady=6)

        kpi_frame = ttk.LabelFrame(body, text="Executive Summary")
        kpi_frame.pack(fill="x", padx=8, pady=6)
        kpi_grid = tk.Frame(kpi_frame, bg=BG_PANEL)
        kpi_grid.pack(fill="x", pady=(0, 10))
        self.sd_kpi_vars = {}
        self.sd_kpi_sev = {}
        kpi_titles = [
            "Total Packets",
            "Total Bytes",
            "Duration",
            "Peak BPS",
            "TCP Handshake Completion",
            "TCP Retransmission Rate",
            "Drop Rate",
            "NXDOMAIN Spike",
        ]
        for idx, title in enumerate(kpi_titles):
            row = idx // 4
            col = idx % 4
            value_var = tk.StringVar(value="n/a")
            sev_var = tk.StringVar(value="INFO")
            self.sd_kpi_vars[title] = value_var
            self.sd_kpi_sev[title] = sev_var
            self._kpi_card(kpi_grid, title, value_var, sev_var, col=col, row=row)
        for c in range(4):
            kpi_grid.grid_columnconfigure(c, weight=1)

        charts_frame = ttk.LabelFrame(body, text="Key Charts")
        charts_frame.pack(fill="x", padx=8, pady=6)
        self.sd_charts_notebook = ttk.Notebook(charts_frame)
        self.sd_charts_notebook.pack(fill="both", expand=True)
        chart_tabs = {}
        for name in ["Traffic", "Protocols", "Talkers", "TCP", "Packet Sizes"]:
            tab = tk.Frame(self.sd_charts_notebook, bg=BG_PANEL)
            self.sd_charts_notebook.add(tab, text=name)
            chart_tabs[name] = tab
        self.sd_chart_tabs = chart_tabs

        self.sd_tcp_chart_frame = tk.Frame(self.sd_chart_tabs["TCP"], bg=BG_PANEL)
        self.sd_tcp_chart_frame.pack(fill="both", expand=True)
        self.sd_tcp_interpret = tk.StringVar(value="")
        tk.Label(self.sd_chart_tabs["TCP"], textvariable=self.sd_tcp_interpret, fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9), justify="left").pack(anchor="w", padx=8, pady=(4, 0))

        diag_frame = ttk.LabelFrame(body, text="Diagnostics")
        diag_frame.pack(fill="x", padx=8, pady=6)
        self.sd_diag_container = tk.Frame(diag_frame, bg=BG_PANEL)
        self.sd_diag_container.pack(fill="x", padx=8, pady=6)

    def _make_kpi_grid(self, parent, items):
        grid = tk.Frame(parent, bg=BG_PANEL)
        grid.pack(fill="x", pady=(0, 10))
        vars_map = {}
        for idx, (label, default_value) in enumerate(items):
            row = idx // 3
            col = idx % 3
            card = tk.Frame(grid, bg=BG_CARD, padx=10, pady=8, bd=1, relief="flat")
            card.grid(row=row, column=col, padx=8, pady=6, sticky="nsew")
            tk.Label(card, text=label, fg=FG_MUTED, bg=BG_CARD, font=("Segoe UI", 9, "bold")).pack(anchor="w")
            var = tk.StringVar(value=default_value)
            tk.Label(card, textvariable=var, fg=FG_TEXT, bg=BG_CARD,
                     font=("Segoe UI", 9), justify="left", wraplength=320).pack(anchor="w")
            vars_map[label] = var
        for c in range(3):
            grid.grid_columnconfigure(c, weight=1)
        return vars_map

    def _make_kpi_grid_cols(self, parent, items, cols):
        grid = tk.Frame(parent, bg=BG_PANEL)
        grid.pack(fill="x", pady=(0, 10))
        vars_map = {}
        for idx, (label, default_value) in enumerate(items):
            row = idx // cols
            col = idx % cols
            card = tk.Frame(grid, bg=BG_CARD, padx=10, pady=8, bd=1, relief="flat")
            card.grid(row=row, column=col, padx=8, pady=6, sticky="nsew")
            tk.Label(card, text=label, fg=FG_MUTED, bg=BG_CARD, font=("Segoe UI", 9, "bold")).pack(anchor="w")
            var = tk.StringVar(value=default_value)
            tk.Label(card, textvariable=var, fg=FG_TEXT, bg=BG_CARD,
                     font=("Segoe UI", 9), justify="left", wraplength=320).pack(anchor="w")
            vars_map[label] = var
        for c in range(cols):
            grid.grid_columnconfigure(c, weight=1)
        return vars_map

    def _kpi_card(self, parent, title, value_var, severity_var, sub_var=None, col=0, row=0):
        card = tk.Frame(parent, bg=BG_CARD, padx=10, pady=8, bd=1, relief="flat")
        card.grid(row=row, column=col, padx=8, pady=6, sticky="nsew")
        header = tk.Frame(card, bg=BG_CARD)
        header.pack(fill="x")
        tk.Label(header, text=title, fg=FG_MUTED, bg=BG_CARD,
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        badge = tk.Label(header, textvariable=severity_var, fg=BG_MAIN, bg=BG_CARD,
                         font=("Segoe UI", 8, "bold"), padx=6, pady=1)
        badge.pack(side="right")

        def _update_badge(*_):
            sev = (severity_var.get() or "INFO").upper()
            if sev == "GOOD":
                badge.configure(bg=GOOD, fg=BG_MAIN)
            elif sev == "WARN":
                badge.configure(bg=WARN_BADGE, fg=BG_MAIN)
            elif sev == "BAD":
                badge.configure(bg=BAD, fg=BG_MAIN)
            else:
                badge.configure(bg=FG_MUTED, fg=BG_MAIN)

        severity_var.trace_add("write", _update_badge)
        _update_badge()

        tk.Label(card, textvariable=value_var, fg=FG_TEXT, bg=BG_CARD,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(4, 0))
        if sub_var is not None:
            tk.Label(card, textvariable=sub_var, fg=FG_MUTED, bg=BG_CARD,
                     font=("Segoe UI", 9)).pack(anchor="w")
        return card

    def _sev_from_pct(self, value, good_lt, warn_lt, bad_ge):
        if value is None:
            return "INFO"
        try:
            v = float(value)
        except (TypeError, ValueError):
            return "INFO"
        if v >= bad_ge:
            return "BAD"
        if v >= warn_lt:
            return "WARN"
        if v < good_lt:
            return "GOOD"
        return "INFO"

    def _sev_from_bool(self, flag):
        if flag is None:
            return "INFO"
        return "WARN" if bool(flag) else "GOOD"

    def _mpl_clear_frame(self, frame):
        for child in frame.winfo_children():
            child.destroy()

    def _mpl_pie(self, frame, labels, values, title):
        self._mpl_clear_frame(frame)
        if not self.has_mpl:
            self._render_table(frame, ["label", "value"], list(zip(labels, values)))
            return
        fig = Figure(figsize=(5, 3), dpi=100)
        ax = fig.add_subplot(111)
        ax.pie(values, labels=labels, autopct="%1.0f%%" if sum(values) else None)
        ax.set_title(title)
        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def _mpl_bar(self, frame, labels, values, title, xrot=0):
        self._mpl_clear_frame(frame)
        if not self.has_mpl:
            self._render_table(frame, ["label", "value"], list(zip(labels, values)))
            return
        fig = Figure(figsize=(6, 3), dpi=100)
        ax = fig.add_subplot(111)
        ax.bar(labels, values)
        ax.set_title(title)
        ax.tick_params(axis="x", rotation=xrot)
        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def _mpl_line(self, frame, x, series_list, title, xlabel="", ylabel=""):
        self._mpl_clear_frame(frame)
        if not self.has_mpl:
            cols = ["x"] + [series["label"] for series in series_list]
            rows = []
            for i, xv in enumerate(x):
                row = [xv]
                for series in series_list:
                    values = series.get("values", [])
                    row.append(values[i] if i < len(values) else None)
                rows.append(tuple(row))
            self._render_table(frame, cols, rows)
            return
        fig = Figure(figsize=(6, 3), dpi=100)
        ax = fig.add_subplot(111)
        for series in series_list:
            ax.plot(x, series.get("values", []), label=series.get("label"))
        ax.set_title(title)
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        ax.legend()
        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def _mpl_hist(self, frame, bucket_labels, counts, title):
        self._mpl_clear_frame(frame)
        if not self.has_mpl:
            self._render_table(frame, ["bucket", "count"], list(zip(bucket_labels, counts)))
            return
        fig = Figure(figsize=(6, 3), dpi=100)
        ax = fig.add_subplot(111)
        ax.bar(bucket_labels, counts)
        ax.set_title(title)
        ax.tick_params(axis="x", rotation=30)
        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def _render_table(self, frame, columns, rows):
        container = tk.Frame(frame, bg=BG_PANEL)
        container.pack(fill="both", expand=True)
        tree = ttk.Treeview(container, columns=columns, show="headings", height=6)
        yscroll = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=yscroll.set)
        tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=120, anchor="w")
        self._tree_set_rows(tree, rows)

    def _make_tree(self, parent, columns, headings=None):
        container = tk.Frame(parent, bg=BG_PANEL)
        container.pack(fill="both", expand=True, pady=(0, 10))
        tree = ttk.Treeview(container, columns=columns, show="headings", height=6)
        yscroll = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=yscroll.set)
        tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        if headings is None:
            headings = columns
        for col, heading in zip(columns, headings):
            tree.heading(col, text=heading)
            tree.column(col, width=120, anchor="w")
        return tree

    def _tree_set_rows(self, tree, rows):
        tree.delete(*tree.get_children())
        for row in rows:
            tree.insert("", "end", values=row)

    def _make_json_text(self, parent):
        container = tk.Frame(parent, bg=BG_PANEL)
        container.pack(fill="both", expand=True)
        text = tk.Text(container, height=8, bg=BG_CARD, fg=FG_TEXT, insertbackground=FG_TEXT,
                       wrap="none", state="disabled", font=("Consolas", 9))
        yscroll = ttk.Scrollbar(container, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=yscroll.set)
        text.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        return text

    def _set_json_text(self, text_widget, obj):
        try:
            payload = json.dumps(obj, indent=2)
        except (TypeError, ValueError):
            payload = "{}"
        cap = 200_000
        if len(payload) > cap:
            payload = payload[:cap] + "\n... (truncated)"
        text_widget.configure(state="normal")
        text_widget.delete("1.0", "end")
        text_widget.insert("1.0", payload)
        text_widget.configure(state="disabled")

    def _build_json_panel(self, parent):
        frame = tk.Frame(parent, bg=BG_PANEL)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text="Full Analyzer JSON", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        return self._make_json_text(frame)

    def _build_ti_capture_quality(self):
        tab = self.tech_tabs["Capture Quality"]
        session_frame = ttk.LabelFrame(tab, text="Session")
        session_frame.pack(fill="x", padx=8, pady=6)
        kpi_vars_session = self._make_kpi_grid(session_frame, [
            ("Capture Start", "n/a"),
            ("Capture End", "n/a"),
            ("Duration", "n/a"),
            ("Link Types", "n/a"),
            ("Snaplen", "n/a"),
            ("Promiscuous", "n/a"),
        ])

        drops_frame = ttk.LabelFrame(tab, text="Drops")
        drops_frame.pack(fill="x", padx=8, pady=6)
        kpi_vars_drops = self._make_kpi_grid(drops_frame, [
            ("Dropped Packets", "n/a"),
            ("Drop Rate", "n/a"),
        ])

        decode_frame = ttk.LabelFrame(tab, text="Decode Health")
        decode_frame.pack(fill="x", padx=8, pady=6)
        kpi_vars_decode = self._make_kpi_grid(decode_frame, [
            ("Decode Success", "n/a"),
            ("Malformed Packets", "n/a"),
            ("Truncated Packets", "n/a"),
            ("Unknown L3", "n/a"),
            ("Unknown L4", "n/a"),
            ("Unsupported Link Types", "n/a"),
        ])
        tk.Label(decode_frame, text="Decode Counters", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_decode = self._make_tree(decode_frame, ("key", "value"), ("Key", "Value"))

        filtering_frame = ttk.LabelFrame(tab, text="Filtering / Sampling")
        filtering_frame.pack(fill="x", padx=8, pady=6)
        tk.Label(filtering_frame, text="Fields", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_filtering = self._make_tree(filtering_frame, ("key", "value"), ("Key", "Value"))

        json_text = self._build_json_panel(tab)

        self.ti_capture_quality = {
            "kpi_vars_session": kpi_vars_session,
            "kpi_vars_drops": kpi_vars_drops,
            "kpi_vars_decode": kpi_vars_decode,
            "tree_decode": tree_decode,
            "tree_filtering": tree_filtering,
            "json_text": json_text,
        }

    def _build_ti_traffic_overview(self):
        tab = self.tech_tabs["Traffic Overview"]
        throughput_frame = ttk.LabelFrame(tab, text="Throughput and Peaks")
        throughput_frame.pack(fill="x", padx=8, pady=6)
        kpi_vars_throughput = self._make_kpi_grid(throughput_frame, [
            ("BPS Now", "n/a"),
            ("BPS Avg", "n/a"),
            ("PPS Now", "n/a"),
            ("PPS Avg", "n/a"),
            ("Peak BPS", "n/a"),
            ("Peak PPS", "n/a"),
            ("Peak BPS Time", "n/a"),
            ("Peak PPS Time", "n/a"),
        ])
        tk.Label(throughput_frame, text="All Fields", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_throughput = self._make_tree(throughput_frame, ("key", "value"), ("Key", "Value"))

        size_frame = ttk.LabelFrame(tab, text="Packet Size Statistics")
        size_frame.pack(fill="x", padx=8, pady=6)
        kpi_vars_sizes = self._make_kpi_grid(size_frame, [
            ("Captured Len Min", "n/a"),
            ("Captured Len Median", "n/a"),
            ("Captured Len P95", "n/a"),
            ("Captured Len Max", "n/a"),
            ("Original Len Min", "n/a"),
            ("Original Len Median", "n/a"),
            ("Original Len P95", "n/a"),
            ("Original Len Max", "n/a"),
            ("IPv4 Fragments", "n/a"),
            ("IPv6 Fragments", "n/a"),
        ])
        tk.Label(size_frame, text="Histogram", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_histogram = self._make_tree(size_frame, ("bucket", "count"), ("Bucket", "Count"))

        l2l3_frame = ttk.LabelFrame(tab, text="L2/L3 Breakdown")
        l2l3_frame.pack(fill="x", padx=8, pady=6)
        tree_l2l3 = self._make_tree(l2l3_frame, ("key", "count"), ("Key", "Count"))

        totals_frame = ttk.LabelFrame(tab, text="Global Totals (context)")
        totals_frame.pack(fill="x", padx=8, pady=6)
        kpi_vars_totals = self._make_kpi_grid(totals_frame, [
            ("Packets", "n/a"),
            ("Bytes", "n/a"),
            ("Duration", "n/a"),
        ])

        raw_frame = ttk.LabelFrame(tab, text="Raw JSON")
        raw_frame.pack(fill="both", expand=True, padx=8, pady=6)
        raw_notebook = ttk.Notebook(raw_frame)
        raw_notebook.pack(fill="both", expand=True)
        raw_tabs = {}
        json_texts = {}
        for key, label in [
            ("throughput_peaks", "Throughput Peaks"),
            ("packet_size_stats", "Packet Size Stats"),
            ("l2_l3_breakdown", "L2/L3 Breakdown"),
        ]:
            raw_tab = tk.Frame(raw_notebook, bg=BG_PANEL)
            raw_notebook.add(raw_tab, text=label)
            raw_tabs[key] = raw_tab
            json_texts[key] = self._make_json_text(raw_tab)

        self.ti_traffic_overview = {
            "kpi_vars_throughput": kpi_vars_throughput,
            "tree_throughput": tree_throughput,
            "kpi_vars_sizes": kpi_vars_sizes,
            "tree_histogram": tree_histogram,
            "tree_l2l3": tree_l2l3,
            "kpi_vars_totals": kpi_vars_totals,
            "json_texts": json_texts,
        }

    def _build_ti_protocol_mix(self):
        tab = self.tech_tabs["Protocol Mix"]
        totals_frame = ttk.LabelFrame(tab, text="Totals")
        totals_frame.pack(fill="x", padx=8, pady=6)
        kpi_vars_totals = self._make_kpi_grid(totals_frame, [
            ("Packets", "n/a"),
            ("Bytes Captured", "n/a"),
            ("Bytes Original", "n/a"),
            ("Duration", "n/a"),
        ])

        mix_frame = ttk.LabelFrame(tab, text="Protocol Mix")
        mix_frame.pack(fill="x", padx=8, pady=6)
        tk.Label(mix_frame, text="Protocol Counts", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_counts = self._make_tree(mix_frame, ("protocol", "count"), ("Protocol", "Count"))
        tk.Label(mix_frame, text="Protocol Percentages", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_percentages = self._make_tree(mix_frame, ("protocol", "percent"), ("Protocol", "Percent"))
        tk.Label(mix_frame, text="Additional Fields", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_misc = self._make_tree(mix_frame, ("key", "value"), ("Key", "Value"))

        dist_frame = ttk.LabelFrame(tab, text="Global Distributions")
        dist_frame.pack(fill="x", padx=8, pady=6)
        dist_trees = {}
        for key, label in [
            ("ip_versions", "IP Versions"),
            ("l4_protocols", "L4 Protocols"),
            ("tcp_flags", "TCP Flags"),
            ("decode_quality_flags", "Decode Quality Flags"),
        ]:
            tk.Label(dist_frame, text=label, fg=FG_MUTED, bg=BG_PANEL,
                     font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
            dist_trees[key] = self._make_tree(dist_frame, ("key", "count", "percent"),
                                              ("Key", "Count", "Percent"))

        raw_frame = ttk.LabelFrame(tab, text="Raw JSON")
        raw_frame.pack(fill="both", expand=True, padx=8, pady=6)
        raw_notebook = ttk.Notebook(raw_frame)
        raw_notebook.pack(fill="both", expand=True)
        json_texts = {}
        for key, label in [
            ("protocol_mix", "Protocol Mix"),
            ("global_stats", "Global Stats"),
        ]:
            raw_tab = tk.Frame(raw_notebook, bg=BG_PANEL)
            raw_notebook.add(raw_tab, text=label)
            json_texts[key] = self._make_json_text(raw_tab)

        self.ti_protocol_mix = {
            "kpi_vars_totals": kpi_vars_totals,
            "tree_counts": tree_counts,
            "tree_percentages": tree_percentages,
            "tree_misc": tree_misc,
            "dist_trees": dist_trees,
            "json_texts": json_texts,
        }

    def _build_ti_flow_analytics(self):
        tab = self.tech_tabs["Flow Analytics"]
        summary_frame = ttk.LabelFrame(tab, text="Summary KPIs")
        summary_frame.pack(fill="x", padx=8, pady=6)
        kpi_vars_summary = self._make_kpi_grid(summary_frame, [
            ("Total Flows", "n/a"),
            ("New Flows/sec", "n/a"),
            ("Duration Median", "n/a"),
            ("Duration P95", "n/a"),
            ("Bytes/Flow Avg", "n/a"),
            ("Bytes/Flow P95", "n/a"),
        ])

        heavy_frame = ttk.LabelFrame(tab, text="Heavy Hitters")
        heavy_frame.pack(fill="x", padx=8, pady=6)
        tk.Label(heavy_frame, text="Top by Bytes", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        top_bytes_container = tk.Frame(heavy_frame, bg=BG_PANEL)
        top_bytes_container.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(heavy_frame, text="Top by Packets", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        top_packets_container = tk.Frame(heavy_frame, bg=BG_PANEL)
        top_packets_container.pack(fill="x", padx=8, pady=(0, 4))

        states_frame = ttk.LabelFrame(tab, text="Flow States")
        states_frame.pack(fill="x", padx=8, pady=6)
        tree_states = self._make_tree(states_frame, ("key", "value"), ("Key", "Value"))

        summary_raw_frame = ttk.LabelFrame(tab, text="Flow Summary (raw table aggregates)")
        summary_raw_frame.pack(fill="x", padx=8, pady=6)
        flow_summary_container = tk.Frame(summary_raw_frame, bg=BG_PANEL)
        flow_summary_container.pack(fill="x")

        raw_frame = ttk.LabelFrame(tab, text="Raw JSON")
        raw_frame.pack(fill="both", expand=True, padx=8, pady=6)
        raw_notebook = ttk.Notebook(raw_frame)
        raw_notebook.pack(fill="both", expand=True)
        json_texts = {}
        for key, label in [
            ("flow_analytics", "Flow Analytics"),
            ("flow_summary", "Flow Summary"),
        ]:
            raw_tab = tk.Frame(raw_notebook, bg=BG_PANEL)
            raw_notebook.add(raw_tab, text=label)
            json_texts[key] = self._make_json_text(raw_tab)

        self.ti_flow_analytics = {
            "kpi_vars_summary": kpi_vars_summary,
            "heavy_top_bytes_container": top_bytes_container,
            "heavy_top_packets_container": top_packets_container,
            "tree_states": tree_states,
            "flow_summary_container": flow_summary_container,
            "json_texts": json_texts,
            "heavy_top_bytes_tree": None,
            "heavy_top_packets_tree": None,
            "flow_summary_tree": None,
        }

    def _build_ti_tcp_health(self):
        tab = self.tech_tabs["TCP Health"]
        handshake_frame = ttk.LabelFrame(tab, text="Handshakes")
        handshake_frame.pack(fill="x", padx=8, pady=6)
        kpi_vars_handshakes = self._make_kpi_grid(handshake_frame, [
            ("Handshakes Total", "n/a"),
            ("Handshakes Complete", "n/a"),
            ("Handshakes Incomplete", "n/a"),
            ("Completion Rate", "n/a"),
            ("RTT Median (ms)", "n/a"),
            ("RTT P95 (ms)", "n/a"),
        ])
        tk.Label(handshake_frame, text="Additional Fields", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_handshake_extra = self._make_tree(handshake_frame, ("key", "value"), ("Key", "Value"))

        reliability_frame = ttk.LabelFrame(tab, text="Reliability")
        reliability_frame.pack(fill="x", padx=8, pady=6)
        kpi_vars_reliability = self._make_kpi_grid(reliability_frame, [
            ("Retransmissions", "n/a"),
            ("Retransmission Rate", "n/a"),
            ("Out of Order", "n/a"),
            ("Out of Order Rate", "n/a"),
            ("Dup ACKs", "n/a"),
            ("Dup ACK Rate", "n/a"),
            ("RST Packets", "n/a"),
            ("RST Rate", "n/a"),
        ])
        tk.Label(reliability_frame, text="Additional Fields", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_reliability_extra = self._make_tree(reliability_frame, ("key", "value"), ("Key", "Value"))

        performance_frame = ttk.LabelFrame(tab, text="Performance")
        performance_frame.pack(fill="x", padx=8, pady=6)
        kpi_vars_performance = self._make_kpi_grid(performance_frame, [
            ("Window Median", "n/a"),
            ("Window P95", "n/a"),
            ("Zero Window", "n/a"),
            ("MSS Top", "n/a"),
            ("MSS Top %", "n/a"),
        ])
        tk.Label(performance_frame, text="MSS Distribution", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        mss_container = tk.Frame(performance_frame, bg=BG_PANEL)
        mss_container.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(performance_frame, text="Additional Fields", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_perf_extra = self._make_tree(performance_frame, ("key", "value"), ("Key", "Value"))

        raw_frame = ttk.LabelFrame(tab, text="Raw JSON")
        raw_frame.pack(fill="both", expand=True, padx=8, pady=6)
        raw_notebook = ttk.Notebook(raw_frame)
        raw_notebook.pack(fill="both", expand=True)
        json_texts = {}
        for key, label in [
            ("tcp_handshakes", "TCP Handshakes"),
            ("tcp_reliability", "TCP Reliability"),
            ("tcp_performance", "TCP Performance"),
        ]:
            raw_tab = tk.Frame(raw_notebook, bg=BG_PANEL)
            raw_notebook.add(raw_tab, text=label)
            json_texts[key] = self._make_json_text(raw_tab)

        self.ti_tcp_health = {
            "kpi_vars_handshakes": kpi_vars_handshakes,
            "tree_handshake_extra": tree_handshake_extra,
            "kpi_vars_reliability": kpi_vars_reliability,
            "tree_reliability_extra": tree_reliability_extra,
            "kpi_vars_performance": kpi_vars_performance,
            "mss_container": mss_container,
            "mss_tree": None,
            "tree_perf_extra": tree_perf_extra,
            "json_texts": json_texts,
        }

    def _build_ti_top_entities(self):
        tab = self.tech_tabs["Top Entities"]
        ip_frame = ttk.LabelFrame(tab, text="IP Talkers")
        ip_frame.pack(fill="x", padx=8, pady=6)
        tk.Label(ip_frame, text="Top Source IPs", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        ip_src_container = tk.Frame(ip_frame, bg=BG_PANEL)
        ip_src_container.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(ip_frame, text="Top Destination IPs", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        ip_dst_container = tk.Frame(ip_frame, bg=BG_PANEL)
        ip_dst_container.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(ip_frame, text="Internal/External Split", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_ip_split = self._make_tree(ip_frame, ("key", "value"), ("Key", "Value"))

        mac_frame = ttk.LabelFrame(tab, text="MAC Talkers")
        mac_frame.pack(fill="x", padx=8, pady=6)
        tk.Label(mac_frame, text="Top Source MACs", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        mac_src_container = tk.Frame(mac_frame, bg=BG_PANEL)
        mac_src_container.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(mac_frame, text="Top Destination MACs", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        mac_dst_container = tk.Frame(mac_frame, bg=BG_PANEL)
        mac_dst_container.pack(fill="x", padx=8, pady=(0, 8))

        ports_frame = ttk.LabelFrame(tab, text="Ports and Services")
        ports_frame.pack(fill="x", padx=8, pady=6)
        tk.Label(ports_frame, text="TCP Top Destination Ports", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tcp_ports_container = tk.Frame(ports_frame, bg=BG_PANEL)
        tcp_ports_container.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(ports_frame, text="UDP Top Destination Ports", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        udp_ports_container = tk.Frame(ports_frame, bg=BG_PANEL)
        udp_ports_container.pack(fill="x", padx=8, pady=(0, 8))

        raw_frame = ttk.LabelFrame(tab, text="Raw JSON")
        raw_frame.pack(fill="both", expand=True, padx=8, pady=6)
        raw_notebook = ttk.Notebook(raw_frame)
        raw_notebook.pack(fill="both", expand=True)
        json_texts = {}
        for key, label in [
            ("top_entities", "Top Entities"),
            ("ip_talkers", "IP Talkers"),
            ("mac_talkers", "MAC Talkers"),
            ("ports", "Ports"),
        ]:
            raw_tab = tk.Frame(raw_notebook, bg=BG_PANEL)
            raw_notebook.add(raw_tab, text=label)
            json_texts[key] = self._make_json_text(raw_tab)

        self.ti_top_entities = {
            "ip_src_container": ip_src_container,
            "ip_dst_container": ip_dst_container,
            "tree_ip_split": tree_ip_split,
            "mac_src_container": mac_src_container,
            "mac_dst_container": mac_dst_container,
            "tcp_ports_container": tcp_ports_container,
            "udp_ports_container": udp_ports_container,
            "json_texts": json_texts,
            "ip_src_tree": None,
            "ip_dst_tree": None,
            "mac_src_tree": None,
            "mac_dst_tree": None,
            "tcp_ports_tree": None,
            "udp_ports_tree": None,
        }

    def _build_ti_security_signals(self):
        tab = self.tech_tabs["Security Signals"]
        scan_frame = ttk.LabelFrame(tab, text="Scan Signals")
        scan_frame.pack(fill="x", padx=8, pady=6)
        tk.Label(scan_frame, text="Distinct Ports", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_distinct_ports = self._make_tree(scan_frame, ("key", "value"), ("Key", "Value"))
        tk.Label(scan_frame, text="Distinct IPs", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_distinct_ips = self._make_tree(scan_frame, ("key", "value"), ("Key", "Value"))
        tk.Label(scan_frame, text="TCP SYN Ratio", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_syn_ratio = self._make_tree(scan_frame, ("key", "value"), ("Key", "Value"))
        tk.Label(scan_frame, text="Other Fields", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_scan_extra = self._make_tree(scan_frame, ("key", "value"), ("Key", "Value"))

        arp_frame = ttk.LabelFrame(tab, text="ARP / LAN Signals")
        arp_frame.pack(fill="x", padx=8, pady=6)
        tk.Label(arp_frame, text="Multiple MACs (Count)", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_multiple_macs = self._make_tree(arp_frame, ("key", "value"), ("Key", "Value"))
        tk.Label(arp_frame, text="Multiple MACs Examples", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        multiple_macs_container = tk.Frame(arp_frame, bg=BG_PANEL)
        multiple_macs_container.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(arp_frame, text="ARP Changes", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_arp_changes = self._make_tree(arp_frame, ("key", "value"), ("Key", "Value"))
        tk.Label(arp_frame, text="ARP Changes Top Entries", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        arp_changes_container = tk.Frame(arp_frame, bg=BG_PANEL)
        arp_changes_container.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(arp_frame, text="Other Fields", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_arp_extra = self._make_tree(arp_frame, ("key", "value"), ("Key", "Value"))

        dns_frame = ttk.LabelFrame(tab, text="DNS Anomalies")
        dns_frame.pack(fill="x", padx=8, pady=6)
        tk.Label(dns_frame, text="High Entropy Domains", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_entropy = self._make_tree(dns_frame, ("key", "value"), ("Key", "Value"))
        tk.Label(dns_frame, text="Entropy Samples", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        entropy_container = tk.Frame(dns_frame, bg=BG_PANEL)
        entropy_container.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(dns_frame, text="Long Labels", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_long_labels = self._make_tree(dns_frame, ("key", "value"), ("Key", "Value"))
        tk.Label(dns_frame, text="Long Label Samples", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        long_labels_container = tk.Frame(dns_frame, bg=BG_PANEL)
        long_labels_container.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(dns_frame, text="NXDOMAIN", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_nxdomain = self._make_tree(dns_frame, ("key", "value"), ("Key", "Value"))
        tk.Label(dns_frame, text="Other Fields", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tree_dns_extra = self._make_tree(dns_frame, ("key", "value"), ("Key", "Value"))

        raw_frame = ttk.LabelFrame(tab, text="Raw JSON")
        raw_frame.pack(fill="both", expand=True, padx=8, pady=6)
        raw_notebook = ttk.Notebook(raw_frame)
        raw_notebook.pack(fill="both", expand=True)
        json_texts = {}
        for key, label in [
            ("scan_signals", "Scan Signals"),
            ("arp_lan_signals", "ARP/LAN Signals"),
            ("dns_anomalies", "DNS Anomalies"),
        ]:
            raw_tab = tk.Frame(raw_notebook, bg=BG_PANEL)
            raw_notebook.add(raw_tab, text=label)
            json_texts[key] = self._make_json_text(raw_tab)

        self.ti_security_signals = {
            "tree_distinct_ports": tree_distinct_ports,
            "tree_distinct_ips": tree_distinct_ips,
            "tree_syn_ratio": tree_syn_ratio,
            "tree_scan_extra": tree_scan_extra,
            "tree_multiple_macs": tree_multiple_macs,
            "multiple_macs_container": multiple_macs_container,
            "tree_arp_changes": tree_arp_changes,
            "arp_changes_container": arp_changes_container,
            "tree_arp_extra": tree_arp_extra,
            "tree_entropy": tree_entropy,
            "entropy_container": entropy_container,
            "tree_long_labels": tree_long_labels,
            "long_labels_container": long_labels_container,
            "tree_nxdomain": tree_nxdomain,
            "tree_dns_extra": tree_dns_extra,
            "json_texts": json_texts,
            "multiple_macs_tree": None,
            "arp_changes_tree": None,
            "entropy_tree": None,
            "long_labels_tree": None,
        }

    def _build_ti_time_series_chunking(self):
        tab = self.tech_tabs["Time Series & Chunking"]
        series_frame = ttk.LabelFrame(tab, text="Traffic Over Time")
        series_frame.pack(fill="x", padx=8, pady=6)
        tk.Label(series_frame, text="Time Series", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        series_container = tk.Frame(series_frame, bg=BG_PANEL)
        series_container.pack(fill="x", padx=8, pady=(0, 8))

        chunks_frame = ttk.LabelFrame(tab, text="Packet Chunks")
        chunks_frame.pack(fill="x", padx=8, pady=6)
        tk.Label(chunks_frame, text="Chunks Table", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        chunks_container = tk.Frame(chunks_frame, bg=BG_PANEL)
        chunks_container.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(chunks_frame, text="Top Chunks by Bytes", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        top_bytes_container = tk.Frame(chunks_frame, bg=BG_PANEL)
        top_bytes_container.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(chunks_frame, text="Top Chunks by Packets", fg=FG_MUTED, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        top_packets_container = tk.Frame(chunks_frame, bg=BG_PANEL)
        top_packets_container.pack(fill="x", padx=8, pady=(0, 8))

        raw_frame = ttk.LabelFrame(tab, text="Raw JSON")
        raw_frame.pack(fill="both", expand=True, padx=8, pady=6)
        raw_notebook = ttk.Notebook(raw_frame)
        raw_notebook.pack(fill="both", expand=True)
        json_texts = {}
        for key, label in [
            ("time_series", "Time Series"),
            ("packet_chunks", "Packet Chunks"),
        ]:
            raw_tab = tk.Frame(raw_notebook, bg=BG_PANEL)
            raw_notebook.add(raw_tab, text=label)
            json_texts[key] = self._make_json_text(raw_tab)

        self.ti_time_series = {
            "series_container": series_container,
            "chunks_container": chunks_container,
            "top_bytes_container": top_bytes_container,
            "top_packets_container": top_packets_container,
            "json_texts": json_texts,
            "series_tree": None,
            "chunks_tree": None,
            "top_bytes_tree": None,
            "top_packets_tree": None,
        }

    def _extra_analysis_data(self):
        return []

    def _build_packet_table(self):
        header = tk.Frame(self.content, bg=BG_MAIN)
        header.pack(fill="x", padx=20, pady=(10, 4))

        tk.Label(header, text="Packet List", fg=FG_MUTED, bg=BG_MAIN,
                 font=("Segoe UI", 10, "bold")).pack(side="left")

        self.toggle_btn = tk.Button(header, text="Collapse Packet List", command=self.toggle_table,
                                    bg=BG_PANEL, fg=FG_TEXT)
        self.toggle_btn.pack(side="right")

        self.table_frame = tk.Frame(self.content, bg=BG_MAIN)
        self.table_frame.pack(fill="both", expand=True, padx=20, pady=10)

        columns = ("id", "time", "stack", "src", "dst", "ports", "l4", "flags", "quality")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=120 if col in ("src", "dst") else 90, anchor="w")

        scrollbar = ttk.Scrollbar(self.table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def toggle_table(self):
        if self.table_visible:
            self.table_frame.pack_forget()
            self.toggle_btn.config(text="Expand Packet List")
            self.table_visible = False
        else:
            self.table_frame.pack(fill="both", expand=True, padx=20, pady=10)
            self.toggle_btn.config(text="Collapse Packet List")
            self.table_visible = True

    def set_status(self, text):
        self.status_var.set(text)

    def start_capture(self):
        backend = self.backend_var.get().strip()
        interface = self.interface_var.get().strip()
        duration = int(self.duration_var.get() or 0)
        limit = int(self.limit_var.get() or 0)

        if backend == "scapy" and (not interface or interface.startswith("dummy")):
            default_iface = get_default_scapy_iface()
            if default_iface:
                interface = default_iface
                self.interface_var.set(default_iface)
            else:
                messagebox.showerror(
                    "No Scapy Interface",
                    "Scapy backend requires a real NPF interface. Use the capture list to find one."
                )
                return

        self.start_btn.config(state="disabled")
        self.set_status("Capturing...")

        thread = threading.Thread(
            target=self._capture_thread,
            args=(backend, interface, duration, limit),
            daemon=True,
        )
        thread.start()

    def _capture_thread(self, backend, interface, duration, limit):
        try:
            packets = run_capture(backend, interface, duration, limit)
            analysis = run_analysis(packets)
            self.latest_packets = packets
            self.latest_analysis = analysis or {}
            self.rows = packets
            self.after(0, self.refresh_table)
            self.after(0, lambda: self.refresh_analysis(analysis))
            self.after(0, self.refresh_technical_information)
            self.after(0, self.refresh_simplified_dashboard)
            self.after(0, lambda: self.set_status(f"Loaded {len(packets)} packets"))
            self.after(0, lambda: self.download_btn.config(state="normal" if packets else "disabled"))
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror("Capture failed", str(exc)))
            self.after(0, lambda: self.set_status("Capture failed"))
        finally:
            self.after(0, lambda: self.start_btn.config(state="normal"))

    def apply_filter(self):
        self.refresh_table()

    def refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        filtered = self._filtered_rows()
        for packet in filtered:
            ports = f"{packet.get('src_port')}->{packet.get('dst_port')}" if packet.get("src_port") is not None else "-"
            flags = ",".join(packet.get("tcp_flags_names") or []) or "-"
            quality = ",".join(packet.get("quality_names") or []) or "-"
            values = (
                packet.get("packet_id"),
                packet.get("timestamp_us"),
                packet.get("stack_summary"),
                packet.get("src_ip"),
                packet.get("dst_ip"),
                ports,
                packet.get("l4_protocol") or "-",
                flags,
                quality,
            )
            self.tree.insert("", "end", values=values)
        self.update_stats(filtered)

    def _filtered_rows(self):
        term = self.filter_var.get().strip().lower()
        if not term:
            return self.rows
        result = []
        for packet in self.rows:
            haystack = " ".join([
                str(packet.get("stack_summary") or ""),
                str(packet.get("src_ip") or ""),
                str(packet.get("dst_ip") or ""),
                str(packet.get("l4_protocol") or ""),
                str(packet.get("src_port") or ""),
                str(packet.get("dst_port") or ""),
                ":".join(packet.get("flow_key") or []),
            ]).lower()
            if term in haystack:
                result.append(packet)
        return result

    def update_stats(self, packets):
        ipv4 = sum(1 for p in packets if p.get("ip_version") == 4)
        ipv6 = sum(1 for p in packets if p.get("ip_version") == 6)
        tcp = sum(1 for p in packets if p.get("l4_protocol") == "TCP")
        udp = sum(1 for p in packets if p.get("l4_protocol") == "UDP")
        flows = set()
        for p in packets:
            fk = p.get("flow_key")
            if isinstance(fk, list) and len(fk) == 5:
                flows.add(":".join(map(str, fk)))

        self.stat_packets.set(str(len(packets)))
        self.stat_ip.set(f"{ipv4} / {ipv6}")
        self.stat_l4.set(f"{tcp} / {udp}")
        self.stat_flows.set(str(len(flows)))

    def refresh_analysis(self, analysis):
        if not analysis:
            self.analysis_protocol.set("-")
            self.analysis_abnormal.set("-")
            self.analysis_handshake.set("-")
            self.analysis_chunks.set("-")
            self.analysis_capture_quality.set("-")
            self.analysis_decode_health.set("-")
            self.analysis_filtering.set("-")
            self.analysis_throughput.set("-")
            self.analysis_packet_sizes.set("-")
            self.analysis_l2l3.set("-")
            self.analysis_top_talkers.set("-")
            self.analysis_top_macs.set("-")
            self.analysis_top_ports.set("-")
            self.analysis_flow_summary.set("-")
            self.analysis_flow_heavy.set("-")
            self.analysis_flow_states.set("-")
            self.analysis_tcp_handshake.set("-")
            self.analysis_tcp_reliability.set("-")
            self.analysis_tcp_performance.set("-")
            self.analysis_scan_signals.set("-")
            self.analysis_dns_anomalies.set("-")
            self.analysis_arp_lan.set("-")
            return

        protocol = analysis.get("global_results", {}).get("protocol_mix", {})
        percents = protocol.get("protocol_percentages", {})
        if percents:
            text = "\n".join([f"{k}: {v}%" for k, v in percents.items()])
        else:
            text = "-"
        self.analysis_protocol.set(text)

        abnormal = analysis.get("global_results", {}).get("abnormal_activity", {})
        findings = abnormal.get("findings", [])
        if not findings:
            self.analysis_abnormal.set("None")
        else:
            summary = []
            for finding in findings:
                if finding.get("type") == "possible_port_scan":
                    summary.append(f"port_scan({len(finding.get('sources', []))})")
                elif finding.get("type") == "high_tcp_rst_ratio":
                    summary.append(f"rst_ratio({finding.get('ratio')})")
                else:
                    summary.append(finding.get("type", "unknown"))
            self.analysis_abnormal.set("\n".join(summary))

        handshakes = analysis.get("global_results", {}).get("tcp_handshakes", {})
        if handshakes:
            self.analysis_handshake.set(
                f"total {handshakes.get('handshakes_total', 0)}\n"
                f"complete {handshakes.get('handshakes_complete', 0)}"
            )
        else:
            self.analysis_handshake.set("-")

        chunks = analysis.get("time_series", {}).get("packet_chunks", {})
        chunk_list = chunks.get("chunks", [])
        if chunk_list:
            last = chunk_list[-1]
            self.analysis_chunks.set(
                f"chunks {len(chunk_list)}\n"
                f"last {last.get('packets', 0)} pkts"
            )
        else:
            self.analysis_chunks.set("-")

        health = analysis.get("global_results", {}).get("capture_health", {})
        if health:
            quality = health.get("capture_quality", {})
            session = quality.get("session", {})
            drops = quality.get("drops", {})
            self.analysis_capture_quality.set(
                f"start {session.get('capture_start_us', 'n/a')}\n"
                f"end {session.get('capture_end_us', 'n/a')}\n"
                f"duration {session.get('duration_us', 'n/a')}\n"
                f"link {session.get('link_types', 'n/a')}\n"
                f"snaplen {session.get('snaplen', 'n/a')}\n"
                f"promisc {session.get('promiscuous', 'n/a')}\n"
                f"drops {drops.get('dropped_packets', 'n/a')}"
            )
            decode = health.get("decode_health", {})
            self.analysis_decode_health.set(
                f"success {decode.get('decode_success_rate', 'n/a')}\n"
                f"malformed {decode.get('malformed_packets', 'n/a')}\n"
                f"truncated {decode.get('truncated_packets', 'n/a')}\n"
                f"unknown_l3 {decode.get('unknown_l3_packets', 'n/a')}\n"
                f"unknown_l4 {decode.get('unknown_l4_packets', 'n/a')}"
            )
            filtering = health.get("filtering_sampling", {})
            self.analysis_filtering.set(
                f"filter {filtering.get('capture_filter', 'n/a')}\n"
                f"filtered_out {filtering.get('packets_filtered_out', 'n/a')}\n"
                f"sampling {filtering.get('sampling_rate', 'n/a')}"
            )
        else:
            self.analysis_capture_quality.set("-")
            self.analysis_decode_health.set("-")
            self.analysis_filtering.set("-")

        throughput = analysis.get("global_results", {}).get("throughput_peaks", {})
        if throughput:
            self.analysis_throughput.set(
                f"bps now {_fmt_bps(throughput.get('bps_now'))}\n"
                f"bps avg {_fmt_bps(throughput.get('bps_avg'))}\n"
                f"pps now {_fmt_pps(throughput.get('pps_now'))}\n"
                f"pps avg {_fmt_pps(throughput.get('pps_avg'))}\n"
                f"peak bps {_fmt_bps(throughput.get('peak_bps'))}\n"
                f"peak pps {_fmt_pps(throughput.get('peak_pps'))}\n"
                f"peak bps ts {_fmt_ts_utc(throughput.get('peak_bps_timestamp'))}\n"
                f"peak pps ts {_fmt_ts_utc(throughput.get('peak_pps_timestamp'))}"
            )
        else:
            self.analysis_throughput.set("-")

        size_stats = analysis.get("global_results", {}).get("packet_size_stats", {})
        if size_stats:
            captured = size_stats.get("captured_length", {})
            original = size_stats.get("original_length", {})
            hist = size_stats.get("histogram", {})
            fragments = size_stats.get("fragments", {})
            self.analysis_packet_sizes.set(
                f"cap min/med/p95/max "
                f"{_fmt_bytes(captured.get('min'))} / {_fmt_bytes(captured.get('median'))} / "
                f"{_fmt_bytes(captured.get('p95'))} / {_fmt_bytes(captured.get('max'))}\n"
                f"orig min/med/p95/max "
                f"{_fmt_bytes(original.get('min'))} / {_fmt_bytes(original.get('median'))} / "
                f"{_fmt_bytes(original.get('p95'))} / {_fmt_bytes(original.get('max'))}\n"
                f"hist 0-63 {_fmt_count(hist.get('0-63', 0))}, 64-127 {_fmt_count(hist.get('64-127', 0))}\n"
                f"hist 128-511 {_fmt_count(hist.get('128-511', 0))}, 512-1023 {_fmt_count(hist.get('512-1023', 0))}\n"
                f"hist 1024-1514 {_fmt_count(hist.get('1024-1514', 0))}, jumbo {_fmt_count(hist.get('jumbo', 0))}\n"
                f"frags v4/v6 {_fmt_count(fragments.get('ipv4_fragments', 0))} / {_fmt_count(fragments.get('ipv6_fragments', 0))}"
            )
        else:
            self.analysis_packet_sizes.set("-")

        l2l3 = analysis.get("global_results", {}).get("l2_l3_breakdown", {})
        if l2l3:
            self.analysis_l2l3.set(
                f"Ethernet {_fmt_count(l2l3.get('ethernet_frames', 0))}\n"
                f"VLAN {_fmt_count(l2l3.get('vlan_frames', 0))}\n"
                f"ARP {_fmt_count(l2l3.get('arp_packets', 0))}\n"
                f"ICMP {_fmt_count(l2l3.get('icmp_packets', 0))}\n"
                f"ICMPv6 {_fmt_count(l2l3.get('icmpv6_packets', 0))}\n"
                f"Multicast {_fmt_count(l2l3.get('multicast_packets', 0))}\n"
                f"Broadcast {_fmt_count(l2l3.get('broadcast_packets', 0))}"
            )
        else:
            self.analysis_l2l3.set("-")

        top_entities = analysis.get("global_results", {}).get("top_entities", {})
        ip_talkers = top_entities.get("ip_talkers", {})
        if ip_talkers:
            src_list = ip_talkers.get("top_src", [])
            dst_list = ip_talkers.get("top_dst", [])
            internal = ip_talkers.get("internal_external", {})
            src_lines = [
                f"src {item.get('ip')} {_fmt_bytes(item.get('bytes'))}"
                for item in src_list
            ]
            dst_lines = [
                f"dst {item.get('ip')} {_fmt_bytes(item.get('bytes'))}"
                for item in dst_list
            ]
            split = (
                f"internal {_fmt_pct(internal.get('internal_bytes_pct'))} / "
                f"external {_fmt_pct(internal.get('external_bytes_pct'))}"
            )
            self.analysis_top_talkers.set("\n".join(src_lines + dst_lines + [split]) if (src_lines or dst_lines) else "-")
        else:
            self.analysis_top_talkers.set("-")

        mac_talkers = top_entities.get("mac_talkers", {})
        if mac_talkers:
            mac_list = mac_talkers.get("top_src", []) + mac_talkers.get("top_dst", [])
            lines = []
            for item in mac_list[:6]:
                vendor = item.get("vendor", "Unknown")
                lines.append(f"{item.get('mac')} {vendor} {_fmt_bytes(item.get('bytes'))}")
            self.analysis_top_macs.set("\n".join(lines) if lines else "-")
        else:
            self.analysis_top_macs.set("-")

        ports = top_entities.get("ports", {})
        if ports:
            tcp = ports.get("tcp", {})
            udp = ports.get("udp", {})
            tcp_lines = [
                f"TCP {item.get('port')} ({item.get('service')}) {_fmt_pct(item.get('packets_pct'))}"
                for item in tcp.get("top_dst_ports", [])
            ]
            udp_lines = [
                f"UDP {item.get('port')} ({item.get('service')}) {_fmt_pct(item.get('packets_pct'))}"
                for item in udp.get("top_dst_ports", [])
            ]
            self.analysis_top_ports.set("\n".join(tcp_lines + udp_lines) if (tcp_lines or udp_lines) else "-")
        else:
            self.analysis_top_ports.set("-")

        flow_analytics = analysis.get("global_results", {}).get("flow_analytics", {})
        if flow_analytics:
            summary = flow_analytics.get("summary", {})
            self.analysis_flow_summary.set(
                f"total flows {_fmt_count(summary.get('total_flows', 0))}\n"
                f"new flows/sec {_fmt_number(summary.get('new_flows_per_sec'))}\n"
                f"duration med {_fmt_duration_us(summary.get('duration_us_median'))}\n"
                f"duration p95 {_fmt_duration_us(summary.get('duration_us_p95'))}\n"
                f"bytes/flow avg {_fmt_bytes(summary.get('bytes_per_flow_avg'))}\n"
                f"bytes/flow p95 {_fmt_bytes(summary.get('bytes_per_flow_p95'))}"
            )

            heavy = flow_analytics.get("heavy_hitters", {})
            by_bytes = heavy.get("top_by_bytes", [])
            by_packets = heavy.get("top_by_packets", [])
            heavy_lines = []
            for item in by_bytes[:3]:
                heavy_lines.append(
                    f"bytes {item.get('label')} {_fmt_bytes(item.get('bytes'))} "
                    f"{_fmt_duration_us(item.get('duration_us'))}"
                )
            for item in by_packets[:3]:
                heavy_lines.append(
                    f"pkts {item.get('label')} {_fmt_count(item.get('packets'))} "
                    f"{_fmt_duration_us(item.get('duration_us'))}"
                )
            self.analysis_flow_heavy.set("\n".join(heavy_lines) if heavy_lines else "-")

            states = flow_analytics.get("states", {})
            self.analysis_flow_states.set(
                f"TCP established {_fmt_count(states.get('tcp_established', 0))}\n"
                f"TCP half-open {_fmt_count(states.get('tcp_half_open', 0))}\n"
                f"TCP reset/failed {_fmt_count(states.get('tcp_reset_failed', 0))}\n"
                f"UDP paired {_fmt_count(states.get('udp_paired', 0))}\n"
                f"UDP unpaired {_fmt_count(states.get('udp_unpaired', 0))}"
            )
        else:
            self.analysis_flow_summary.set("-")
            self.analysis_flow_heavy.set("-")
            self.analysis_flow_states.set("-")

        handshake = analysis.get("global_results", {}).get("tcp_handshakes", {})
        if handshake:
            self.analysis_tcp_handshake.set(
                f"total {_fmt_count(handshake.get('handshakes_total', 0))}\n"
                f"complete {_fmt_count(handshake.get('handshakes_complete', 0))}\n"
                f"completion {_fmt_pct(handshake.get('completion_rate'))}\n"
                f"rtt median {handshake.get('rtt_median_ms', 'n/a')} ms\n"
                f"rtt p95 {handshake.get('rtt_p95_ms', 'n/a')} ms"
            )
        else:
            self.analysis_tcp_handshake.set("-")

        reliability = analysis.get("global_results", {}).get("tcp_reliability", {})
        if reliability:
            self.analysis_tcp_reliability.set(
                f"retrans {_fmt_count(reliability.get('retransmissions', 0))} "
                f"({_fmt_pct(reliability.get('retransmission_rate'))})\n"
                f"out-of-order {_fmt_count(reliability.get('out_of_order', 0))} "
                f"({_fmt_pct(reliability.get('out_of_order_rate'))})\n"
                f"dup ACKs {_fmt_count(reliability.get('dup_acks', 0))} "
                f"({_fmt_pct(reliability.get('dup_ack_rate'))})\n"
                f"RST {_fmt_count(reliability.get('rst_packets', 0))} "
                f"({_fmt_pct(reliability.get('rst_rate'))})"
            )
        else:
            self.analysis_tcp_reliability.set("-")

        performance = analysis.get("global_results", {}).get("tcp_performance", {})
        if performance:
            mss_top = performance.get("mss_top_value")
            mss_pct = performance.get("mss_top_pct")
            self.analysis_tcp_performance.set(
                f"window median {_fmt_number(performance.get('window_median'))}\n"
                f"window p95 {_fmt_number(performance.get('window_p95'))}\n"
                f"zero-window {_fmt_count(performance.get('zero_window', 0))}\n"
                f"mss top {mss_top if mss_top is not None else 'n/a'} "
                f"({_fmt_pct(mss_pct)})"
            )
        else:
            self.analysis_tcp_performance.set("-")

        scan = analysis.get("global_results", {}).get("scan_signals", {})
        if scan:
            ports = scan.get("distinct_ports", {})
            ips = scan.get("distinct_ips", {})
            syn_ratio = scan.get("tcp_syn_ratio", {})
            ratio_val = syn_ratio.get("ratio")
            ratio_note = syn_ratio.get("ratio_note")
            ratio_text = _fmt_number(ratio_val, 3) if ratio_val is not None else (ratio_note or "n/a")
            self.analysis_scan_signals.set(
                f"dst ports max {ports.get('max_count', 0)} ({ports.get('src_ip', 'n/a')})\n"
                f"dst ips max {ips.get('max_count', 0)} ({ips.get('src_ip', 'n/a')})\n"
                f"SYN {syn_ratio.get('syn_count', 0)} / SYN-ACK {syn_ratio.get('synack_count', 0)}\n"
                f"SYN:SYN-ACK {ratio_text}"
            )
        else:
            self.analysis_scan_signals.set("-")

        dns = analysis.get("global_results", {}).get("dns_anomalies", {})
        if dns:
            entropy = dns.get("entropy", {})
            long_labels = dns.get("long_labels", {})
            nxd = dns.get("nxdomain", {})
            sample_entropy = entropy.get("samples", [])
            sample_long = long_labels.get("samples", [])
            entropy_line = sample_entropy[0]["domain"] if sample_entropy else "none"
            long_line = sample_long[0]["domain"] if sample_long else "none"
            self.analysis_dns_anomalies.set(
                f"high entropy {entropy.get('count', 0)} (e.g. {entropy_line})\n"
                f"long labels {long_labels.get('count', 0)} (e.g. {long_line})\n"
                f"NXDOMAIN {nxd.get('nxdomain_count', 0)} / {nxd.get('total_responses', 0)} "
                f"({_fmt_pct(nxd.get('nxdomain_pct'))})\n"
                f"spike {nxd.get('spike_detected', False)}"
            )
        else:
            self.analysis_dns_anomalies.set("-")

        arp = analysis.get("global_results", {}).get("arp_lan_signals", {})
        if arp:
            multiple = arp.get("multiple_macs", {})
            changes = arp.get("arp_changes", {})
            example = multiple.get("examples", [])
            example_ip = example[0]["ip"] if example else "none"
            self.analysis_arp_lan.set(
                f"multiple MACs {multiple.get('count', 0)} (e.g. {example_ip})\n"
                f"arp changes {changes.get('count', 0)}\n"
                f"threshold {changes.get('threshold', 'n/a')}"
            )
        else:
            self.analysis_arp_lan.set("-")

    def refresh_technical_information(self):
        analysis = self.latest_analysis or {}
        self._refresh_ti_capture_quality(analysis)
        self._refresh_ti_traffic_overview(analysis)
        self._refresh_ti_protocol_mix(analysis)
        self._refresh_ti_flow_analytics(analysis)
        self._refresh_ti_tcp_health(analysis)
        self._refresh_ti_top_entities(analysis)
        self._refresh_ti_security_signals(analysis)
        self._refresh_ti_time_series_chunking(analysis)

    def refresh_simplified_dashboard(self):
        analysis = self.latest_analysis or {}
        totals = analysis.get("global_results", {}).get("global_stats", {}).get("totals", {})
        totals = totals if isinstance(totals, dict) else {}
        packets_total = totals.get("packets")
        if packets_total is None:
            packets_total = analysis.get("stats", {}).get("packets_total")
        bytes_total = totals.get("bytes_captured")
        if bytes_total is None:
            bytes_total = totals.get("bytes_captured_total")
        if bytes_total is None:
            bytes_total = analysis.get("stats", {}).get("bytes_captured_total")
        duration_us = totals.get("duration_us")
        if duration_us is None:
            duration_us = analysis.get("stats", {}).get("duration_us")

        throughput = analysis.get("global_results", {}).get("throughput_peaks", {})
        throughput = throughput if isinstance(throughput, dict) else {}
        peak_bps = throughput.get("peak_bps")

        handshakes = analysis.get("global_results", {}).get("tcp_handshakes", {})
        handshakes = handshakes if isinstance(handshakes, dict) else {}
        completion_rate = handshakes.get("completion_rate")
        completion_pct = completion_rate * 100 if isinstance(completion_rate, (int, float)) else None

        reliability = analysis.get("global_results", {}).get("tcp_reliability", {})
        reliability = reliability if isinstance(reliability, dict) else {}
        retrans_rate = reliability.get("retransmission_rate")
        retrans_pct = retrans_rate * 100 if isinstance(retrans_rate, (int, float)) else None
        rst_rate = reliability.get("rst_rate")
        rst_pct = rst_rate * 100 if isinstance(rst_rate, (int, float)) else None

        drops = (analysis.get("global_results", {})
                 .get("capture_health", {})
                 .get("capture_quality", {})
                 .get("drops", {}))
        drops = drops if isinstance(drops, dict) else {}
        drop_rate_pct = drops.get("drop_rate_pct")
        if drop_rate_pct is None:
            dropped_packets = drops.get("dropped_packets")
            if isinstance(dropped_packets, (int, float)) and isinstance(packets_total, (int, float)):
                denom = packets_total + dropped_packets
                drop_rate_pct = (dropped_packets / denom * 100) if denom else None

        nxdomain = analysis.get("global_results", {}).get("dns_anomalies", {}).get("nxdomain", {})
        nxdomain = nxdomain if isinstance(nxdomain, dict) else {}
        nxdomain_spike = nxdomain.get("spike_detected")

        self.sd_kpi_vars["Total Packets"].set(_fmt_count(packets_total))
        self.sd_kpi_vars["Total Bytes"].set(_fmt_bytes(bytes_total))
        self.sd_kpi_vars["Duration"].set(_fmt_duration_us(duration_us))
        self.sd_kpi_vars["Peak BPS"].set(_fmt_bps(peak_bps))
        self.sd_kpi_vars["TCP Handshake Completion"].set(_fmt_pct(completion_pct))
        self.sd_kpi_vars["TCP Retransmission Rate"].set(_fmt_pct(retrans_pct))
        self.sd_kpi_vars["Drop Rate"].set(_fmt_pct(drop_rate_pct))
        self.sd_kpi_vars["NXDOMAIN Spike"].set(str(nxdomain_spike if nxdomain_spike is not None else "n/a"))

        self.sd_kpi_sev["Total Packets"].set("INFO")
        self.sd_kpi_sev["Total Bytes"].set("INFO")
        self.sd_kpi_sev["Duration"].set("INFO")
        self.sd_kpi_sev["Peak BPS"].set("INFO")
        self.sd_kpi_sev["Drop Rate"].set(self._sev_from_pct(drop_rate_pct, DROP_RATE_WARN, DROP_RATE_WARN, DROP_RATE_BAD))
        if completion_pct is None:
            self.sd_kpi_sev["TCP Handshake Completion"].set("INFO")
        elif completion_pct < HANDSHAKE_WARN_LO:
            self.sd_kpi_sev["TCP Handshake Completion"].set("BAD")
        elif completion_pct < HANDSHAKE_GOOD_LO:
            self.sd_kpi_sev["TCP Handshake Completion"].set("WARN")
        else:
            self.sd_kpi_sev["TCP Handshake Completion"].set("GOOD")
        self.sd_kpi_sev["TCP Retransmission Rate"].set(
            self._sev_from_pct(retrans_pct, RETX_WARN, RETX_WARN, RETX_BAD)
        )
        self.sd_kpi_sev["NXDOMAIN Spike"].set(self._sev_from_bool(nxdomain_spike))

        # Charts: Traffic over time
        ts_obj = analysis.get("time_series", {})
        ts_obj = ts_obj if isinstance(ts_obj, dict) else {}
        series = ts_obj.get("time_series") or ts_obj.get("buckets") or ts_obj.get("series")
        if series is None:
            series = analysis.get("global_results", {}).get("time_series")
        if series is None and isinstance(analysis.get("time_series"), list):
            series = analysis.get("time_series")

        x = []
        packets_series = []
        bytes_series = []

        if isinstance(series, dict):
            if isinstance(series.get("traffic"), list):
                series = series.get("traffic")
        if isinstance(series, list):
            for idx, point in enumerate(series):
                if isinstance(point, dict):
                    ts = point.get("start_us") or point.get("timestamp_us") or point.get("end_us")
                    x.append(_fmt_ts_utc(ts) if isinstance(ts, (int, float)) and ts > 1_000_000 else str(idx))
                    packets_series.append(point.get("packets"))
                    bytes_series.append(point.get("bytes") if point.get("bytes") is not None else point.get("bytes_captured"))
                else:
                    x.append(str(idx))
                    packets_series.append(None)
                    bytes_series.append(None)
        elif isinstance(series, dict):
            packets_list = series.get("packets") or series.get("packet_counts")
            bytes_list = series.get("bytes") or series.get("byte_counts") or series.get("bytes_captured")
            starts = series.get("bucket_start_us") or series.get("start_us") or series.get("timestamps")
            if isinstance(packets_list, list) or isinstance(bytes_list, list):
                total = max(len(packets_list or []), len(bytes_list or []), len(starts or []))
                for idx in range(total):
                    ts = starts[idx] if isinstance(starts, list) and idx < len(starts) else None
                    x.append(_fmt_ts_utc(ts) if isinstance(ts, (int, float)) and ts > 1_000_000 else str(idx))
                    packets_series.append(packets_list[idx] if isinstance(packets_list, list) and idx < len(packets_list) else None)
                    bytes_series.append(bytes_list[idx] if isinstance(bytes_list, list) and idx < len(bytes_list) else None)

        if len(x) > 200:
            step = max(1, len(x) // 200)
            x = x[::step][:200]
            packets_series = packets_series[::step][:200]
            bytes_series = bytes_series[::step][:200]

        if x:
            self._mpl_line(
                self.sd_chart_tabs["Traffic"],
                x,
                [
                    {"label": "Packets", "values": packets_series},
                    {"label": "Bytes", "values": bytes_series},
                ],
                "Traffic Over Time",
                xlabel="Bucket",
                ylabel="Count",
            )
        else:
            self._mpl_clear_frame(self.sd_chart_tabs["Traffic"])
            self._render_table(self.sd_chart_tabs["Traffic"], ["bucket", "packets", "bytes"], [("n/a", "n/a", "n/a")])

        protocol = analysis.get("global_results", {}).get("protocol_mix", {})
        protocol = protocol if isinstance(protocol, dict) else {}
        counts = protocol.get("protocol_counts")
        percents = protocol.get("protocol_percentages")
        if isinstance(counts, dict):
            counts_dict = counts
        elif isinstance(percents, dict):
            counts_dict = {}
        else:
            counts_dict = protocol if isinstance(protocol, dict) else {}
        if isinstance(percents, dict):
            percent_dict = percents
        else:
            total = sum(v for v in counts_dict.values() if isinstance(v, (int, float)))
            percent_dict = {
                k: (v / total * 100.0) if total else 0.0
                for k, v in counts_dict.items()
                if isinstance(v, (int, float))
            }
        labels = list(percent_dict.keys())
        values = [percent_dict.get(k, 0) for k in labels]
        if self.has_mpl:
            self._mpl_pie(self.sd_chart_tabs["Protocols"], labels, values, "Protocol Mix")
        else:
            self._mpl_clear_frame(self.sd_chart_tabs["Protocols"])
            rows = []
            for key in labels:
                count_val = counts_dict.get(key)
                count_text = _fmt_count(count_val) if isinstance(count_val, (int, float)) else "n/a"
                rows.append((key, count_text, _fmt_pct(percent_dict.get(key))))
            self._render_table(self.sd_chart_tabs["Protocols"], ["protocol", "count", "percent"], rows)

        talkers = (analysis.get("global_results", {})
                   .get("top_entities", {})
                   .get("ip_talkers", {})
                   .get("top_src", []))
        talkers = talkers if isinstance(talkers, list) else []
        talkers_sorted = sorted(
            [t for t in talkers if isinstance(t, dict)],
            key=lambda x: x.get("bytes", 0) if isinstance(x.get("bytes"), (int, float)) else 0,
            reverse=True,
        )[:10]
        talker_labels = [t.get("ip") for t in talkers_sorted]
        talker_values = [t.get("bytes", 0) if isinstance(t.get("bytes"), (int, float)) else 0 for t in talkers_sorted]
        if self.has_mpl:
            self._mpl_bar(self.sd_chart_tabs["Talkers"], talker_labels, talker_values,
                          "Top Source IPs by Bytes", xrot=45)
        else:
            self._mpl_clear_frame(self.sd_chart_tabs["Talkers"])
            rows = []
            for item in talkers_sorted:
                rows.append((
                    item.get("ip"),
                    _fmt_bytes(item.get("bytes")),
                    _fmt_count(item.get("packets")) if item.get("packets") is not None else "n/a",
                ))
            self._render_table(self.sd_chart_tabs["Talkers"], ["ip", "bytes", "packets"], rows)

        tcp_total = reliability.get("tcp_packets")
        def _rate_pct(rate_key, count_key):
            rate_val = reliability.get(rate_key)
            if isinstance(rate_val, (int, float)):
                return rate_val * 100
            count_val = reliability.get(count_key)
            if isinstance(count_val, (int, float)) and isinstance(tcp_total, (int, float)) and tcp_total:
                return (count_val / tcp_total) * 100
            return None

        tcp_metrics = [
            ("Retrans", "retransmission_rate", "retransmissions"),
            ("Out-of-order", "out_of_order_rate", "out_of_order"),
            ("Dup ACK", "dup_ack_rate", "dup_acks"),
            ("RST", "rst_rate", "rst_packets"),
        ]
        tcp_rows = []
        for label, rate_key, count_key in tcp_metrics:
            tcp_rows.append((label, _rate_pct(rate_key, count_key)))

        chart_labels = [label for label, value in tcp_rows if value is not None]
        chart_values = [value for _, value in tcp_rows if value is not None]
        if not chart_labels:
            chart_labels = [label for label, _ in tcp_rows]
            chart_values = [0 for _ in tcp_rows]

        if self.has_mpl:
            self._mpl_bar(self.sd_tcp_chart_frame, chart_labels, chart_values, "TCP Reliability Rates (%)")
        else:
            self._mpl_clear_frame(self.sd_tcp_chart_frame)
            rows = [(label, _fmt_pct(value)) for label, value in tcp_rows]
            self._render_table(self.sd_tcp_chart_frame, ["metric", "percent"], rows)

        interp_lines = []
        retrans_line = next((v for k, v in tcp_rows if k == "Retrans"), None)
        dup_line = next((v for k, v in tcp_rows if k == "Dup ACK"), None)
        ooo_line = next((v for k, v in tcp_rows if k == "Out-of-order"), None)
        rst_line = next((v for k, v in tcp_rows if k == "RST"), None)

        def _sev_text(value, good_lt, warn_lt, bad_ge):
            sev = self._sev_from_pct(value, good_lt, warn_lt, bad_ge)
            return f"{_fmt_pct(value)} ({sev})" if value is not None else "n/a (INFO)"

        interp_lines.append(f"Retrans rate {_sev_text(retrans_line, RETX_WARN, RETX_WARN, RETX_BAD)}")
        interp_lines.append(f"Out-of-order rate {_sev_text(ooo_line, RETX_WARN, RETX_WARN, RETX_BAD)}")
        interp_lines.append(f"Dup ACK rate {_sev_text(dup_line, RETX_WARN, RETX_WARN, RETX_BAD)}")
        interp_lines.append(f"RST rate {_sev_text(rst_line, RST_WARN, RST_WARN, RST_BAD)}")
        self.sd_tcp_interpret.set("\n".join(interp_lines[:3]))

        histogram = (analysis.get("global_results", {})
                     .get("packet_size_stats", {})
                     .get("histogram", {}))
        histogram = histogram if isinstance(histogram, dict) else {}
        bucket_order = ["0-63", "64-127", "128-511", "512-1023", "1024-1514", "jumbo"]
        bucket_labels = [b for b in bucket_order if b in histogram] + [
            b for b in histogram.keys() if b not in bucket_order
        ]
        bucket_counts = [histogram.get(b, 0) for b in bucket_labels]
        if not bucket_labels:
            self._mpl_clear_frame(self.sd_chart_tabs["Packet Sizes"])
            self._render_table(self.sd_chart_tabs["Packet Sizes"], ["bucket", "count"], [("n/a", "n/a")])
        else:
            self._mpl_hist(self.sd_chart_tabs["Packet Sizes"], bucket_labels, bucket_counts,
                           "Packet Size Histogram")

        diagnostics = []

        def _add_line(sev, title, detail):
            diagnostics.append((sev, f"[{sev}] {title}  {detail}"))

        if drop_rate_pct is None:
            _add_line("INFO", "Drop Rate", "not available in this capture.")
        else:
            if drop_rate_pct >= DROP_RATE_BAD:
                _add_line("BAD", "Drop Rate", f"{drop_rate_pct:.2f}% (>= {DROP_RATE_BAD}%)")
            elif drop_rate_pct >= DROP_RATE_WARN:
                _add_line("WARN", "Drop Rate", f"{drop_rate_pct:.2f}% (>= {DROP_RATE_WARN}%)")
            else:
                _add_line("GOOD", "Drop Rate", f"{drop_rate_pct:.2f}%")

        if completion_pct is None:
            _add_line("INFO", "Handshake Completion", "not available in this capture.")
        else:
            if completion_pct < HANDSHAKE_WARN_LO:
                _add_line("BAD", "Handshake Completion", f"{completion_pct:.2f}% (< {HANDSHAKE_WARN_LO}%)")
            elif completion_pct < HANDSHAKE_GOOD_LO:
                _add_line("WARN", "Handshake Completion", f"{completion_pct:.2f}% (< {HANDSHAKE_GOOD_LO}%)")
            else:
                _add_line("GOOD", "Handshake Completion", f"{completion_pct:.2f}%")

        if retrans_pct is None:
            _add_line("INFO", "Retransmission Rate", "not available in this capture.")
        else:
            if retrans_pct >= RETX_BAD:
                _add_line("BAD", "Retransmission Rate", f"{retrans_pct:.2f}% (>= {RETX_BAD}%)")
            elif retrans_pct >= RETX_WARN:
                _add_line("WARN", "Retransmission Rate", f"{retrans_pct:.2f}% (>= {RETX_WARN}%)")
            else:
                _add_line("GOOD", "Retransmission Rate", f"{retrans_pct:.2f}%")

        if rst_pct is None:
            _add_line("INFO", "RST Rate", "not available in this capture.")
        else:
            if rst_pct >= RST_BAD:
                _add_line("BAD", "RST Rate", f"{rst_pct:.2f}% (>= {RST_BAD}%)")
            elif rst_pct >= RST_WARN:
                _add_line("WARN", "RST Rate", f"{rst_pct:.2f}% (>= {RST_WARN}%)")
            else:
                _add_line("GOOD", "RST Rate", f"{rst_pct:.2f}%")

        if nxdomain_spike is None:
            _add_line("INFO", "NXDOMAIN Spike", "not available in this capture.")
        elif nxdomain_spike == NXDOMAIN_SPIKE_WARN:
            _add_line("WARN", "NXDOMAIN Spike", "spike_detected")
        else:
            _add_line("GOOD", "NXDOMAIN Spike", "no spike detected")

        arp_macs = (analysis.get("global_results", {})
                    .get("arp_lan_signals", {})
                    .get("multiple_macs", {}))
        arp_macs = arp_macs if isinstance(arp_macs, dict) else {}
        arp_count = arp_macs.get("count")
        if arp_count is None:
            _add_line("INFO", "ARP Multiple MACs", "not available in this capture.")
        elif arp_count >= ARP_CONFLICT_WARN:
            _add_line("WARN", "ARP Multiple MACs", f"{arp_count} detected")
        else:
            _add_line("GOOD", "ARP Multiple MACs", "none detected")

        scan_ports = (analysis.get("global_results", {})
                      .get("scan_signals", {})
                      .get("distinct_ports", {}))
        scan_ports = scan_ports if isinstance(scan_ports, dict) else {}
        max_ports = scan_ports.get("max_count")
        if max_ports is None:
            _add_line("INFO", "Scan Signals", "not available in this capture.")
        elif isinstance(max_ports, (int, float)) and max_ports >= SCAN_PORTS_WARN:
            _add_line("WARN", "Scan Signals", f"max distinct ports {max_ports}")
        else:
            _add_line("GOOD", "Scan Signals", f"max distinct ports {max_ports}")

        for child in self.sd_diag_container.winfo_children():
            child.destroy()
        for sev, msg in diagnostics:
            color = FG_MUTED
            if sev == "GOOD":
                color = GOOD
            elif sev == "WARN":
                color = WARN_BADGE
            elif sev == "BAD":
                color = BAD
            tk.Label(self.sd_diag_container, text=msg, fg=color, bg=BG_PANEL,
                     font=("Segoe UI", 9)).pack(anchor="w")
    def _refresh_ti_capture_quality(self, analysis):
        health = analysis.get("global_results", {}).get("capture_health", {})
        quality = health.get("capture_quality", {}) if isinstance(health, dict) else {}
        session = quality.get("session", {}) if isinstance(quality, dict) else {}
        drops = quality.get("drops", {}) if isinstance(quality, dict) else {}
        decode = health.get("decode_health", {}) if isinstance(health, dict) else {}
        filtering = health.get("filtering_sampling", {}) if isinstance(health, dict) else {}

        def _fmt_ts_or_raw(value):
            if value is None:
                return "n/a"
            if isinstance(value, (int, float)) and value > 1_000_000_000:
                return _fmt_ts_utc(value)
            return str(value)

        session_vars = self.ti_capture_quality["kpi_vars_session"]
        session_vars["Capture Start"].set(_fmt_ts_or_raw(session.get("capture_start_us")))
        session_vars["Capture End"].set(_fmt_ts_or_raw(session.get("capture_end_us")))
        duration_us = session.get("duration_us")
        duration_text = _fmt_duration_us(duration_us)
        if isinstance(duration_us, (int, float)):
            duration_text = f"{duration_text} ({_fmt_number(duration_us / 1_000_000, 3)} s)"
        session_vars["Duration"].set(duration_text)
        session_vars["Link Types"].set(str(session.get("link_types", "n/a")))
        session_vars["Snaplen"].set(str(session.get("snaplen", "n/a")))
        session_vars["Promiscuous"].set(str(session.get("promiscuous", "n/a")))

        drops_vars = self.ti_capture_quality["kpi_vars_drops"]
        dropped_packets = drops.get("dropped_packets")
        drops_vars["Dropped Packets"].set(_fmt_count(dropped_packets))
        drop_rate_pct = drops.get("drop_rate_pct")
        if drop_rate_pct is None:
            totals = analysis.get("global_results", {}).get("global_stats", {}).get("totals", {})
            total_packets = totals.get("packets")
            if isinstance(dropped_packets, (int, float)) and isinstance(total_packets, (int, float)):
                denom = total_packets + dropped_packets
                drop_rate_pct = (dropped_packets / denom * 100) if denom else None
        drops_vars["Drop Rate"].set(_fmt_pct(drop_rate_pct))

        decode_vars = self.ti_capture_quality["kpi_vars_decode"]
        decode_vars["Decode Success"].set(_fmt_pct(decode.get("decode_success_rate")))
        decode_vars["Malformed Packets"].set(_fmt_count(decode.get("malformed_packets")))
        decode_vars["Truncated Packets"].set(_fmt_count(decode.get("truncated_packets")))
        decode_vars["Unknown L3"].set(_fmt_count(decode.get("unknown_l3_packets")))
        decode_vars["Unknown L4"].set(_fmt_count(decode.get("unknown_l4_packets")))
        decode_vars["Unsupported Link Types"].set(str(decode.get("unsupported_link_types", "n/a")))

        decode_rows = []
        for key, value in (decode or {}).items():
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                if isinstance(value, float) and not value.is_integer():
                    value_text = _fmt_number(value, 4)
                else:
                    value_text = _fmt_count(value)
                decode_rows.append((key, value_text))
        decode_rows.sort(key=lambda row: row[0])
        self._tree_set_rows(self.ti_capture_quality["tree_decode"], decode_rows)

        filtering_rows = []
        for key, value in (filtering or {}).items():
            if isinstance(value, dict):
                value_text = json.dumps(value)
            else:
                value_text = str(value)
            filtering_rows.append((key, value_text))
        filtering_rows.sort(key=lambda row: row[0])
        self._tree_set_rows(self.ti_capture_quality["tree_filtering"], filtering_rows)

        self._set_json_text(self.ti_capture_quality["json_text"], health if health else {})

    def _refresh_ti_traffic_overview(self, analysis):
        throughput = analysis.get("global_results", {}).get("throughput_peaks", {})
        throughput = throughput if isinstance(throughput, dict) else {}
        size_stats = analysis.get("global_results", {}).get("packet_size_stats", {})
        size_stats = size_stats if isinstance(size_stats, dict) else {}
        l2l3 = analysis.get("global_results", {}).get("l2_l3_breakdown", {})
        l2l3 = l2l3 if isinstance(l2l3, dict) else {}

        vars_throughput = self.ti_traffic_overview["kpi_vars_throughput"]
        vars_throughput["BPS Now"].set(_fmt_bps(throughput.get("bps_now")))
        vars_throughput["BPS Avg"].set(_fmt_bps(throughput.get("bps_avg")))
        vars_throughput["PPS Now"].set(_fmt_pps(throughput.get("pps_now")))
        vars_throughput["PPS Avg"].set(_fmt_pps(throughput.get("pps_avg")))
        vars_throughput["Peak BPS"].set(_fmt_bps(throughput.get("peak_bps")))
        vars_throughput["Peak PPS"].set(_fmt_pps(throughput.get("peak_pps")))
        vars_throughput["Peak BPS Time"].set(_fmt_ts_utc(throughput.get("peak_bps_timestamp")))
        vars_throughput["Peak PPS Time"].set(_fmt_ts_utc(throughput.get("peak_pps_timestamp")))

        throughput_rows = []
        if isinstance(throughput, dict):
            ordered_keys = [
                "bucket_ms",
                "bps_now",
                "bps_avg",
                "pps_now",
                "pps_avg",
                "peak_bps",
                "peak_pps",
                "peak_bps_timestamp",
                "peak_pps_timestamp",
                "peak_timestamp",
            ]
            keys = [key for key in ordered_keys if key in throughput]
            extra_keys = sorted(key for key in throughput.keys() if key not in ordered_keys)
            for key in keys + extra_keys:
                value = throughput.get(key)
                if key.endswith("_timestamp"):
                    value_text = _fmt_ts_utc(value)
                elif key.endswith("_bps") or "bps" in key:
                    value_text = _fmt_bps(value)
                elif key.endswith("_pps") or "pps" in key:
                    value_text = _fmt_pps(value)
                elif key.endswith("_ms") or key == "bucket_ms":
                    value_text = f"{value} ms" if value is not None else "n/a"
                else:
                    value_text = str(value)
                throughput_rows.append((key, value_text))
        self._tree_set_rows(self.ti_traffic_overview["tree_throughput"], throughput_rows)

        vars_sizes = self.ti_traffic_overview["kpi_vars_sizes"]
        captured = size_stats.get("captured_length", {}) if isinstance(size_stats, dict) else {}
        original = size_stats.get("original_length", {}) if isinstance(size_stats, dict) else {}
        fragments = size_stats.get("fragments", {}) if isinstance(size_stats, dict) else {}
        vars_sizes["Captured Len Min"].set(_fmt_bytes(captured.get("min")))
        vars_sizes["Captured Len Median"].set(_fmt_bytes(captured.get("median")))
        vars_sizes["Captured Len P95"].set(_fmt_bytes(captured.get("p95")))
        vars_sizes["Captured Len Max"].set(_fmt_bytes(captured.get("max")))
        vars_sizes["Original Len Min"].set(_fmt_bytes(original.get("min")))
        vars_sizes["Original Len Median"].set(_fmt_bytes(original.get("median")))
        vars_sizes["Original Len P95"].set(_fmt_bytes(original.get("p95")))
        vars_sizes["Original Len Max"].set(_fmt_bytes(original.get("max")))
        vars_sizes["IPv4 Fragments"].set(_fmt_count(fragments.get("ipv4_fragments")))
        vars_sizes["IPv6 Fragments"].set(_fmt_count(fragments.get("ipv6_fragments")))

        histogram_rows = []
        histogram = size_stats.get("histogram", {}) if isinstance(size_stats, dict) else {}
        if isinstance(histogram, dict):
            bucket_order = ["0-63", "64-127", "128-511", "512-1023", "1024-1514", "jumbo"]
            keys = [key for key in bucket_order if key in histogram]
            extra_keys = sorted(key for key in histogram.keys() if key not in bucket_order)
            for key in keys + extra_keys:
                histogram_rows.append((key, _fmt_count(histogram.get(key))))
        self._tree_set_rows(self.ti_traffic_overview["tree_histogram"], histogram_rows)

        l2l3_rows = []
        if isinstance(l2l3, dict):
            l2l3_order = [
                "ethernet_frames",
                "vlan_frames",
                "arp_packets",
                "icmp_packets",
                "icmpv6_packets",
                "multicast_packets",
                "broadcast_packets",
            ]
            keys = [key for key in l2l3_order if key in l2l3]
            extra_keys = sorted(key for key in l2l3.keys() if key not in l2l3_order)
            for key in keys + extra_keys:
                l2l3_rows.append((key, _fmt_count(l2l3.get(key))))
        self._tree_set_rows(self.ti_traffic_overview["tree_l2l3"], l2l3_rows)

        totals = analysis.get("global_results", {}).get("global_stats", {}).get("totals", {})
        totals = totals if isinstance(totals, dict) else {}
        totals_packets = totals.get("packets")
        if totals_packets is None:
            totals_packets = totals.get("packets_total")
        totals_bytes = totals.get("bytes")
        if totals_bytes is None:
            totals_bytes = totals.get("bytes_captured")
        if totals_bytes is None:
            totals_bytes = totals.get("bytes_captured_total")
        totals_duration = totals.get("duration_us")
        vars_totals = self.ti_traffic_overview["kpi_vars_totals"]
        vars_totals["Packets"].set(_fmt_count(totals_packets))
        vars_totals["Bytes"].set(_fmt_bytes(totals_bytes))
        vars_totals["Duration"].set(_fmt_duration_us(totals_duration))

        json_texts = self.ti_traffic_overview["json_texts"]
        self._set_json_text(json_texts["throughput_peaks"], throughput or {})
        self._set_json_text(json_texts["packet_size_stats"], size_stats or {})
        self._set_json_text(json_texts["l2_l3_breakdown"], l2l3 or {})

    def _refresh_ti_protocol_mix(self, analysis):
        protocol = analysis.get("global_results", {}).get("protocol_mix", {})
        protocol = protocol if isinstance(protocol, dict) else {}
        global_stats = analysis.get("global_results", {}).get("global_stats", {})
        global_stats = global_stats if isinstance(global_stats, dict) else {}

        totals = global_stats.get("totals", {})
        totals = totals if isinstance(totals, dict) else {}
        packets_total = totals.get("packets")
        if packets_total is None:
            packets_total = totals.get("packets_total")
        if packets_total is None:
            packets_total = global_stats.get("packets_total")

        bytes_captured = totals.get("bytes_captured")
        if bytes_captured is None:
            bytes_captured = totals.get("bytes_captured_total")
        if bytes_captured is None:
            bytes_captured = global_stats.get("bytes_captured_total")

        bytes_original = totals.get("bytes_original")
        if bytes_original is None:
            bytes_original = totals.get("bytes_original_total")
        if bytes_original is None:
            bytes_original = global_stats.get("bytes_original_total")

        duration_us = totals.get("duration_us")
        if duration_us is None:
            duration_us = global_stats.get("duration_us")

        vars_totals = self.ti_protocol_mix["kpi_vars_totals"]
        vars_totals["Packets"].set(_fmt_count(packets_total))
        vars_totals["Bytes Captured"].set(_fmt_bytes(bytes_captured))
        vars_totals["Bytes Original"].set(_fmt_bytes(bytes_original))
        vars_totals["Duration"].set(_fmt_duration_us(duration_us))

        counts = protocol.get("protocol_counts", {})
        counts = counts if isinstance(counts, dict) else {}
        count_rows = []
        for key in sorted(counts.keys()):
            count_rows.append((key, _fmt_count(counts.get(key))))
        self._tree_set_rows(self.ti_protocol_mix["tree_counts"], count_rows)

        percents = protocol.get("protocol_percentages", {})
        if not isinstance(percents, dict) or not percents:
            percents = {}
            denom = sum(counts.values()) if counts else 0
            for key, count in counts.items():
                pct = (count / denom * 100.0) if denom else None
                percents[key] = pct
        percent_rows = []
        for key in sorted(percents.keys()):
            percent_rows.append((key, _fmt_pct(percents.get(key))))
        self._tree_set_rows(self.ti_protocol_mix["tree_percentages"], percent_rows)

        misc_rows = []
        for key in sorted(protocol.keys()):
            if key in ("protocol_counts", "protocol_percentages"):
                continue
            value = protocol.get(key)
            if isinstance(value, (dict, list)):
                value_text = json.dumps(value)
            else:
                value_text = str(value)
            misc_rows.append((key, value_text))
        self._tree_set_rows(self.ti_protocol_mix["tree_misc"], misc_rows)

        distributions = global_stats.get("distributions", {})
        distributions = distributions if isinstance(distributions, dict) else {}

        def _render_distribution(tree_key, fallback_key):
            dist = distributions.get(tree_key)
            if not isinstance(dist, dict):
                dist = global_stats.get(fallback_key, {})
            dist = dist if isinstance(dist, dict) else {}
            denom = sum(dist.values()) if dist else 0
            rows = []
            for key in sorted(dist.keys()):
                count = dist.get(key)
                pct = (count / denom * 100.0) if denom else None
                rows.append((key, _fmt_count(count), _fmt_pct(pct)))
            self._tree_set_rows(self.ti_protocol_mix["dist_trees"][tree_key], rows)

        _render_distribution("ip_versions", "ip_versions")
        _render_distribution("l4_protocols", "l4_protocols")
        _render_distribution("tcp_flags", "tcp_flags")
        _render_distribution("decode_quality_flags", "quality_flags")

        json_texts = self.ti_protocol_mix["json_texts"]
        self._set_json_text(json_texts["protocol_mix"], protocol if protocol else {})
        self._set_json_text(json_texts["global_stats"], global_stats if global_stats else {})

    def _refresh_ti_flow_analytics(self, analysis):
        flow = analysis.get("global_results", {}).get("flow_analytics", {})
        flow = flow if isinstance(flow, dict) else {}
        summary = flow.get("summary", {}) if isinstance(flow, dict) else {}
        states = flow.get("states", {}) if isinstance(flow, dict) else {}

        vars_summary = self.ti_flow_analytics["kpi_vars_summary"]
        vars_summary["Total Flows"].set(_fmt_count(summary.get("total_flows")))
        vars_summary["New Flows/sec"].set(_fmt_number(summary.get("new_flows_per_sec")))
        vars_summary["Duration Median"].set(_fmt_duration_us(summary.get("duration_us_median")))
        vars_summary["Duration P95"].set(_fmt_duration_us(summary.get("duration_us_p95")))
        vars_summary["Bytes/Flow Avg"].set(_fmt_bytes(summary.get("bytes_per_flow_avg")))
        vars_summary["Bytes/Flow P95"].set(_fmt_bytes(summary.get("bytes_per_flow_p95")))

        def _build_dynamic_tree(container, items):
            for child in container.winfo_children():
                child.destroy()
            keys = set()
            for item in items:
                if isinstance(item, dict):
                    keys.update(item.keys())
            columns = sorted(keys) if keys else ["value"]
            tree = ttk.Treeview(container, columns=columns, show="headings", height=6)
            yscroll = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=yscroll.set)
            tree.pack(side="left", fill="both", expand=True)
            yscroll.pack(side="right", fill="y")
            for col in columns:
                tree.heading(col, text=col)
                tree.column(col, width=120, anchor="w")
            rows = []
            for item in items:
                if isinstance(item, dict):
                    row = []
                    for col in columns:
                        value = item.get(col)
                        if col in ("bytes", "bytes_captured_total", "bytes_original_total", "bytes_captured", "bytes_original"):
                            value = _fmt_bytes(value)
                        elif col in ("packets", "packets_total"):
                            value = _fmt_count(value)
                        elif col.endswith("_us") and isinstance(value, (int, float)):
                            value = _fmt_duration_us(value)
                        row.append(value)
                    rows.append(tuple(row))
                else:
                    rows.append((item,))
            self._tree_set_rows(tree, rows)
            return tree

        heavy = flow.get("heavy_hitters", {}) if isinstance(flow, dict) else {}
        top_by_bytes = heavy.get("top_by_bytes", []) if isinstance(heavy, dict) else []
        top_by_packets = heavy.get("top_by_packets", []) if isinstance(heavy, dict) else []
        self.ti_flow_analytics["heavy_top_bytes_tree"] = _build_dynamic_tree(
            self.ti_flow_analytics["heavy_top_bytes_container"],
            top_by_bytes or [],
        )
        self.ti_flow_analytics["heavy_top_packets_tree"] = _build_dynamic_tree(
            self.ti_flow_analytics["heavy_top_packets_container"],
            top_by_packets or [],
        )

        state_rows = []
        if isinstance(states, dict):
            for key in sorted(states.keys()):
                state_rows.append((key, _fmt_count(states.get(key))))
        self._tree_set_rows(self.ti_flow_analytics["tree_states"], state_rows)

        flow_summary = analysis.get("flow_results", {}).get("flow_summary", {})
        flow_summary = flow_summary if isinstance(flow_summary, dict) else {}
        flow_summary_container = self.ti_flow_analytics["flow_summary_container"]
        for child in flow_summary_container.winfo_children():
            child.destroy()

        flows = flow_summary.get("flows")
        if isinstance(flows, list) and flows:
            self.ti_flow_analytics["flow_summary_tree"] = _build_dynamic_tree(
                flow_summary_container,
                flows,
            )
        else:
            tree = self._make_tree(flow_summary_container, ("key", "value"), ("Key", "Value"))
            rows = []
            if isinstance(flow_summary, dict):
                for key in sorted(flow_summary.keys()):
                    if key == "flows":
                        continue
                    value = flow_summary.get(key)
                    if isinstance(value, (dict, list)):
                        value_text = json.dumps(value)
                    else:
                        value_text = str(value)
                    rows.append((key, value_text))
            self._tree_set_rows(tree, rows)
            self.ti_flow_analytics["flow_summary_tree"] = tree

        json_texts = self.ti_flow_analytics["json_texts"]
        self._set_json_text(json_texts["flow_analytics"], flow if flow else {})
        self._set_json_text(json_texts["flow_summary"], flow_summary if flow_summary else {})

    def _refresh_ti_tcp_health(self, analysis):
        handshake = analysis.get("global_results", {}).get("tcp_handshakes", {})
        handshake = handshake if isinstance(handshake, dict) else {}
        reliability = analysis.get("global_results", {}).get("tcp_reliability", {})
        reliability = reliability if isinstance(reliability, dict) else {}
        performance = analysis.get("global_results", {}).get("tcp_performance", {})
        performance = performance if isinstance(performance, dict) else {}

        vars_handshakes = self.ti_tcp_health["kpi_vars_handshakes"]
        vars_handshakes["Handshakes Total"].set(_fmt_count(handshake.get("handshakes_total")))
        vars_handshakes["Handshakes Complete"].set(_fmt_count(handshake.get("handshakes_complete")))
        vars_handshakes["Handshakes Incomplete"].set(_fmt_count(handshake.get("handshakes_incomplete")))
        vars_handshakes["Completion Rate"].set(_fmt_pct(handshake.get("completion_rate")))
        vars_handshakes["RTT Median (ms)"].set(_fmt_number(handshake.get("rtt_median_ms")))
        vars_handshakes["RTT P95 (ms)"].set(_fmt_number(handshake.get("rtt_p95_ms")))
        handshake_rows = []
        for key in sorted(handshake.keys()):
            if key in {
                "handshakes_total",
                "handshakes_complete",
                "handshakes_incomplete",
                "completion_rate",
                "rtt_median_ms",
                "rtt_p95_ms",
            }:
                continue
            value = handshake.get(key)
            if isinstance(value, (dict, list)):
                value_text = json.dumps(value)
            else:
                value_text = str(value)
            handshake_rows.append((key, value_text))
        self._tree_set_rows(self.ti_tcp_health["tree_handshake_extra"], handshake_rows)

        vars_reliability = self.ti_tcp_health["kpi_vars_reliability"]
        vars_reliability["Retransmissions"].set(_fmt_count(reliability.get("retransmissions")))
        vars_reliability["Retransmission Rate"].set(_fmt_pct(reliability.get("retransmission_rate")))
        vars_reliability["Out of Order"].set(_fmt_count(reliability.get("out_of_order")))
        vars_reliability["Out of Order Rate"].set(_fmt_pct(reliability.get("out_of_order_rate")))
        vars_reliability["Dup ACKs"].set(_fmt_count(reliability.get("dup_acks")))
        vars_reliability["Dup ACK Rate"].set(_fmt_pct(reliability.get("dup_ack_rate")))
        vars_reliability["RST Packets"].set(_fmt_count(reliability.get("rst_packets")))
        vars_reliability["RST Rate"].set(_fmt_pct(reliability.get("rst_rate")))
        reliability_rows = []
        for key in sorted(reliability.keys()):
            if key in {
                "retransmissions",
                "retransmission_rate",
                "out_of_order",
                "out_of_order_rate",
                "dup_acks",
                "dup_ack_rate",
                "rst_packets",
                "rst_rate",
            }:
                continue
            value = reliability.get(key)
            if isinstance(value, (dict, list)):
                value_text = json.dumps(value)
            else:
                value_text = str(value)
            reliability_rows.append((key, value_text))
        self._tree_set_rows(self.ti_tcp_health["tree_reliability_extra"], reliability_rows)

        vars_performance = self.ti_tcp_health["kpi_vars_performance"]
        vars_performance["Window Median"].set(_fmt_number(performance.get("window_median")))
        vars_performance["Window P95"].set(_fmt_number(performance.get("window_p95")))
        vars_performance["Zero Window"].set(_fmt_count(performance.get("zero_window")))
        vars_performance["MSS Top"].set(str(performance.get("mss_top_value", "n/a")))
        vars_performance["MSS Top %"].set(_fmt_pct(performance.get("mss_top_pct")))

        mss_container = self.ti_tcp_health["mss_container"]
        for child in mss_container.winfo_children():
            child.destroy()
        mss_list = performance.get("mss_top_k")
        if isinstance(mss_list, list) and mss_list:
            keys = set()
            for item in mss_list:
                if isinstance(item, dict):
                    keys.update(item.keys())
            columns = sorted(keys) if keys else ["value"]
            tree = ttk.Treeview(mss_container, columns=columns, show="headings", height=4)
            yscroll = ttk.Scrollbar(mss_container, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=yscroll.set)
            tree.pack(side="left", fill="both", expand=True)
            yscroll.pack(side="right", fill="y")
            for col in columns:
                tree.heading(col, text=col)
                tree.column(col, width=120, anchor="w")
            rows = []
            for item in mss_list:
                if isinstance(item, dict):
                    rows.append(tuple(item.get(col) for col in columns))
                else:
                    rows.append((item,))
            self._tree_set_rows(tree, rows)
            self.ti_tcp_health["mss_tree"] = tree
        else:
            tree = self._make_tree(mss_container, ("field", "value"), ("Field", "Value"))
            rows = [
                ("mss_top_value", performance.get("mss_top_value")),
                ("mss_top_pct", performance.get("mss_top_pct")),
            ]
            self._tree_set_rows(tree, rows)
            self.ti_tcp_health["mss_tree"] = tree

        perf_rows = []
        for key in sorted(performance.keys()):
            if key in {"window_median", "window_p95", "zero_window", "mss_top_value", "mss_top_pct", "mss_top_k"}:
                continue
            value = performance.get(key)
            if isinstance(value, (dict, list)):
                value_text = json.dumps(value)
            else:
                value_text = str(value)
            perf_rows.append((key, value_text))
        self._tree_set_rows(self.ti_tcp_health["tree_perf_extra"], perf_rows)

        json_texts = self.ti_tcp_health["json_texts"]
        self._set_json_text(json_texts["tcp_handshakes"], handshake if handshake else {})
        self._set_json_text(json_texts["tcp_reliability"], reliability if reliability else {})
        self._set_json_text(json_texts["tcp_performance"], performance if performance else {})

    def _refresh_ti_top_entities(self, analysis):
        top = analysis.get("global_results", {}).get("top_entities", {})
        top = top if isinstance(top, dict) else {}
        ip = top.get("ip_talkers", {}) if isinstance(top, dict) else {}
        mac = top.get("mac_talkers", {}) if isinstance(top, dict) else {}
        ports = top.get("ports", {}) if isinstance(top, dict) else {}

        def _build_dynamic_tree(container, items):
            for child in container.winfo_children():
                child.destroy()
            keys = set()
            for item in items:
                if isinstance(item, dict):
                    keys.update(item.keys())
            columns = sorted(keys) if keys else ["value"]
            tree = ttk.Treeview(container, columns=columns, show="headings", height=6)
            yscroll = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=yscroll.set)
            tree.pack(side="left", fill="both", expand=True)
            yscroll.pack(side="right", fill="y")
            for col in columns:
                tree.heading(col, text=col)
                tree.column(col, width=120, anchor="w")
            rows = []
            for item in items:
                if isinstance(item, dict):
                    row = []
                    for col in columns:
                        value = item.get(col)
                        if col in ("bytes", "bytes_total", "bytes_captured_total", "bytes_original_total"):
                            value = _fmt_bytes(value)
                        elif col in ("packets", "packets_total"):
                            value = _fmt_count(value)
                        elif col.endswith("_pct") or col.endswith("_percent"):
                            value = _fmt_pct(value)
                        row.append(value)
                    rows.append(tuple(row))
                else:
                    rows.append((item,))
            self._tree_set_rows(tree, rows)
            return tree

        self.ti_top_entities["ip_src_tree"] = _build_dynamic_tree(
            self.ti_top_entities["ip_src_container"],
            ip.get("top_src", []) if isinstance(ip, dict) else [],
        )
        self.ti_top_entities["ip_dst_tree"] = _build_dynamic_tree(
            self.ti_top_entities["ip_dst_container"],
            ip.get("top_dst", []) if isinstance(ip, dict) else [],
        )

        split_rows = []
        internal_external = ip.get("internal_external", {}) if isinstance(ip, dict) else {}
        if isinstance(internal_external, dict):
            for key in sorted(internal_external.keys()):
                value = internal_external.get(key)
                if key.endswith("_pct") or key.endswith("_percent"):
                    value_text = _fmt_pct(value)
                else:
                    value_text = str(value)
                split_rows.append((key, value_text))
        self._tree_set_rows(self.ti_top_entities["tree_ip_split"], split_rows)

        self.ti_top_entities["mac_src_tree"] = _build_dynamic_tree(
            self.ti_top_entities["mac_src_container"],
            mac.get("top_src", []) if isinstance(mac, dict) else [],
        )
        self.ti_top_entities["mac_dst_tree"] = _build_dynamic_tree(
            self.ti_top_entities["mac_dst_container"],
            mac.get("top_dst", []) if isinstance(mac, dict) else [],
        )

        tcp = ports.get("tcp", {}) if isinstance(ports, dict) else {}
        udp = ports.get("udp", {}) if isinstance(ports, dict) else {}
        self.ti_top_entities["tcp_ports_tree"] = _build_dynamic_tree(
            self.ti_top_entities["tcp_ports_container"],
            tcp.get("top_dst_ports", []) if isinstance(tcp, dict) else [],
        )
        self.ti_top_entities["udp_ports_tree"] = _build_dynamic_tree(
            self.ti_top_entities["udp_ports_container"],
            udp.get("top_dst_ports", []) if isinstance(udp, dict) else [],
        )

        json_texts = self.ti_top_entities["json_texts"]
        self._set_json_text(json_texts["top_entities"], top if top else {})
        self._set_json_text(json_texts["ip_talkers"], ip if ip else {})
        self._set_json_text(json_texts["mac_talkers"], mac if mac else {})
        self._set_json_text(json_texts["ports"], ports if ports else {})

    def _refresh_ti_security_signals(self, analysis):
        scan = analysis.get("global_results", {}).get("scan_signals", {})
        scan = scan if isinstance(scan, dict) else {}
        dns = analysis.get("global_results", {}).get("dns_anomalies", {})
        dns = dns if isinstance(dns, dict) else {}
        arp = analysis.get("global_results", {}).get("arp_lan_signals", {})
        arp = arp if isinstance(arp, dict) else {}

        def _kv_rows(obj, keys=None):
            rows = []
            if isinstance(obj, dict):
                iterable = keys if keys is not None else sorted(obj.keys())
                for key in iterable:
                    if key not in obj:
                        continue
                    value = obj.get(key)
                    if key.endswith("_pct") or key.endswith("_percent"):
                        value_text = _fmt_pct(value)
                    else:
                        value_text = str(value)
                    rows.append((key, value_text))
            return rows

        distinct_ports = scan.get("distinct_ports", {}) if isinstance(scan, dict) else {}
        ports_keys = ["src_ip", "max_count"]
        ports_rows = _kv_rows(distinct_ports, ports_keys + [k for k in sorted(distinct_ports.keys()) if k not in ports_keys])
        self._tree_set_rows(self.ti_security_signals["tree_distinct_ports"], ports_rows)

        distinct_ips = scan.get("distinct_ips", {}) if isinstance(scan, dict) else {}
        self._tree_set_rows(self.ti_security_signals["tree_distinct_ips"], _kv_rows(distinct_ips))

        syn_ratio = scan.get("tcp_syn_ratio", {}) if isinstance(scan, dict) else {}
        syn_keys = ["syn_count", "synack_count", "ratio", "ratio_note"]
        self._tree_set_rows(
            self.ti_security_signals["tree_syn_ratio"],
            _kv_rows(syn_ratio, syn_keys + [k for k in sorted(syn_ratio.keys()) if k not in syn_keys]),
        )

        scan_extra_rows = []
        for key in sorted(scan.keys()):
            if key in ("distinct_ports", "distinct_ips", "tcp_syn_ratio"):
                continue
            value = scan.get(key)
            if isinstance(value, (dict, list)):
                value_text = json.dumps(value)
            else:
                value_text = str(value)
            scan_extra_rows.append((key, value_text))
        self._tree_set_rows(self.ti_security_signals["tree_scan_extra"], scan_extra_rows)

        multiple_macs = arp.get("multiple_macs", {}) if isinstance(arp, dict) else {}
        multiple_rows = _kv_rows(multiple_macs, ["count"] + [k for k in sorted(multiple_macs.keys()) if k != "examples"])
        self._tree_set_rows(self.ti_security_signals["tree_multiple_macs"], multiple_rows)
        multiple_examples = multiple_macs.get("examples", []) if isinstance(multiple_macs, dict) else []

        def _build_dynamic_tree(container, items, limit=200):
            for child in container.winfo_children():
                child.destroy()
            if not items:
                tree = self._make_tree(container, ("value",), ("Value",))
                self._tree_set_rows(tree, [])
                return tree
            keys = set()
            for item in items[:limit]:
                if isinstance(item, dict):
                    keys.update(item.keys())
            columns = sorted(keys) if keys else ["value"]
            tree = ttk.Treeview(container, columns=columns, show="headings", height=6)
            yscroll = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=yscroll.set)
            tree.pack(side="left", fill="both", expand=True)
            yscroll.pack(side="right", fill="y")
            for col in columns:
                tree.heading(col, text=col)
                tree.column(col, width=120, anchor="w")
            rows = []
            for item in items[:limit]:
                if isinstance(item, dict):
                    rows.append(tuple(item.get(col) for col in columns))
                else:
                    rows.append((item,))
            self._tree_set_rows(tree, rows)
            return tree

        self.ti_security_signals["multiple_macs_tree"] = _build_dynamic_tree(
            self.ti_security_signals["multiple_macs_container"],
            multiple_examples,
        )

        arp_changes = arp.get("arp_changes", {}) if isinstance(arp, dict) else {}
        arp_rows = _kv_rows(arp_changes, ["count", "threshold"] + [k for k in sorted(arp_changes.keys()) if k not in ("top_changes",)])
        self._tree_set_rows(self.ti_security_signals["tree_arp_changes"], arp_rows)
        top_changes = arp_changes.get("top_changes", []) if isinstance(arp_changes, dict) else []
        self.ti_security_signals["arp_changes_tree"] = _build_dynamic_tree(
            self.ti_security_signals["arp_changes_container"],
            top_changes,
        )

        arp_extra_rows = []
        for key in sorted(arp.keys()):
            if key in ("multiple_macs", "arp_changes"):
                continue
            value = arp.get(key)
            if isinstance(value, (dict, list)):
                value_text = json.dumps(value)
            else:
                value_text = str(value)
            arp_extra_rows.append((key, value_text))
        self._tree_set_rows(self.ti_security_signals["tree_arp_extra"], arp_extra_rows)

        entropy = dns.get("entropy", {}) if isinstance(dns, dict) else {}
        entropy_rows = _kv_rows(entropy, ["count"] + [k for k in sorted(entropy.keys()) if k != "samples"])
        self._tree_set_rows(self.ti_security_signals["tree_entropy"], entropy_rows)
        entropy_samples = entropy.get("samples", []) if isinstance(entropy, dict) else []
        self.ti_security_signals["entropy_tree"] = _build_dynamic_tree(
            self.ti_security_signals["entropy_container"],
            entropy_samples,
        )

        long_labels = dns.get("long_labels", {}) if isinstance(dns, dict) else {}
        long_rows = _kv_rows(long_labels, ["count"] + [k for k in sorted(long_labels.keys()) if k != "samples"])
        self._tree_set_rows(self.ti_security_signals["tree_long_labels"], long_rows)
        long_samples = long_labels.get("samples", []) if isinstance(long_labels, dict) else []
        self.ti_security_signals["long_labels_tree"] = _build_dynamic_tree(
            self.ti_security_signals["long_labels_container"],
            long_samples,
        )

        nxdomain = dns.get("nxdomain", {}) if isinstance(dns, dict) else {}
        self._tree_set_rows(self.ti_security_signals["tree_nxdomain"], _kv_rows(nxdomain))

        dns_extra_rows = []
        for key in sorted(dns.keys()):
            if key in ("entropy", "long_labels", "nxdomain"):
                continue
            value = dns.get(key)
            if isinstance(value, (dict, list)):
                value_text = json.dumps(value)
            else:
                value_text = str(value)
            dns_extra_rows.append((key, value_text))
        self._tree_set_rows(self.ti_security_signals["tree_dns_extra"], dns_extra_rows)

        json_texts = self.ti_security_signals["json_texts"]
        self._set_json_text(json_texts["scan_signals"], scan if scan else {})
        self._set_json_text(json_texts["arp_lan_signals"], arp if arp else {})
        self._set_json_text(json_texts["dns_anomalies"], dns if dns else {})

    def _refresh_ti_time_series_chunking(self, analysis):
        raw_time_series = analysis.get("time_series", {})
        if isinstance(raw_time_series, dict):
            ts_obj = raw_time_series
        else:
            ts_obj = {}

        packet_chunks = ts_obj.get("packet_chunks")
        if packet_chunks is None:
            packet_chunks = analysis.get("packet_chunks", {})
        packet_chunks = packet_chunks if isinstance(packet_chunks, dict) else {}
        chunks = packet_chunks.get("chunks")
        if chunks is None:
            chunks = packet_chunks if isinstance(packet_chunks, list) else []
        chunks = chunks if isinstance(chunks, list) else []

        series = ts_obj.get("time_series") or ts_obj.get("series") or ts_obj.get("buckets")
        if series is None and isinstance(raw_time_series, list):
            series = raw_time_series
        if series is None:
            series = ts_obj.get("time_series", {}) or ts_obj
        points = []
        if isinstance(series, dict):
            if isinstance(series.get("buckets"), list):
                points = series.get("buckets")
            elif isinstance(series.get("series"), list):
                points = series.get("series")
            elif isinstance(series.get("time_series"), list):
                points = series.get("time_series")
            elif isinstance(series.get("points"), list):
                points = series.get("points")
            elif isinstance(series.get("data"), list):
                points = series.get("data")
            else:
                points = [{"bucket": key, "value": value} for key, value in series.items()]
        elif isinstance(series, list):
            points = series

        def _build_dynamic_tree(container, items):
            for child in container.winfo_children():
                child.destroy()
            keys = set()
            for item in items:
                if isinstance(item, dict):
                    keys.update(item.keys())
            if not keys:
                columns = ["value"]
            else:
                has_time = any(key in keys for key in ("timestamp_us", "start_us", "start", "bucket", "index", "idx"))
                if not has_time:
                    keys.add("index")
                columns = sorted(keys)
            tree = ttk.Treeview(container, columns=columns, show="headings", height=8)
            yscroll = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=yscroll.set)
            tree.pack(side="left", fill="both", expand=True)
            yscroll.pack(side="right", fill="y")
            for col in columns:
                tree.heading(col, text=col)
                tree.column(col, width=120, anchor="w")
            rows = []
            for idx, item in enumerate(items):
                if isinstance(item, dict):
                    if ("index" not in item) and ("idx" not in item) and ("bucket" not in item):
                        item = dict(item)
                        item.setdefault("index", idx)
                    rows.append(tuple(item.get(col) for col in columns))
                else:
                    rows.append((item,))
            self._tree_set_rows(tree, rows)
            return tree

        self.ti_time_series["series_tree"] = _build_dynamic_tree(
            self.ti_time_series["series_container"],
            points,
        )
        self.ti_time_series["chunks_tree"] = _build_dynamic_tree(
            self.ti_time_series["chunks_container"],
            chunks,
        )

        def _get_numeric(item, keys):
            for key in keys:
                value = item.get(key)
                if isinstance(value, (int, float)):
                    return value
            return 0

        def _top_chunks(items, metric_keys, top_n=3):
            indexed = []
            for idx, item in enumerate(items):
                if isinstance(item, dict):
                    metric = _get_numeric(item, metric_keys)
                    indexed.append((idx, metric, item))
            ranked = sorted(indexed, key=lambda x: (-x[1], x[0]))[:top_n]
            rows = []
            for rank, (idx, metric, item) in enumerate(ranked, start=1):
                label = item.get("start_us") or item.get("start") or item.get("bucket") or idx
                rows.append((rank, label, metric))
            return rows

        top_bytes_rows = _top_chunks(chunks, ["bytes", "bytes_captured", "bytes_total", "bytes_captured_total"])
        top_packets_rows = _top_chunks(chunks, ["packets", "packets_total"])
        for child in self.ti_time_series["top_bytes_container"].winfo_children():
            child.destroy()
        self.ti_time_series["top_bytes_tree"] = self._make_tree(
            self.ti_time_series["top_bytes_container"],
            ("rank", "chunk", "bytes"),
            ("Rank", "Chunk", "Bytes"),
        )
        self._tree_set_rows(
            self.ti_time_series["top_bytes_tree"],
            [(rank, chunk, _fmt_bytes(value)) for rank, chunk, value in top_bytes_rows],
        )
        for child in self.ti_time_series["top_packets_container"].winfo_children():
            child.destroy()
        self.ti_time_series["top_packets_tree"] = self._make_tree(
            self.ti_time_series["top_packets_container"],
            ("rank", "chunk", "packets"),
            ("Rank", "Chunk", "Packets"),
        )
        self._tree_set_rows(
            self.ti_time_series["top_packets_tree"],
            [(rank, chunk, _fmt_count(value)) for rank, chunk, value in top_packets_rows],
        )

        json_texts = self.ti_time_series["json_texts"]
        if isinstance(raw_time_series, (dict, list)):
            self._set_json_text(json_texts["time_series"], raw_time_series)
        else:
            self._set_json_text(json_texts["time_series"], ts_obj if ts_obj else {})
        self._set_json_text(json_texts["packet_chunks"], packet_chunks if packet_chunks else {})

    def download_capture(self):
        if not self.latest_packets:
            messagebox.showinfo("No capture", "No packets available to download.")
            return
        filename = filedialog.asksaveasfilename(
            title="Save capture data",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not filename:
            return
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.latest_packets, f, indent=2)
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))


if __name__ == "__main__":
    app = AsphaltApp()
    app.mainloop()
