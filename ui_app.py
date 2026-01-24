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

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from analysis.engine import AnalysisEngine
from analysis.registry import create_analyzer


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
        self.configure(bg="#0e1117")

        self.rows = []
        self.table_visible = True
        self.latest_packets = []

        self._build_ui()

    def _build_ui(self):
        container = tk.Frame(self, bg="#0e1117")
        container.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(container, bg="#0e1117", highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.content = tk.Frame(self.canvas, bg="#0e1117")
        self.canvas.create_window((0, 0), window=self.content, anchor="nw")
        self.content.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        header = tk.Frame(self.content, bg="#0e1117")
        header.pack(fill="x", padx=20, pady=(20, 10))

        title = tk.Label(header, text="Asphalt Live Decode", fg="#e6edf3", bg="#0e1117",
                         font=("Segoe UI", 20, "bold"))
        title.pack(anchor="w")

        subtitle = tk.Label(header, text="Capture -> Decode -> UI (local)", fg="#9aa4b2", bg="#0e1117")
        subtitle.pack(anchor="w")

        controls = tk.Frame(self.content, bg="#151b23")
        controls.pack(fill="x", padx=20, pady=10)

        tk.Label(controls, text="Backend", fg="#9aa4b2", bg="#151b23").grid(row=0, column=0, padx=8, pady=8)
        self.backend_var = tk.StringVar(value="dummy")
        backend = ttk.Combobox(controls, textvariable=self.backend_var, values=["dummy", "scapy"], width=10)
        backend.grid(row=0, column=1, padx=8, pady=8)

        tk.Label(controls, text="Interface", fg="#9aa4b2", bg="#151b23").grid(row=0, column=2, padx=8, pady=8)
        self.interface_var = tk.StringVar(value="dummy0")
        tk.Entry(controls, textvariable=self.interface_var, width=20).grid(row=0, column=3, padx=8, pady=8)

        tk.Label(controls, text="Duration (s)", fg="#9aa4b2", bg="#151b23").grid(row=0, column=4, padx=8, pady=8)
        self.duration_var = tk.StringVar(value="3")
        tk.Entry(controls, textvariable=self.duration_var, width=6).grid(row=0, column=5, padx=8, pady=8)

        tk.Label(controls, text="Limit", fg="#9aa4b2", bg="#151b23").grid(row=0, column=6, padx=8, pady=8)
        self.limit_var = tk.StringVar(value="50")
        tk.Entry(controls, textvariable=self.limit_var, width=6).grid(row=0, column=7, padx=8, pady=8)

        self.start_btn = tk.Button(controls, text="Start", command=self.start_capture, bg="#4fd1c5", fg="#0b0f12")
        self.start_btn.grid(row=0, column=8, padx=8, pady=8)

        self.download_btn = tk.Button(controls, text="Download", command=self.download_capture,
                                       bg="#151b23", fg="#e6edf3", state="disabled")
        self.download_btn.grid(row=0, column=9, padx=8, pady=8)

        tk.Label(controls, text="Filter", fg="#9aa4b2", bg="#151b23").grid(row=1, column=0, padx=8, pady=8)
        self.filter_var = tk.StringVar()
        filter_entry = tk.Entry(controls, textvariable=self.filter_var, width=35)
        filter_entry.grid(row=1, column=1, columnspan=3, padx=8, pady=8, sticky="w")
        filter_entry.bind("<KeyRelease>", lambda e: self.apply_filter())

        self.status_var = tk.StringVar(value="Idle")
        status = tk.Label(controls, textvariable=self.status_var, fg="#f6c177", bg="#151b23")
        status.grid(row=1, column=4, columnspan=5, padx=8, pady=8, sticky="w")

        stats = tk.Frame(self.content, bg="#0e1117")
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

        analysis = tk.Frame(self.content, bg="#0e1117")
        analysis.pack(fill="x", padx=20, pady=(0, 10))

        self._analysis_block(analysis, "Protocol Mix", self.analysis_protocol, 0)
        self._analysis_block(analysis, "Abnormal Activity", self.analysis_abnormal, 1)
        self._analysis_block(analysis, "TCP Handshakes", self.analysis_handshake, 2)
        self._analysis_block(analysis, "Packet Chunks", self.analysis_chunks, 3)

        self._build_capture_health_section()
        self._build_extra_sections()
        self._build_packet_table()

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _stat_block(self, parent, label, var, column):
        block = tk.Frame(parent, bg="#151b23", padx=12, pady=8)
        block.grid(row=0, column=column, padx=8, pady=4, sticky="ew")
        tk.Label(block, text=label, fg="#9aa4b2", bg="#151b23").pack(anchor="w")
        tk.Label(block, textvariable=var, fg="#e6edf3", bg="#151b23", font=("Segoe UI", 12, "bold")).pack(anchor="w")

    def _analysis_block(self, parent, label, var, column):
        block = tk.Frame(parent, bg="#151b23", padx=12, pady=8)
        block.grid(row=0, column=column, padx=8, pady=4, sticky="ew")
        tk.Label(block, text=label, fg="#9aa4b2", bg="#151b23").pack(anchor="w")
        tk.Label(block, textvariable=var, fg="#e6edf3", bg="#151b23", font=("Segoe UI", 10, "bold"),
                 justify="left", wraplength=220).pack(anchor="w")

    def _collapsible_section(self, parent, title, summary):
        frame = tk.Frame(parent, bg="#151b23", bd=1, relief="flat")
        header = tk.Frame(frame, bg="#111720")
        header.pack(fill="x")

        title_label = tk.Label(header, text=title, fg="#6ee7c8", bg="#111720", font=("Segoe UI", 10, "bold"))
        title_label.pack(side="left", padx=10, pady=6)

        summary_label = tk.Label(header, text=summary, fg="#9aa4b2", bg="#111720")
        summary_label.pack(side="left", padx=10)

        toggle = tk.Label(header, text="+", fg="#e6edf3", bg="#111720", font=("Segoe UI", 12, "bold"))
        toggle.pack(side="right", padx=10)

        body = tk.Frame(frame, bg="#151b23")
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
        card = tk.Frame(parent, bg="#0f141c", padx=10, pady=8, bd=1, relief="flat")
        card.grid(row=row, column=column, padx=8, pady=6, sticky="nsew")
        tk.Label(card, text=title, fg="#9aa4b2", bg="#0f141c", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        for line in lines:
            tk.Label(card, text=line, fg="#e6edf3", bg="#0f141c", font=("Segoe UI", 9)).pack(anchor="w")
        return card

    def _info_card_var(self, parent, title, var, column, row):
        card = tk.Frame(parent, bg="#0f141c", padx=10, pady=8, bd=1, relief="flat")
        card.grid(row=row, column=column, padx=8, pady=6, sticky="nsew")
        tk.Label(card, text=title, fg="#9aa4b2", bg="#0f141c", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(card, textvariable=var, fg="#e6edf3", bg="#0f141c",
                 font=("Segoe UI", 9), justify="left", wraplength=320).pack(anchor="w")
        return card

    def _build_capture_health_section(self):
        section = tk.Frame(self.content, bg="#0e1117")
        section.pack(fill="x", padx=20, pady=10)

        frame, body = self._collapsible_section(
            section,
            "Capture health and integrity",
            "Capture Quality · Decode Health · Filtering and Sampling"
        )
        frame.pack(fill="x", pady=6)

        grid = tk.Frame(body, bg="#151b23")
        grid.pack(fill="x")

        self._info_card_var(grid, "Capture Quality", self.analysis_capture_quality, 0, 0)
        self._info_card_var(grid, "Decode Health", self.analysis_decode_health, 1, 0)
        self._info_card_var(grid, "Filtering and Sampling", self.analysis_filtering, 2, 0)

        for c in range(3):
            grid.grid_columnconfigure(c, weight=1)

    def _build_extra_sections(self):
        sections = tk.Frame(self.content, bg="#0e1117")
        sections.pack(fill="x", padx=20, pady=10)

        frame, body = self._collapsible_section(
            sections,
            "Traffic overview",
            "Throughput · Packet Size Stats · L2/L3 Breakdown"
        )
        frame.pack(fill="x", pady=6)
        grid = tk.Frame(body, bg="#151b23")
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
        grid = tk.Frame(body, bg="#151b23")
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
        grid = tk.Frame(body, bg="#151b23")
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
        grid = tk.Frame(body, bg="#151b23")
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
        grid = tk.Frame(body, bg="#151b23")
        grid.pack(fill="x")
        self._info_card_var(grid, "Scan-like Behavior", self.analysis_scan_signals, 0, 0)
        self._info_card_var(grid, "DNS Anomalies", self.analysis_dns_anomalies, 1, 0)
        self._info_card_var(grid, "ARP and LAN Attacks", self.analysis_arp_lan, 2, 0)
        for c in range(3):
            grid.grid_columnconfigure(c, weight=1)

    def _extra_analysis_data(self):
        return []

    def _build_packet_table(self):
        header = tk.Frame(self.content, bg="#0e1117")
        header.pack(fill="x", padx=20, pady=(10, 4))

        tk.Label(header, text="Packet List", fg="#9aa4b2", bg="#0e1117",
                 font=("Segoe UI", 10, "bold")).pack(side="left")

        self.toggle_btn = tk.Button(header, text="Collapse Packet List", command=self.toggle_table,
                                    bg="#151b23", fg="#e6edf3")
        self.toggle_btn.pack(side="right")

        self.table_frame = tk.Frame(self.content, bg="#0e1117")
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
            self.rows = packets
            self.after(0, self.refresh_table)
            self.after(0, lambda: self.refresh_analysis(analysis))
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
