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
from tkinter import ttk, messagebox

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
        "abnormal_activity",
        "packet_chunks",
        "time_series",
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


class AsphaltApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Asphalt")
        self.geometry("1200x820")
        self.configure(bg="#0e1117")

        self.rows = []
        self.table_visible = True

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

        data = self._extra_analysis_data()
        for section in data:
            frame, body = self._collapsible_section(sections, section["title"], section["summary"])
            frame.pack(fill="x", pady=6)
            grid = tk.Frame(body, bg="#151b23")
            grid.pack(fill="x")
            for idx, block in enumerate(section["blocks"]):
                col = idx % section["columns"]
                row = idx // section["columns"]
                self._info_card(grid, block["title"], block["lines"], col, row)
            for c in range(section["columns"]):
                grid.grid_columnconfigure(c, weight=1)

    def _extra_analysis_data(self):
        return [
            {
                "title": "Traffic overview",
                "summary": "Throughput 18.4 Mbps now · p95 1472B",
                "columns": 3,
                "blocks": [
                    {
                        "title": "Throughput",
                        "lines": [
                            "bps now: 18.4 Mbps",
                            "bps avg: 12.1 Mbps",
                            "pps now: 3,820",
                            "pps avg: 2,940",
                            "peak bps: 41.2 Mbps @ 14:20:54",
                            "peak pps: 6,900 @ 14:20:54",
                        ],
                    },
                    {
                        "title": "Packet Size Stats",
                        "lines": [
                            "min: 64B, median: 312B",
                            "p95: 1472B, max: 9014B",
                            "hist: 0-128B 32%",
                            "hist: 128-512B 44%",
                            "fragments: 2 (IPv4)",
                        ],
                    },
                    {
                        "title": "L2/L3 Breakdown",
                        "lines": [
                            "Ethernet: 1,362",
                            "VLAN: 24, ARP: 16",
                            "ICMP: 11, ICMPv6: 8",
                            "Multicast: 148, Broadcast: 42",
                        ],
                    },
                ],
            },
            {
                "title": "Top entities",
                "summary": "Top src 192.168.0.14 · TCP 443 62%",
                "columns": 3,
                "blocks": [
                    {
                        "title": "Top Talkers",
                        "lines": [
                            "src: 192.168.0.14 22.1MB",
                            "src: 192.168.0.12 8.6MB",
                            "dst: 8.8.8.8 3.2MB",
                            "dst: 34.120.32.2 10.2MB",
                            "Internal 62% / External 38%",
                        ],
                    },
                    {
                        "title": "Top MAC Addresses",
                        "lines": [
                            "CC:98:8B:2A:4C:11 21.4MB",
                            "B0:AA:36:14:9D:20 8.0MB",
                            "Vendors: Apple 44%",
                        ],
                    },
                    {
                        "title": "Top Ports and Services",
                        "lines": [
                            "TCP 443 (HTTPS) 62%",
                            "TCP 80 (HTTP) 12%",
                            "UDP 53 (DNS) 34%",
                            "UDP 5353 (mDNS) 24%",
                        ],
                    },
                ],
            },
            {
                "title": "Flow analytics",
                "summary": "Flows 132 · New 3.2/s",
                "columns": 3,
                "blocks": [
                    {
                        "title": "Flow Summary",
                        "lines": [
                            "total flows: 132",
                            "new flows/sec: 3.2",
                            "duration median: 2.1s",
                            "bytes/flow avg: 182KB",
                        ],
                    },
                    {
                        "title": "Heavy Hitters",
                        "lines": [
                            "192.168.0.14:53144 -> 34.120.32.2:443 9.1MB",
                            "192.168.0.12:51422 -> 52.43.112.8:443 6.2MB",
                            "Longest: SSDP 40.3s",
                        ],
                    },
                    {
                        "title": "Flow States",
                        "lines": [
                            "TCP Established: 44",
                            "TCP Half-open: 5",
                            "TCP Reset/Failed: 3",
                            "UDP Paired: 56",
                            "UDP Unpaired: 24",
                        ],
                    },
                ],
            },
            {
                "title": "TCP health and behavior",
                "summary": "Completion 90.7% · Retrans 2.1%",
                "columns": 3,
                "blocks": [
                    {
                        "title": "Handshake Detail",
                        "lines": [
                            "SYN: 58, SYN-ACK: 54",
                            "ACK: 49",
                            "Completion: 90.7%",
                            "RTT median: 28ms, p95: 120ms",
                        ],
                    },
                    {
                        "title": "Reliability Indicators",
                        "lines": [
                            "Retransmissions: 12 (2.1%)",
                            "Out-of-order: 7",
                            "Dup ACKs: 21",
                            "RST: 5 (0.9%)",
                        ],
                    },
                    {
                        "title": "TCP Performance Signals",
                        "lines": [
                            "Window median: 256KB",
                            "Window p95: 1.2MB",
                            "Zero-window: 0",
                            "MSS top: 1460 (82%)",
                        ],
                    },
                ],
            },
            {
                "title": "UDP and DNS insights",
                "summary": "UDP 2.4k pps · DNS response 96.8%",
                "columns": 3,
                "blocks": [
                    {
                        "title": "UDP Quality",
                        "lines": [
                            "rate: 2.4k pps / 9.1 Mbps",
                            "largest flow: 192.168.0.14 -> 224.0.0.251",
                            "burstiness: 0.62",
                        ],
                    },
                    {
                        "title": "DNS Dashboard",
                        "lines": [
                            "Queries: 221, Responses: 214",
                            "Response rate: 96.8%",
                            "NXDOMAIN: 6 (2.7%)",
                            "Avg latency: 18ms",
                        ],
                    },
                    {
                        "title": "Top Queried Domains",
                        "lines": [
                            "api.apple.com (44)",
                            "clients4.google.com (31)",
                            "time.cloudflare.com (18)",
                        ],
                    },
                ],
            },
            {
                "title": "Timing and burst detection",
                "summary": "Peak 6,900 pps · Jitter 1.1ms",
                "columns": 2,
                "blocks": [
                    {
                        "title": "Burst Monitor",
                        "lines": [
                            "Peak PPS: 6,900 @ 14:20:54",
                            "Peak BPS: 41.2 Mbps",
                            "Burst events: 7",
                        ],
                    },
                    {
                        "title": "Inter-arrival Stats",
                        "lines": [
                            "Median: 0.5ms",
                            "p95: 6.2ms",
                            "Jitter: 1.1ms",
                        ],
                    },
                ],
            },
            {
                "title": "Security and anomaly signals",
                "summary": "SYN:SYN-ACK 1.12 · ARP changes 1",
                "columns": 3,
                "blocks": [
                    {
                        "title": "Scan-like Behavior",
                        "lines": [
                            "Distinct dst ports/src: max 41",
                            "Distinct dst IPs/src: max 23",
                            "SYN:SYN-ACK ratio: 1.12",
                        ],
                    },
                    {
                        "title": "DNS Anomalies",
                        "lines": [
                            "High-entropy subdomains: 2",
                            "Long labels: 4",
                            "NXDOMAIN spike: None",
                        ],
                    },
                    {
                        "title": "ARP and LAN Attacks",
                        "lines": [
                            "IP claimed by multiple MACs: 0",
                            "Frequent ARP changes: 1",
                        ],
                    },
                ],
            },
            {
                "title": "Application metadata",
                "summary": "TLS 1.3 74% · HTTP GET 61%",
                "columns": 2,
                "blocks": [
                    {
                        "title": "TLS Handshake Metadata",
                        "lines": [
                            "SNI count: 24",
                            "Top SNI: api.apple.com (7)",
                            "ALPN: h2 68%, http/1.1 32%",
                            "TLS version: 1.3 74%",
                        ],
                    },
                    {
                        "title": "HTTP Plaintext",
                        "lines": [
                            "Hosts: 12",
                            "Methods: GET 61%, POST 24%",
                            "Status: 200 91%, 404 4%",
                            "Slowest: /upload 1.2s",
                        ],
                    },
                ],
            },
        ]

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
            self.rows = packets
            self.after(0, self.refresh_table)
            self.after(0, lambda: self.refresh_analysis(analysis))
            self.after(0, lambda: self.set_status(f"Loaded {len(packets)} packets"))
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


if __name__ == "__main__":
    app = AsphaltApp()
    app.mainloop()
