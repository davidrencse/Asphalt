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


class AsphaltApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Asphalt")
        self.geometry("1100x700")
        self.configure(bg="#0e1117")

        self.rows = []

        self._build_ui()

    def _build_ui(self):
        header = tk.Frame(self, bg="#0e1117")
        header.pack(fill="x", padx=20, pady=(20, 10))

        title = tk.Label(header, text="Asphalt Live Decode", fg="#e6edf3", bg="#0e1117",
                         font=("Segoe UI", 18, "bold"))
        title.pack(anchor="w")

        subtitle = tk.Label(header, text="Capture → Decode → UI (local)", fg="#9aa4b2", bg="#0e1117")
        subtitle.pack(anchor="w")

        controls = tk.Frame(self, bg="#151b23")
        controls.pack(fill="x", padx=20, pady=10)

        tk.Label(controls, text="Backend", fg="#9aa4b2", bg="#151b23").grid(row=0, column=0, padx=8, pady=8)
        self.backend_var = tk.StringVar(value="dummy")
        backend = ttk.Combobox(controls, textvariable=self.backend_var, values=["dummy", "scapy"], width=10)
        backend.grid(row=0, column=1, padx=8, pady=8)

        tk.Label(controls, text="Interface", fg="#9aa4b2", bg="#151b23").grid(row=0, column=2, padx=8, pady=8)
        self.interface_var = tk.StringVar(value="dummy0")
        tk.Entry(controls, textvariable=self.interface_var, width=15).grid(row=0, column=3, padx=8, pady=8)

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
        filter_entry = tk.Entry(controls, textvariable=self.filter_var, width=30)
        filter_entry.grid(row=1, column=1, columnspan=3, padx=8, pady=8, sticky="w")
        filter_entry.bind("<KeyRelease>", lambda e: self.apply_filter())

        self.status_var = tk.StringVar(value="Idle")
        status = tk.Label(controls, textvariable=self.status_var, fg="#f6c177", bg="#151b23")
        status.grid(row=1, column=4, columnspan=5, padx=8, pady=8, sticky="w")

        stats = tk.Frame(self, bg="#0e1117")
        stats.pack(fill="x", padx=20, pady=(0, 10))

        self.stat_packets = tk.StringVar(value="0")
        self.stat_ip = tk.StringVar(value="0 / 0")
        self.stat_l4 = tk.StringVar(value="0 / 0")
        self.stat_flows = tk.StringVar(value="0")

        self._stat_block(stats, "Packets", self.stat_packets, 0)
        self._stat_block(stats, "IPv4 / IPv6", self.stat_ip, 1)
        self._stat_block(stats, "TCP / UDP", self.stat_l4, 2)
        self._stat_block(stats, "Flows", self.stat_flows, 3)

        table_frame = tk.Frame(self, bg="#0e1117")
        table_frame.pack(fill="both", expand=True, padx=20, pady=10)

        columns = ("id", "time", "stack", "src", "dst", "ports", "l4", "flags", "quality")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=110 if col in ("src", "dst") else 90, anchor="w")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _stat_block(self, parent, label, var, column):
        block = tk.Frame(parent, bg="#151b23", padx=12, pady=8)
        block.grid(row=0, column=column, padx=8, pady=4, sticky="ew")
        tk.Label(block, text=label, fg="#9aa4b2", bg="#151b23").pack(anchor="w")
        tk.Label(block, textvariable=var, fg="#e6edf3", bg="#151b23", font=("Segoe UI", 12, "bold")).pack(anchor="w")

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
            self.rows = packets
            self.after(0, self.refresh_table)
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


if __name__ == "__main__":
    app = AsphaltApp()
    app.mainloop()
