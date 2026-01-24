"""
Minimal UI server for Asphalt live capture decode viewer.

Usage:
  python ui_server.py --port 8000

Optional:
  python ui_server.py --backend dummy --interface dummy0 --duration 3 --limit 50
"""
import argparse
import json
import os
import subprocess
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
UI_DIR = PROJECT_ROOT / "ui"
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from analysis.engine import AnalysisEngine
from analysis.registry import create_analyzer


def run_capture(backend: str, interface: str, duration: int, limit: int):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_DIR)

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
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "capture failed")

    output = result.stdout.strip()
    if not output:
        return []
    return json.loads(output)


def run_analysis(packets, bucket_ms: int, chunk_size: int):
    analyzer_names = [
        "capture_health",
        "global_stats",
        "protocol_mix",
        "flow_summary",
        "flow_analytics",
        "tcp_handshakes",
        "abnormal_activity",
        "packet_chunks",
        "time_series",
        "throughput_peaks",
        "packet_size_stats",
        "l2_l3_breakdown",
        "top_entities",
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
    report = engine.finalize()
    return report.to_dict()


class UIHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PROJECT_ROOT), **kwargs)
    def do_GET(self):
        if self.path.startswith("/capture"):
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            params = {}
            for part in query.split("&"):
                if not part:
                    continue
                key, _, value = part.partition("=")
                params[key] = value

            backend = params.get("backend", self.server.defaults["backend"])
            interface = params.get("interface", self.server.defaults["interface"])
            duration = int(params.get("duration", self.server.defaults["duration"]))
            limit = int(params.get("limit", self.server.defaults["limit"]))
            include_analysis = params.get("analysis", "1") == "1"
            bucket_ms = int(params.get("bucket_ms", self.server.defaults["bucket_ms"]))
            chunk_size = int(params.get("chunk_size", self.server.defaults["chunk_size"]))

            try:
                packets = run_capture(backend, interface, duration, limit)
                payload_obj = {"packets": packets}
                if include_analysis:
                    payload_obj["analysis"] = run_analysis(packets, bucket_ms=bucket_ms, chunk_size=chunk_size)
                payload = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except Exception as exc:
                msg = str(exc).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)
            return

        if self.path == "/":
            self.path = "/ui/index.html"
        return super().do_GET()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--backend", default="dummy")
    parser.add_argument("--interface", default="dummy0")
    parser.add_argument("--duration", type=int, default=3)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--bucket-ms", type=int, default=1000)
    parser.add_argument("--chunk-size", type=int, default=200)
    args = parser.parse_args()

    os.chdir(PROJECT_ROOT)
    server = ThreadingHTTPServer(("0.0.0.0", args.port), UIHandler)
    server.defaults = {
        "backend": args.backend,
        "interface": args.interface,
        "duration": args.duration,
        "limit": args.limit,
        "bucket_ms": args.bucket_ms,
        "chunk_size": args.chunk_size,
    }

    print(f"UI server running on http://localhost:{args.port}")
    print("/capture will run asphalt capture-decode (full pipeline)")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server")


if __name__ == "__main__":
    main()
