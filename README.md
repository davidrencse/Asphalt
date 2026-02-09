# Asphalt

Asphalt is a Python-based packet capture, decode, and analysis toolkit with a CLI and an optional desktop UI. It supports live capture via Scapy, offline decoding of PCAP/PCAPNG files, and configurable analysis pipelines that emit JSON reports.

## Features
- Live packet capture with interface listing, BPF filters, and live stats
- Offline decode of PCAP/PCAPNG to table, JSON, or JSONL
- Live capture + decode stream in a single command
- Analysis engine with pluggable analyzers and JSON output
- Optional PySide6 desktop UI for capture, decode, and visual dashboards

## Requirements
- Python 3.8+
- Windows live capture: Npcap in WinPcap API-compatible mode (required by Scapy)
- Dependencies:
  - CLI/core: `click`, `scapy`
  - UI: `PySide6` (required), `matplotlib` (optional but recommended for charts)

## Install
From the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
```

If you only want the CLI without the UI:

```powershell
pip install -e .
```

## Quickstart (CLI)

List interfaces:

```powershell
asphalt capture --interface list
```

Start a capture (Ctrl+C to stop):

```powershell
asphalt capture --interface "Ethernet" --duration 10
```

Capture with a BPF filter:

```powershell
asphalt capture --interface "Ethernet" --filter "tcp port 80"
```

Decode a PCAP/PCAPNG file:

```powershell
asphalt decode capture.pcapng --limit 20
```

Decode to JSONL:

```powershell
asphalt decode capture.pcapng --format jsonl --output decoded.jsonl
```

Live capture + decode:

```powershell
asphalt capture-decode --interface "Ethernet" --limit 50
```

Run analysis and save a report:

```powershell
asphalt analyze capture.pcapng --output report.json
```

## Analyzer List
The built-in analyzer names include:
`abnormal_activity`, `arp_lan_signals`, `capture_health`, `dns_anomalies`, `flow_analytics`, `flow_summary`, `global_stats`, `l2_l3_breakdown`, `packet_chunks`, `packet_size_stats`, `protocol_mix`, `scan_signals`, `tcp_handshakes`, `tcp_performance`, `tcp_reliability`, `throughput_peaks`, `time_series`, `top_entities`.

To run a subset:

```powershell
asphalt analyze capture.pcapng --analyzers global_stats,flow_summary,protocol_mix
```

## Packet Filters
Both `decode` and `analyze` accept `--filter` expressions for decoded packets. Filters are evaluated against decoded fields (e.g., IPs, ports, protocol tags). See `src/utils/filtering.py` for supported fields and behavior.

## Desktop UI
Run the optional desktop UI:

```powershell
python ui_app.py
```

If `PySide6` is missing, the UI will exit with an install hint. If `matplotlib` is missing, charts will be disabled but the UI will still run.

## Entry Points
- `asphalt` CLI (installed via `pip install -e .`)
- `python run.py` or `python asphalt.py` (local launcher wrappers)

## Project Layout
- `src/`: Core capture, decode, analysis, and CLI modules
- `tests/`: Test suite
- `docs/`: Architecture and design notes
- `ui_app.py`: Desktop UI

## Notes
- Live capture generally requires administrator privileges.
- On Windows, ensure Npcap is installed and enabled for WinPcap API compatibility.
