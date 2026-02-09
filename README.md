# Asphalt

Asphalt is a packet capture, decode, and analysis toolkit with a CLI and an UI. It captures live traffic via Scapy, decodes packets into records and runs an analysis pipeline suitable for dashboards or downstream tooling.

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

## Desktop UI
Run the desktop UI:

```powershell
python ui_app.py
```

## Build EXE (Windows)
Build a single-file UI executable with PyInstaller:

```powershell
.\build_exe.ps1
```

Output:
- `dist/Asphalt.exe`

If you prefer the spec file:

```powershell
pyinstaller asphalt_ui.spec --noconfirm --clean --onefile --windowed
```

## Build Installer (Windows EXE Setup)
This uses Inno Setup to create a standard Windows installer.

1. Install Inno Setup.
2. Build the installer:

```powershell
.\build_installer.ps1
```

Output:
- `dist-installer\Asphalt-Setup.exe`

## End User Install (No Python Required)
Distribute `dist-installer\Asphalt-Setup.exe`. End users only need to run the installer and launch Asphalt from the Start Menu or desktop shortcut. If they plan to use live capture, they must also install Npcap in WinPcap API-compatible mode.

## Pipeline Overview
Asphalt is the same whether you run live capture, offline decode, or full analysis. The steps are modular and can be combined:

1. **Capture**
   - Live capture is performed via Scapy (`capture.scapy_backend`).
   - Capture configuration uses a `CaptureConfig` (interface, BPF filter, buffer).
   - A session is started and packet stats are sampled periodically.

2. **Decode**
   - Raw packets are decoded by `capture.decoder.PacketDecoder`.
   - Decoding extracts L2/L3/L4 fields (MAC/IP/ports), protocol stack summaries, and flags.
   - Decoded packets are converted to dictionaries for filtering or serialization.

3. **Filter (optional)**
   - Packet filters are compiled from an expression string (`utils.filtering`).
   - Filters run against decoded fields and OSI tags (L2/L3/L4/App).

4. **Analyze**
   - The analysis engine (`analysis.engine.AnalysisEngine`) consumes decoded packets.
   - A set of analyzers (registered in `analysis.registry`) produce metrics, summaries, and findings.
   - Results are serialized to JSON (`report.to_json()`).

## Backend Architecture
Asphalt is structured around a few core subsystems:

- **Capture backend**
  - `capture.scapy_backend.ScapyBackend` provides live capture, interface listing, and stats.
  - `capture.icapture_backend.CaptureConfig` defines capture parameters.

- **Packet decoding**
  - `capture.decoder.PacketDecoder` parses raw packet bytes into structured records.
  - Quality flags indicate decode confidence and anomalies.

- **PCAP/PCAPNG ingestion**
  - `pcap_loader.pcap_reader.PcapReader` and `pcap_loader.pcapng_reader.PcapngReader`
    stream packets from capture files.
  - The CLI auto-detects file formats by extension or magic bytes.

- **Analysis pipeline**
  - `analysis.engine.AnalysisEngine` orchestrates analyzer execution.
  - `analysis.registry` registers and instantiates analyzers.
  - Output is a normalized JSON report for programmatic use.

- **UI layer**
  - `ui_app.py` provides a PySide6 desktop UI.
  - The UI runs the same capture + decode + analysis pipeline and renders
    diagnostics and charts (via Matplotlib when available).

## Features

- **Live capture**
  - Start capture on any interface with optional BPF filters.
  - View per-interval statistics (packets/sec, totals, drops).
  - Stop at a fixed duration or with Ctrl+C.

- **Interface discovery**
  - List interfaces and identify the exact capture name (including NPF GUIDs on Windows).

- **Offline decode (PCAP/PCAPNG)**
  - Decode capture files into a readable table or JSON/JSONL.
  - Limit decode volume for quick inspection.

- **Live capture + decode**
  - Stream decoded summaries in real time while capturing.
  - Output as table, JSON, or JSONL.

- **Analysis engine**
  - Run a full analyzer suite on capture files.
  - Output structured JSON reports for downstream use or UI ingestion.

- **Pluggable analyzers**
  - Built-in analyzers can be selected by name.
  - Analyzer registry allows modular extension without changing core CLI.

- **Packet filters**
  - Filter decoded packets using expressions (e.g. by protocol, IPs, ports).
  - Applies to both decode and analyze commands.

- **Desktop UI (optional)**
  - Run the full pipeline with live diagnostics and charts.
  - UI gracefully degrades if Matplotlib is missing.

## CLIs

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
