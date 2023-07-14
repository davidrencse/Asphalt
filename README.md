# Asphalt

Asphalt is a packet capture, decode, and analysis toolkit. It captures live traffic via Scapy, decodes packets into records and runs an analysis pipeline suitable for dashboards or downstream tooling.

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
