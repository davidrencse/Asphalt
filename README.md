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
