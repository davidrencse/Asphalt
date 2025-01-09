# Asphalt Codebase Map

Last updated: 2026-01-23

This document gives a high-level map of the Asphalt codebase, with a focus on
the pipeline, objectives, and key functions/modules. It is meant to help a new
developer quickly understand how data flows through the system and where the
major responsibilities live.

## Objectives (Current Implementation)
- Deterministic packet processing: identical inputs should produce identical outputs.
- Support offline PCAP and PCAPNG loading, decoding, and analysis.
- Provide a plugin-style analysis pipeline that produces JSON reports.
- Provide basic UI options (CLI, HTTP server for a static UI, and a local Tk app).

## Architecture At A Glance
Primary data flow (offline):
PCAP/PCAPNG -> RawPacket -> DecodedPacket -> AnalysisEngine -> Analyzer results -> JSON report

Primary data flow (live, current tooling):
Capture backend -> packet queue -> RawPacket -> DecodedPacket -> UI/CLI display

Major components:
- Capture backends (live): src/capture
- Packet loaders (file): src/pcap_loader
- Data models: src/models, src/analysis/models.py
- Decoder: src/capture/packet_decoder.py
- Analysis engine + analyzers: src/analysis
- CLI entry points: src/asphalt_cli + run.py/asphalt.py
- UI entry points: ui_server.py, ui_app.py, ui/ (static), ui-react/ (React prototype)
