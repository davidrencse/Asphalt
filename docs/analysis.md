# Packet Analysis Subsystem

This document describes the offline packet-analysis subsystem that runs on decoded packets and produces JSON reports.

## Architecture

### Pipeline

1. Read packets from PCAP or PCAPNG (offline).
2. Decode packets to structured fields.
3. Analyze decoded packets using a plugin-style analyzer framework.
4. Emit a JSON AnalysisReport with global, per-flow, and optional time-series results.

### Components

- AnalysisEngine: streams decoded packets into analyzers and manages flow state.
- Analyzer plugins: independent modules that compute results (global, per-flow, time-series).
- Registry: maps analyzer names to implementations and enables selection via CLI.
- Models: AnalysisPacket, FlowKey, FlowState, AnalysisReport.

### Analyzer Contract

Each analyzer implements:

- on_start(context)
- on_packet(packet, flow_key, flow_state, context)
- on_end(context) -> AnalyzerResult

The engine merges analyzer results into the final report.
