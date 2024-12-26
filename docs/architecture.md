# Asphalt System Architecture Contract

## 1.1 Executive Summary
Asphalt is a production-grade network diagnostics platform combining Wireshark-level packet capture capabilities with an opinionated analytics and diagnostics layer. It provides full-fidelity packet capture, real-time protocol decoding, configurable analysis pipelines, and a unified diagnostic UI with interactive visualizations and actionable insights—transforming raw packet data into operational intelligence.

## 1.2 System Context Diagram
```
┌─────────────────────────────────────────────────────────────┐
│                    External Entities                         │
├─────────────┬──────────────┬──────────────┬─────────────────┤
│Network      │PCAP Import   │API Clients   │Administrator    │
│Interfaces   │(Files)       │(REST/WebSocket│(UI/CLI)        │
│             │              │)             │                 │
└──────┬──────┴───────┬──────┴──────┬───────┴─────────────────┘
       │              │             │
       ▼              ▼             ▼
┌─────────────────────────────────────────────────────────────┐
│                    Asphalt System Boundary                   │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────────┐  │
│  │Capture     │  │Analytics   │  │Diagnostics UI        │  │
│  │Engine      │◄─┤Pipeline    │◄─┤& API Gateway         │  │
│  └────────────┘  └────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 1.3 Component Diagram and Responsibilities

| Component | Inputs | Outputs | Responsibilities |
|-----------|--------|---------|------------------|
| **Elevated Capture Service** | Network interface config, BPF filters, rotation policies | Raw packets (PCAPNG), capture metadata, performance metrics | Privileged packet capture, BPF compilation, PCAPNG rotation, drop monitoring, hardware timestamping |
| **Packet Decoder** | Raw packets from queue, protocol definitions | Decoded packet objects, protocol metadata, error events | Protocol decoding (Ethernet→IP→TCP/UDP→application), checksum validation, reassembly, malformed packet handling |
| **Flow Tracker** | Decoded packets, flow timeout config | Flow records, session metadata, RTT calculations | TCP/UDP/ICMP flow identification, session state tracking, connection lifecycle events, flow termination detection |
| **Analysis Task Runner** | Decoded packets, flow records, task configurations | Analysis results, time-series data, diagnostic findings | Executes configured analysis modules (retransmission detection, latency spikes, protocol anomalies), produces normalized outputs |
| **Unified Parser** | Raw analysis outputs, normalization schema | Normalized records (JSON/Protobuf), schema version | Schema enforcement, data normalization, version compatibility, output validation |
| **Index Builder** | Decoded packets, flow records, user queries | Search indices, paging tokens, query results | Creates/searchable indices (timestamp, IP 5-tuple, protocol), supports pagination, index optimization |
| **Storage Manager** | PCAPNG files, indices, analysis results | Storage manifests, retention reports, integrity checks | Tiered storage management, rotation/retention policies, data integrity verification, archive operations |
| **API Gateway** | HTTP/REST requests, WebSocket connections, UI events | JSON/Protobuf responses, real-time events, UI state | Request routing, authentication/authorization, rate limiting, WebSocket management, API versioning |
| **Diagnostics UI** | User interactions, real-time data streams, configuration | Visualizations, alerts, reports, configuration changes | Interactive dashboards, graph rendering, drill-down navigation, explanation generation, configuration interface |
| **Metrics Collector** | Component events, performance data, system metrics | Time-series metrics, health status, alert conditions | Performance monitoring, SLA tracking, anomaly detection, observability data export |

## 1.4 Runtime Flows

### Flow A: Start/Stop Capture Sequence Diagram

```
User → API Gateway → Elevated Capture Service → Storage Manager → Index Builder
      ↓             ↓                           ↓                 ↓
    UI Updates   IPC Auth                    File Rotation     Index Updates
      ↓             ↓                           ↓                 ↓
WebSocket Events ← Metrics Streaming ← Capture Loop → Packet Processing
```

**Steps:**
1. **UI Request**: POST `/api/capture/start` with interface and filter
2. **Privileged Execution**: Capture service starts with elevated privileges
3. **Storage Setup**: Session manifest and PCAPNG file creation
