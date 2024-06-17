"""Capture health and integrity analyzer."""
from __future__ import annotations

from typing import Dict, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@register_analyzer
class CaptureHealthAnalyzer(Analyzer):
    name = "capture_health"
    version = "1.0"

    def __init__(self):
        self.total_packets = 0
        self.decode_ok = 0
        self.malformed = 0
        self.truncated = 0
        self.unknown_l3 = 0
        self.unknown_l4 = 0
        self.unsupported_link = 0
        self.first_ts = None
        self.last_ts = None
        self.link_types = set()

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        self.total_packets += 1
        if self.first_ts is None or packet.timestamp_us < self.first_ts:
            self.first_ts = packet.timestamp_us
        if self.last_ts is None or packet.timestamp_us > self.last_ts:
            self.last_ts = packet.timestamp_us
        if packet.link_type:
            self.link_types.add(packet.link_type)

        if packet.quality_flags == 0:
            self.decode_ok += 1
        else:
            self.malformed += 1
            if packet.quality_flags & (1 << 0):
                self.truncated += 1
            if packet.quality_flags & (1 << 1):
                self.unsupported_link += 1
            if packet.quality_flags & (1 << 5):
                self.unknown_l3 += 1
            if packet.quality_flags & (1 << 6):
                self.unknown_l4 += 1

    def on_end(self, context) -> AnalyzerResult:
        duration = None
        if self.first_ts is not None and self.last_ts is not None:
            duration = max(0, self.last_ts - self.first_ts)

        capture_info = context.capture_info or {}
        session_info = {
            "capture_start_us": self.first_ts,
            "capture_end_us": self.last_ts,
            "duration_us": duration,
            "link_types": sorted(self.link_types) if self.link_types else capture_info.get("link_types"),
            "snaplen": capture_info.get("snaplen"),
            "promiscuous": capture_info.get("promisc"),
            "capture_filter": capture_info.get("capture_filter"),
            "sampling_rate": capture_info.get("sampling_rate"),
        }
