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
