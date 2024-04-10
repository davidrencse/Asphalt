"""Time series analyzer."""
from __future__ import annotations

from typing import Dict, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey, TimeSeriesPoint
from ..registry import register_analyzer

@register_analyzer
class TimeSeriesAnalyzer(Analyzer):
    name = "time_series"
    version = "1.0"

    def __init__(self, bucket_ms: int = 1000):
        self.bucket_us = max(1, bucket_ms) * 1000
        self.buckets: Dict[int, Dict[str, int]] = {}

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        ts = packet.timestamp_us
        if ts <= 0:
            return
        start = ts - (ts % self.bucket_us)
        bucket = self.buckets.setdefault(start, {"packets": 0, "bytes_captured": 0, "bytes_original": 0})
        bucket["packets"] += 1
        bucket["bytes_captured"] += packet.captured_length
        bucket["bytes_original"] += packet.original_length
