"""Throughput and peaks analyzer derived from time buckets."""
from __future__ import annotations

from typing import Dict, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@register_analyzer
class ThroughputPeaksAnalyzer(Analyzer):
    name = "throughput_peaks"
    version = "1.0"

    def __init__(self, bucket_ms: int = 1000):
        self.bucket_us = max(1, bucket_ms) * 1000
        self.buckets: Dict[int, Dict[str, int]] = {}

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        ts = packet.timestamp_us
        if ts <= 0:
            return
        start = ts - (ts % self.bucket_us)
        bucket = self.buckets.setdefault(start, {"packets": 0, "bytes_captured": 0})
        bucket["packets"] += 1
        bucket["bytes_captured"] += packet.captured_length

    def on_end(self, context) -> AnalyzerResult:
        if not self.buckets:
            return AnalyzerResult(
                analyzer=self.name,
                global_results={
                    "bucket_ms": self.bucket_us // 1000,
                    "bps_now": 0.0,
                    "bps_avg": 0.0,
                    "pps_now": 0.0,
                    "pps_avg": 0.0,
                    "peak_bps": 0.0,
                    "peak_pps": 0.0,
                    "peak_bps_timestamp": None,
                    "peak_pps_timestamp": None,
                    "peak_timestamp": None,
                },
            )
