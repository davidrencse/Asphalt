"""Packet chunk analyzer (count-based)."""
from __future__ import annotations

from typing import Dict, Optional, Set

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@register_analyzer
class PacketChunksAnalyzer(Analyzer):
    name = "packet_chunks"
    version = "1.0"

    def __init__(self, chunk_size: int = 200):
        self.chunk_size = max(1, chunk_size)
        self.current = None
        self.chunks = []

    def _start_chunk(self, packet: AnalysisPacket) -> None:
        self.current = {
            "start_us": packet.timestamp_us,
            "end_us": packet.timestamp_us,
            "packets": 0,
            "bytes_captured": 0,
            "bytes_original": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "malformed_packets": 0,
            "flows": set(),
        }

    def _finalize_chunk(self) -> None:
        if not self.current:
            return
        payload = dict(self.current)
        payload["flows"] = len(payload["flows"])
        self.chunks.append(payload)
        self.current = None
