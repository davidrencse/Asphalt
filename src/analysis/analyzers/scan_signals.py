"""Scan-like behavior signals."""
from __future__ import annotations

from typing import Dict, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@register_analyzer
class ScanSignalsAnalyzer(Analyzer):
    name = "scan_signals"
    version = "1.0"

    def __init__(self, max_set_size: int = 1024):
        self.max_set_size = max(1, max_set_size)
        self.dst_ports: Dict[str, set] = {}
        self.dst_ips: Dict[str, set] = {}
        self.syn_count = 0
        self.synack_count = 0

    def _add_to_set(self, table: Dict[str, set], src_ip: str, value) -> None:
        entry = table.get(src_ip)
        if entry is None:
            entry = set()
            table[src_ip] = entry
        if len(entry) < self.max_set_size:
            entry.add(value)

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        if packet.src_ip and packet.dst_ip:
            self._add_to_set(self.dst_ips, packet.src_ip, packet.dst_ip)
        if packet.src_ip and packet.dst_port is not None:
            self._add_to_set(self.dst_ports, packet.src_ip, int(packet.dst_port))
