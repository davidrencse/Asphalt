"""Abnormal activity heuristics."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Set

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@dataclass
class _HandshakeState:
    syn_seen: bool = False
    synack_seen: bool = False
    ack_seen: bool = False


@register_analyzer
class AbnormalActivityAnalyzer(Analyzer):
    name = "abnormal_activity"
    version = "1.0"

    def __init__(self, scan_port_threshold: int = 20, rst_ratio_threshold: float = 0.2):
        self.scan_port_threshold = scan_port_threshold
        self.rst_ratio_threshold = rst_ratio_threshold
        self.malformed_packets = 0
        self.truncated_packets = 0
        self.tcp_packets = 0
        self.tcp_rst_packets = 0
        self.tcp_syn_packets = 0
        self.tcp_synack_packets = 0
        self.tcp_ack_packets = 0
        self.per_src_ports: Dict[str, Set[int]] = {}
        self.flow_handshakes: Dict[str, _HandshakeState] = {}
