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
