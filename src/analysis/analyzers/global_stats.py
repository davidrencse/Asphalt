"""Global packet statistics analyzer."""
from __future__ import annotations

from typing import Dict, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer

@register_analyzer
class GlobalStatsAnalyzer(Analyzer):
    name = "global_stats"
    version = "1.0"

    def __init__(self):
        self.ip_versions: Dict[str, int] = {}
        self.l4_protocols: Dict[str, int] = {}
        self.quality_flags: Dict[str, int] = {}
        self.tcp_flags: Dict[str, int] = {}
