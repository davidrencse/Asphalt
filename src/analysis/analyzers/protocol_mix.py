"""Protocol mix analyzer."""
from __future__ import annotations

from typing import Dict, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@register_analyzer
class ProtocolMixAnalyzer(Analyzer):
    name = "protocol_mix"
    version = "1.0"

    def __init__(self):
        self.counts: Dict[str, int] = {}
        self.total = 0
