"""Per-flow summary analyzer."""
from __future__ import annotations

from .base import Analyzer
from ..models import AnalyzerResult
from ..registry import register_analyzer

@register_analyzer
class FlowSummaryAnalyzer(Analyzer):
    name = "flow_summary"
    version = "1.0"

    def on_packet(self, packet, flow_key, flow_state, context) -> None:
        return None
