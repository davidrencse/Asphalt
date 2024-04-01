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
