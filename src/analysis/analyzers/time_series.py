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
