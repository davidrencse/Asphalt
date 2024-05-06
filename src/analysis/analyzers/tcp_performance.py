"""TCP performance analyzer (window, zero-window, MSS distribution)."""
from __future__ import annotations

from collections import defaultdict
from typing import List, Optional, Dict

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


def _percentile(values: List[int], percent: float) -> Optional[float]:
    if not values:
        return None
    if len(values) == 1:
        return float(values[0])
    sorted_vals = sorted(values)
    position = (percent / 100.0) * (len(sorted_vals) - 1)
    lower = int(position)
    upper = min(lower + 1, len(sorted_vals) - 1)
    if lower == upper:
        return float(sorted_vals[lower])
    weight = position - lower
    return sorted_vals[lower] + (sorted_vals[upper] - sorted_vals[lower]) * weight


@register_analyzer
class TcpPerformanceAnalyzer(Analyzer):
    name = "tcp_performance"
    version = "1.0"

    def __init__(self, top_n: int = 3):
        self.top_n = max(1, top_n)
        self.windows: List[int] = []
        self.zero_window = 0
        self.mss_counts: Dict[int, int] = defaultdict(int)
        self.mss_total = 0
