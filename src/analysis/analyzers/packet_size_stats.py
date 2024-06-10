"""Packet size statistics analyzer.

Uses exact storage for small inputs and P² streaming estimates for large inputs
to avoid unbounded memory while keeping median/p95 reasonably accurate.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

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


class _P2Quantile:
    """P² streaming quantile estimator (approximate)."""
    def __init__(self, quantile: float):
        self.quantile = quantile
        self.count = 0
        self.initial: List[float] = []
        self.n: List[int] = []
        self.np: List[float] = []
        self.dn: List[float] = []
        self.q: List[float] = []

    def add(self, value: float) -> None:
        self.count += 1
        if len(self.initial) < 5:
            self.initial.append(value)
            if len(self.initial) == 5:
                self.initial.sort()
                self.q = list(self.initial)
                self.n = [1, 2, 3, 4, 5]
                q = self.quantile
                self.np = [1, 1 + 2 * q, 1 + 4 * q, 3 + 2 * q, 5]
                self.dn = [0, q / 2, q, (1 + q) / 2, 1]
            return
