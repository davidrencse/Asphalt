"""DNS anomalies analyzer."""
from __future__ import annotations

from math import log2
from typing import Dict, List, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


def _entropy_score(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * log2(p)
    return entropy


@register_analyzer
class DnsAnomaliesAnalyzer(Analyzer):
    name = "dns_anomalies"
    version = "1.0"

    def __init__(self,
                 entropy_threshold: float = 3.5,
                 label_length_threshold: int = 40,
                 nxdomain_threshold_pct: float = 30.0,
                 min_responses: int = 10,
                 max_samples: int = 5):
        self.entropy_threshold = entropy_threshold
        self.label_length_threshold = label_length_threshold
        self.nxdomain_threshold_pct = nxdomain_threshold_pct
        self.min_responses = min_responses
        self.max_samples = max(1, max_samples)
        self.high_entropy: List[Dict[str, object]] = []
        self.long_labels: List[Dict[str, object]] = []
        self.nxdomain_count = 0
        self.total_responses = 0
