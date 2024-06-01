"""Capture health and integrity analyzer."""
from __future__ import annotations

from typing import Dict, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@register_analyzer
class CaptureHealthAnalyzer(Analyzer):
    name = "capture_health"
    version = "1.0"

    def __init__(self):
        self.total_packets = 0
        self.decode_ok = 0
        self.malformed = 0
        self.truncated = 0
        self.unknown_l3 = 0
        self.unknown_l4 = 0
        self.unsupported_link = 0
        self.first_ts = None
        self.last_ts = None
        self.link_types = set()
