"""Analysis engine for decoded packets."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from .flow import make_flow_key, make_flow_key_from_fields
from .osi import count_tags, derive_osi_tags_from_analysis_packet, derive_osi_tags_from_decoded
from .models import AnalysisPacket, AnalysisReport, AnalyzerResult, FlowState
from .analyzers.base import Analyzer

@dataclass
class AnalysisContext:
    capture_path: Optional[str]
    stats: Dict[str, int]
    flow_table: Dict[str, FlowState]
    capture_info: Dict[str, object]
    osi_tags: List[List[str]]

class AnalysisEngine:
    def __init__(self,
                 analyzers: List[Analyzer],
                 capture_path: Optional[str] = None,
                 capture_info: Optional[Dict[str, object]] = None):
        self.analyzers = analyzers
        self.context = AnalysisContext(
            capture_path=capture_path,
            stats={
                "packets_total": 0,
                "bytes_captured_total": 0,
                "bytes_original_total": 0,
                "first_ts_us": 0,
                "last_ts_us": 0,
                "duration_us": 0,
            },
            flow_table={},
            capture_info=capture_info or {},
            osi_tags=[],
        )
        for analyzer in self.analyzers:
            analyzer.on_start(self.context)
