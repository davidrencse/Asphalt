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

    def _record_stats(self, packet: AnalysisPacket) -> None:
        stats = self.context.stats
        stats["packets_total"] += 1
        stats["bytes_captured_total"] += packet.captured_length
        stats["bytes_original_total"] += packet.original_length
        if stats["first_ts_us"] == 0 or packet.timestamp_us < stats["first_ts_us"]:
            stats["first_ts_us"] = packet.timestamp_us
        if packet.timestamp_us > stats["last_ts_us"]:
            stats["last_ts_us"] = packet.timestamp_us
        if stats["first_ts_us"] and stats["last_ts_us"]:
            stats["duration_us"] = max(0, stats["last_ts_us"] - stats["first_ts_us"])

    def process_packet(self, decoded) -> None:
        packet = AnalysisPacket.from_decoded(decoded)
        self._record_stats(packet)

        self.context.osi_tags.append(derive_osi_tags_from_decoded(decoded))

        flow_key_data = make_flow_key(decoded)
        flow_key = None
        flow_state = None
        if flow_key_data:
            flow_id, flow_key, endpoints = flow_key_data
            flow_state = self.context.flow_table.get(flow_id)
            if flow_state is None:
                a_ip, a_port, b_ip, b_port = endpoints
                flow_state = FlowState(
                    flow_id=flow_id,
                    a_ip=a_ip,
                    a_port=a_port,
                    b_ip=b_ip,
                    b_port=b_port,
                    ip_protocol=int(decoded.ip_protocol),
                    first_ts_us=packet.timestamp_us,
                    last_ts_us=packet.timestamp_us,
                )
                self.context.flow_table[flow_id] = flow_state
            flow_state.update_from_packet(packet, flow_key.direction)
