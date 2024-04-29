"""TCP reliability analyzer (retransmissions, out-of-order, dup ACKs, RST rate)."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Dict, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@dataclass
class _FlowReliabilityState:
    last_seen_us: int
    last_seq: Dict[str, int]
    recent_seqs: Dict[str, deque]
    last_ack: Dict[str, Optional[int]]
    last_ack_repeats: Dict[str, int]
    tcp_packets: int = 0
    retransmissions: int = 0
    out_of_order: int = 0
    dup_acks: int = 0
    rst_packets: int = 0


@register_analyzer
class TcpReliabilityAnalyzer(Analyzer):
    name = "tcp_reliability"
    version = "1.0"

    def __init__(self, max_flows: int = 10000, idle_timeout_us: int = 60_000_000, seq_window: int = 20):
        self.max_flows = max(1, max_flows)
        self.idle_timeout_us = max(0, idle_timeout_us)
        self.seq_window = max(1, seq_window)
        self.flows: Dict[str, _FlowReliabilityState] = {}
        self.total_tcp_packets = 0
        self.total_retransmissions = 0
        self.total_out_of_order = 0
        self.total_dup_acks = 0
        self.total_rst = 0

    def _purge(self, now_us: int) -> None:
        if self.idle_timeout_us and self.flows:
            stale = [fid for fid, state in self.flows.items()
                     if now_us - state.last_seen_us > self.idle_timeout_us]
            for fid in stale:
                del self.flows[fid]
        if len(self.flows) <= self.max_flows:
            return
        items = sorted(self.flows.items(), key=lambda kv: (kv[1].last_seen_us, kv[0]))
        for fid, _ in items[:len(self.flows) - self.max_flows]:
            del self.flows[fid]

    def _flow_state(self, flow_id: str, ts_us: int) -> _FlowReliabilityState:
        state = self.flows.get(flow_id)
        if state is None:
            state = _FlowReliabilityState(
                last_seen_us=ts_us,
                last_seq={"fwd": 0, "rev": 0},
                recent_seqs={"fwd": deque(maxlen=self.seq_window), "rev": deque(maxlen=self.seq_window)},
                last_ack={"fwd": None, "rev": None},
                last_ack_repeats={"fwd": 0, "rev": 0},
            )
            self.flows[flow_id] = state
        return state
