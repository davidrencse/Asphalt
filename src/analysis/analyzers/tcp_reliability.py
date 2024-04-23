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
