"""TCP handshake grouping analyzer."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@dataclass
class _Handshake:
    flow_id: str
    initiator: Optional[str] = None
    responder: Optional[str] = None
    syn_ts: Optional[int] = None
    synack_ts: Optional[int] = None
    ack_ts: Optional[int] = None
    syn_src: Optional[str] = None
    syn_dst: Optional[str] = None
    syn_port: Optional[int] = None
    syn_dst_port: Optional[int] = None


@register_analyzer
class TcpHandshakeAnalyzer(Analyzer):
    name = "tcp_handshakes"
    version = "1.0"

    def __init__(self):
        self.handshakes: Dict[str, _Handshake] = {}

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        if packet.ip_protocol != 6 and packet.l4_protocol != "TCP":
            return
        if flow_state is None:
            return

        flags = packet.tcp_flags or 0
        is_syn = bool(flags & 0x02)
        is_ack = bool(flags & 0x10)
