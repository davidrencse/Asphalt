"""L2/L3 breakdown analyzer."""
from __future__ import annotations

from typing import Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@register_analyzer
class L2L3BreakdownAnalyzer(Analyzer):
    name = "l2_l3_breakdown"
    version = "1.0"

    def __init__(self):
        self.ethernet_frames = 0
        self.vlan_frames = 0
        self.arp_packets = 0
        self.icmp_packets = 0
        self.icmpv6_packets = 0
        self.multicast_packets = 0
        self.broadcast_packets = 0
