"""ARP/LAN attack signals."""
from __future__ import annotations

from typing import Dict, List, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@register_analyzer
class ArpLanSignalsAnalyzer(Analyzer):
    name = "arp_lan_signals"
    version = "1.0"
