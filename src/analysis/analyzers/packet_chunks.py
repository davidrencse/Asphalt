"""Packet chunk analyzer (count-based)."""
from __future__ import annotations

from typing import Dict, Optional, Set

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@register_analyzer
class PacketChunksAnalyzer(Analyzer):
    name = "packet_chunks"
    version = "1.0"
