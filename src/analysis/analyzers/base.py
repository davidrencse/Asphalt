"""Analyzer base class."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from ..models import AnalysisPacket, AnalyzerResult, FlowKey

class Analyzer(ABC):
    name = "base"
    version = "0.1"

    def on_start(self, context) -> None:
        return None
