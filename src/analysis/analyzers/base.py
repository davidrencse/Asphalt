"""Analyzer base class."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from ..models import AnalysisPacket, AnalyzerResult, FlowKey
