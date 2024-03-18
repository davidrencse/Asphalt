"""Analyzer registry."""
from __future__ import annotations

from typing import Dict, List, Type

from .analyzers.base import Analyzer

_REGISTRY: Dict[str, Type[Analyzer]] = {}
