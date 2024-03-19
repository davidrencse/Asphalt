"""Analyzer registry."""
from __future__ import annotations

from typing import Dict, List, Type

from .analyzers.base import Analyzer

_REGISTRY: Dict[str, Type[Analyzer]] = {}


def register_analyzer(cls: Type[Analyzer]) -> Type[Analyzer]:
    _REGISTRY[cls.name] = cls
    return cls
