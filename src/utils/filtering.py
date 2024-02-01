"""Filtering helpers for decoded packets and flows."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List

from analysis.osi import derive_osi_tags_from_decoded, derive_osi_tags_from_flow
from .filter_expr import build_predicate


_DNS_RCODE_MAP = {
    "nxdomain": 3,
}


def _normalize_tag(tag: str) -> str:
    return tag.lower()
