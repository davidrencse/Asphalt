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


def _with_osi_fields(record: Dict[str, Any]) -> Dict[str, Any]:
    tags = record.get("osi_tags")
    if not tags:
        tags = derive_osi_tags_from_decoded(record)
    tags = [_normalize_tag(t) for t in tags]
    enriched = dict(record)
    enriched["osi_tags"] = tags
    # OSI lenses
    enriched["l2"] = [t.split(":", 1)[1] for t in tags if t.startswith("l2:")]
    enriched["l3"] = [t.split(":", 1)[1] for t in tags if t.startswith("l3:")]
    enriched["l4"] = [t.split(":", 1)[1] for t in tags if t.startswith("l4:")]
    enriched["app"] = [t.split(":", 1)[1] for t in tags if t.startswith("app:")]
    # Aliases
    enriched["tcp_flag"] = [f.lower() for f in (record.get("tcp_flags_names") or [])]
    if record.get("dns_rcode") is not None:
        enriched["dns_rcode"] = record.get("dns_rcode")
    return enriched


def _normalize_dns_rcode(value: Any) -> Any:
    if isinstance(value, str):
        return _DNS_RCODE_MAP.get(value.lower(), value)
    return value


def compile_packet_filter(expr: str):
    predicate = build_predicate(expr, value_normalizers={"dns_rcode": _normalize_dns_rcode})
