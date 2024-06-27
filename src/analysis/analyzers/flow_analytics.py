"""Flow analytics summary, heavy hitters, and flow state classification."""
from __future__ import annotations

from typing import Dict, List, Optional

from .base import Analyzer
from ..models import AnalyzerResult
from ..registry import register_analyzer


def _percentile(values: List[int], percent: float) -> Optional[float]:
    if not values:
        return None
    if len(values) == 1:
        return float(values[0])
    sorted_vals = sorted(values)
    position = (percent / 100.0) * (len(sorted_vals) - 1)
    lower = int(position)
    upper = min(lower + 1, len(sorted_vals) - 1)
    if lower == upper:
        return float(sorted_vals[lower])
    weight = position - lower
    return sorted_vals[lower] + (sorted_vals[upper] - sorted_vals[lower]) * weight


def _flow_label(flow) -> str:
    return f"{flow.a_ip}:{flow.a_port} -> {flow.b_ip}:{flow.b_port}"


@register_analyzer
class FlowAnalyticsAnalyzer(Analyzer):
    name = "flow_analytics"
    version = "1.0"

    def __init__(self, top_n: int = 5):
        self.top_n = max(1, top_n)

    def on_packet(self, packet, flow_key, flow_state, context) -> None:
        return None

    def _heavy_hitters(self, flows, key: str) -> List[Dict[str, object]]:
        sorted_flows = sorted(
            flows,
            key=lambda f: (-getattr(f, key), -f.packets_total, f.flow_id)
        )
        hitters = []
        for flow in sorted_flows[:self.top_n]:
            hitters.append({
                "flow_id": flow.flow_id,
                "label": _flow_label(flow),
                "protocol": flow.ip_protocol,
                "bytes": flow.bytes_captured_total,
                "packets": flow.packets_total,
                "duration_us": flow.duration_us(),
            })
        return hitters

    def _flow_states(self, flows) -> Dict[str, int]:
        states = {
            "tcp_established": 0,
            "tcp_half_open": 0,
            "tcp_reset_failed": 0,
            "udp_paired": 0,
            "udp_unpaired": 0,
        }
        for flow in flows:
            if flow.ip_protocol == 6 or flow.tcp_seen:
                if flow.tcp_rst_seen:
                    states["tcp_reset_failed"] += 1
                elif flow.tcp_syn_seen and flow.tcp_synack_seen and flow.tcp_ack_seen:
                    states["tcp_established"] += 1
                elif flow.tcp_syn_seen:
                    states["tcp_half_open"] += 1
            elif flow.ip_protocol == 17 or flow.udp_seen:
                if flow.has_fwd and flow.has_rev:
                    states["udp_paired"] += 1
                else:
                    states["udp_unpaired"] += 1
        return states
