"""Top entities analyzer: IP talkers, MAC talkers, and ports/services."""
from __future__ import annotations

from collections import defaultdict
from ipaddress import ip_address
from typing import Dict, Optional, Tuple, List

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer
from utils.oui_lookup import lookup_vendor


_SERVICE_MAP = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    993: "IMAPS",
    995: "POP3S",
    5353: "mDNS",
}


def _is_internal_ip(ip: str) -> bool:
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return True
    return False


def _sort_top(entries: Dict[str, Dict[str, int]], top_n: int) -> List[Tuple[str, Dict[str, int]]]:
    items = list(entries.items())
    items.sort(key=lambda item: (-item[1]["bytes"], -item[1]["packets"], item[0]))
    return items[:top_n]


@register_analyzer
class TopEntitiesAnalyzer(Analyzer):
    name = "top_entities"
    version = "1.0"

    def __init__(self, top_n: int = 5):
        self.top_n = max(1, top_n)
        self.src_ip: Dict[str, Dict[str, int]] = defaultdict(lambda: {"bytes": 0, "packets": 0})
        self.dst_ip: Dict[str, Dict[str, int]] = defaultdict(lambda: {"bytes": 0, "packets": 0})
        self.src_mac: Dict[str, Dict[str, int]] = defaultdict(lambda: {"bytes": 0, "packets": 0})
        self.dst_mac: Dict[str, Dict[str, int]] = defaultdict(lambda: {"bytes": 0, "packets": 0})
        self.tcp_ports: Dict[int, int] = defaultdict(int)
        self.udp_ports: Dict[int, int] = defaultdict(int)
        self.tcp_total = 0
        self.udp_total = 0
        self.total_bytes = 0
        self.total_packets = 0
        self.internal_bytes = 0
        self.internal_packets = 0
