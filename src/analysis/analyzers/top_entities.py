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
