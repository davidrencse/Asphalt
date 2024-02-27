"""Flow key helpers."""
from __future__ import annotations

from ipaddress import ip_address
from typing import Optional, Tuple

try:
    from models.packet import DecodedPacket
except ImportError:
    from ..models.packet import DecodedPacket

from .models import Direction, FlowKey


def _endpoint_key(ip: str, port: int):
    try:
        return (ip_address(ip), port)
    except ValueError:
        return (ip, port)
