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


def make_flow_key(decoded: DecodedPacket) -> Optional[Tuple[str, FlowKey, Tuple[str, int, str, int]]]:
    if not decoded.src_ip or not decoded.dst_ip:
        return None
    if decoded.src_port is None or decoded.dst_port is None:
        return None
    if not decoded.ip_protocol:
        return None

    src_ip = decoded.src_ip
    dst_ip = decoded.dst_ip
    src_port = int(decoded.src_port)
    dst_port = int(decoded.dst_port)

    src_key = _endpoint_key(src_ip, src_port)
    dst_key = _endpoint_key(dst_ip, dst_port)
