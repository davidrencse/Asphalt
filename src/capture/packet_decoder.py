"""
Pure packet decoding logic (L2/L3/L4 MVP).

This module is deterministic and best-effort:
- It never throws on malformed/truncated packets
- It returns quality flags to describe decode issues
- It only parses headers (no unbounded payload parsing)
"""
from __future__ import annotations

from enum import IntFlag
import ipaddress
import struct
from typing import Optional, Tuple

try:
    from ..models.packet import RawPacket, DecodedPacket
except ImportError:
    from models.packet import RawPacket, DecodedPacket

# Link type constants (libpcap DLT_*)
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12
DLT_LINUX_SLL = 113

# EtherType constants
ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_ARP = 0x0806
ETH_TYPE_IPV6 = 0x86DD
ETH_TYPE_VLAN = 0x8100
ETH_TYPE_QINQ = 0x88A8

# IP protocol numbers
IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
IP_PROTO_ICMPV6 = 58

class DecodeQuality(IntFlag):
    OK = 0
    TRUNCATED = 1 << 0
    UNSUPPORTED_LINKTYPE = 1 << 1
    MALFORMED_L2 = 1 << 2
    MALFORMED_L3 = 1 << 3
    MALFORMED_L4 = 1 << 4
    UNKNOWN_L3 = 1 << 5
    UNKNOWN_L4 = 1 << 6


def quality_flag_names(flags: int) -> Tuple[str, ...]:
    """Return decode quality flag names for display."""
    if flags == 0:
        return ("OK",)
    names = []
    for flag in DecodeQuality:
        if flag != DecodeQuality.OK and (flags & flag):
            names.append(flag.name)
    return tuple(names)


def decode_packet(raw: RawPacket) -> DecodedPacket:
    """Decode a RawPacket into a DecodedPacket (best-effort)."""
    data = raw.data or b""
    cap_len = len(data)

    quality = DecodeQuality.OK
    if raw.is_truncated or cap_len < raw.original_length:
        quality |= DecodeQuality.TRUNCATED

    protocol_stack = []
    ip_version = 0
    src_ip = None
    dst_ip = None
    l4_protocol = None
    ip_protocol = 0
    src_port = None
    dst_port = None
    tcp_flags = None
    tcp_seq = None
    tcp_ack = None
    tcp_window = None
    tcp_mss = None
    ttl = None
    l4_payload_offset = None
    tcp_header_len = None
    eth_type = None
    src_mac = None
    dst_mac = None
    is_vlan = False
    is_arp = False
    is_multicast = False
    is_broadcast = False
    is_ipv4_fragment = False
    is_ipv6_fragment = False
    arp_sender_ip = None
    arp_sender_mac = None
    dns_qname = None
    dns_is_query = None
    dns_is_response = None
    dns_rcode = None

    offset = 0

    # L2 decoding based on link type
    if raw.link_type == DLT_EN10MB:
        protocol_stack.append("ETH")
        if cap_len >= 6:
            dst_mac = data[0:6]
            is_broadcast = dst_mac == b"\xff\xff\xff\xff\xff\xff"
            is_multicast = (dst_mac[0] & 0x01) == 0x01 and not is_broadcast
        if cap_len >= 12:
            src_mac = data[6:12]
            dst_mac = data[0:6]
        src_mac = _format_mac(src_mac)
        dst_mac = _format_mac(dst_mac)
        if cap_len < 14:
            quality |= DecodeQuality.MALFORMED_L2
            return DecodedPacket(
                raw_packet=raw,
                protocol_stack=tuple(protocol_stack),
                quality_flags=int(quality),
            )
        ethertype = struct.unpack_from("!H", data, 12)[0]
        offset = 14
