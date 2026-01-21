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
    ttl = None

    offset = 0

    # L2 decoding based on link type
    if raw.link_type == DLT_EN10MB:
        protocol_stack.append("ETH")
        if cap_len < 14:
            quality |= DecodeQuality.MALFORMED_L2
            return DecodedPacket(
                raw_packet=raw,
                protocol_stack=tuple(protocol_stack),
                quality_flags=int(quality),
            )
        ethertype = struct.unpack_from("!H", data, 12)[0]
        offset = 14

        # VLAN tags (single or double)
        for _ in range(2):
            if ethertype in (ETH_TYPE_VLAN, ETH_TYPE_QINQ):
                if cap_len < offset + 4:
                    quality |= DecodeQuality.MALFORMED_L2
                    return DecodedPacket(
                        raw_packet=raw,
                        protocol_stack=tuple(protocol_stack + ["VLAN"]),
                        quality_flags=int(quality),
                    )
                protocol_stack.append("VLAN")
                ethertype = struct.unpack_from("!H", data, offset + 2)[0]
                offset += 4
            else:
                break

        if ethertype == ETH_TYPE_IPV4:
            ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality = _parse_ipv4(data, offset)
            quality |= l3_quality
            protocol_stack.append("IP4")
            if l4_offset is None:
                return _finalize(raw, protocol_stack, ip_version, src_ip, dst_ip, l4_protocol,
                                 ip_protocol, src_port, dst_port, tcp_flags, ttl, quality)
            l4_protocol, src_port, dst_port, tcp_flags, l4_quality = _parse_l4(data, l4_offset, ip_protocol)
            quality |= l4_quality
            if l4_protocol:
                protocol_stack.append(l4_protocol)
        elif ethertype == ETH_TYPE_IPV6:
            ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality = _parse_ipv6(data, offset)
            quality |= l3_quality
            protocol_stack.append("IP6")
            if l4_offset is None:
                return _finalize(raw, protocol_stack, ip_version, src_ip, dst_ip, l4_protocol,
                                 ip_protocol, src_port, dst_port, tcp_flags, ttl, quality)
            l4_protocol, src_port, dst_port, tcp_flags, l4_quality = _parse_l4(data, l4_offset, ip_protocol)
            quality |= l4_quality
            if l4_protocol:
                protocol_stack.append(l4_protocol)
        elif ethertype == ETH_TYPE_ARP:
            protocol_stack.append("ARP")
        else:
            quality |= DecodeQuality.UNKNOWN_L3

    elif raw.link_type == DLT_RAW:
        # Raw IP without L2 header
        if cap_len < 1:
            quality |= DecodeQuality.MALFORMED_L3
            return DecodedPacket(raw_packet=raw, quality_flags=int(quality))
        version = data[0] >> 4
        if version == 4:
            ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality = _parse_ipv4(data, 0)
            quality |= l3_quality
            protocol_stack.append("IP4")
        elif version == 6:
            ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality = _parse_ipv6(data, 0)
            quality |= l3_quality
            protocol_stack.append("IP6")
        else:
            quality |= DecodeQuality.UNKNOWN_L3
            l4_offset = None
        if l4_offset is not None:
            l4_protocol, src_port, dst_port, tcp_flags, l4_quality = _parse_l4(data, l4_offset, ip_protocol)
            quality |= l4_quality
            if l4_protocol:
                protocol_stack.append(l4_protocol)

    elif raw.link_type == DLT_LINUX_SLL:
        protocol_stack.append("SLL")
        if cap_len < 16:
            quality |= DecodeQuality.MALFORMED_L2
            return DecodedPacket(raw_packet=raw, protocol_stack=tuple(protocol_stack), quality_flags=int(quality))
        ethertype = struct.unpack_from("!H", data, 14)[0]
        offset = 16
        if ethertype == ETH_TYPE_IPV4:
            ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality = _parse_ipv4(data, offset)
            quality |= l3_quality
            protocol_stack.append("IP4")
            if l4_offset is not None:
                l4_protocol, src_port, dst_port, tcp_flags, l4_quality = _parse_l4(data, l4_offset, ip_protocol)
                quality |= l4_quality
                if l4_protocol:
                    protocol_stack.append(l4_protocol)
        elif ethertype == ETH_TYPE_IPV6:
            ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality = _parse_ipv6(data, offset)
            quality |= l3_quality
            protocol_stack.append("IP6")
            if l4_offset is not None:
                l4_protocol, src_port, dst_port, tcp_flags, l4_quality = _parse_l4(data, l4_offset, ip_protocol)
                quality |= l4_quality
                if l4_protocol:
                    protocol_stack.append(l4_protocol)
        else:
            quality |= DecodeQuality.UNKNOWN_L3

    elif raw.link_type == DLT_NULL:
        if cap_len < 4:
            quality |= DecodeQuality.MALFORMED_L2
        else:
            family_le = struct.unpack_from("<I", data, 0)[0]
            family_be = struct.unpack_from(">I", data, 0)[0]
            family = family_le if family_le in (2, 24, 28, 30) else family_be
            offset = 4
            if family == 2:
                ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality = _parse_ipv4(data, offset)
                quality |= l3_quality
                protocol_stack.append("IP4")
            elif family in (24, 28, 30):
                ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality = _parse_ipv6(data, offset)
                quality |= l3_quality
                protocol_stack.append("IP6")
            else:
                quality |= DecodeQuality.UNKNOWN_L3
                l4_offset = None
            if l4_offset is not None:
                l4_protocol, src_port, dst_port, tcp_flags, l4_quality = _parse_l4(data, l4_offset, ip_protocol)
                quality |= l4_quality
                if l4_protocol:
                    protocol_stack.append(l4_protocol)

    else:
        quality |= DecodeQuality.UNSUPPORTED_LINKTYPE

    return _finalize(raw, protocol_stack, ip_version, src_ip, dst_ip, l4_protocol,
                     ip_protocol, src_port, dst_port, tcp_flags, ttl, quality)


def _finalize(raw: RawPacket,
              protocol_stack,
              ip_version: int,
              src_ip: Optional[str],
              dst_ip: Optional[str],
              l4_protocol: Optional[str],
              ip_protocol: int,
              src_port: Optional[int],
              dst_port: Optional[int],
              tcp_flags: Optional[int],
              ttl: Optional[int],
              quality: DecodeQuality) -> DecodedPacket:
    return DecodedPacket(
        raw_packet=raw,
        protocol_stack=tuple(protocol_stack),
        ip_version=ip_version,
        src_ip=src_ip,
        dst_ip=dst_ip,
        l4_protocol=l4_protocol,
        ip_protocol=ip_protocol,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        ttl=ttl,
        quality_flags=int(quality),
    )


def _parse_ipv4(data: bytes, offset: int) -> Tuple[int, Optional[str], Optional[str], int, Optional[int], Optional[int], DecodeQuality]:
    cap_len = len(data)
    if offset + 20 > cap_len:
        return 0, None, None, 0, None, None, DecodeQuality.MALFORMED_L3
    vihl = data[offset]
    version = vihl >> 4
    ihl = (vihl & 0x0F) * 4
    if version != 4 or ihl < 20:
        return 0, None, None, 0, None, None, DecodeQuality.MALFORMED_L3
    if offset + ihl > cap_len:
        return 0, None, None, 0, None, None, DecodeQuality.MALFORMED_L3

    ttl = data[offset + 8]
    ip_proto = data[offset + 9]
    src_ip = _format_ipv4(data[offset + 12:offset + 16])
    dst_ip = _format_ipv4(data[offset + 16:offset + 20])
    l4_offset = offset + ihl
    return 4, src_ip, dst_ip, ip_proto, ttl, l4_offset, DecodeQuality.OK


def _parse_ipv6(data: bytes, offset: int) -> Tuple[int, Optional[str], Optional[str], int, Optional[int], Optional[int], DecodeQuality]:
    cap_len = len(data)
    if offset + 40 > cap_len:
        return 0, None, None, 0, None, None, DecodeQuality.MALFORMED_L3
    version = data[offset] >> 4
    if version != 6:
        return 0, None, None, 0, None, None, DecodeQuality.MALFORMED_L3

    next_header = data[offset + 6]
    hop_limit = data[offset + 7]
    src_ip = _format_ipv6(data[offset + 8:offset + 24])
    dst_ip = _format_ipv6(data[offset + 24:offset + 40])

    l4_offset = offset + 40
    return 6, src_ip, dst_ip, next_header, hop_limit, l4_offset, DecodeQuality.OK


def _parse_l4(data: bytes, offset: int, ip_protocol: int) -> Tuple[Optional[str], Optional[int], Optional[int], Optional[int], DecodeQuality]:
    cap_len = len(data)

    if ip_protocol == IP_PROTO_TCP:
        if offset + 20 > cap_len:
            return None, None, None, None, DecodeQuality.MALFORMED_L4
        src_port, dst_port = struct.unpack_from("!HH", data, offset)
        data_offset = (data[offset + 12] >> 4) * 4
        if data_offset < 20 or offset + data_offset > cap_len:
            return "TCP", src_port, dst_port, None, DecodeQuality.MALFORMED_L4
        flags = data[offset + 13]
        return "TCP", src_port, dst_port, flags, DecodeQuality.OK

    if ip_protocol == IP_PROTO_UDP:
        if offset + 8 > cap_len:
            return None, None, None, None, DecodeQuality.MALFORMED_L4
        src_port, dst_port = struct.unpack_from("!HH", data, offset)
        return "UDP", src_port, dst_port, None, DecodeQuality.OK

    if ip_protocol == IP_PROTO_ICMP:
        return "ICMP", None, None, None, DecodeQuality.OK

    if ip_protocol == IP_PROTO_ICMPV6:
        return "ICMP6", None, None, None, DecodeQuality.OK

    return None, None, None, None, DecodeQuality.UNKNOWN_L4


def _format_ipv4(addr: bytes) -> Optional[str]:
    if len(addr) != 4:
        return None
    return "{}.{}.{}.{}".format(addr[0], addr[1], addr[2], addr[3])


def _format_ipv6(addr: bytes) -> Optional[str]:
    if len(addr) != 16:
        return None
    try:
        return str(ipaddress.IPv6Address(addr))
    except Exception:
        return None
