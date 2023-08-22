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

        # VLAN tags (single or double)
        for _ in range(2):
            if ethertype in (ETH_TYPE_VLAN, ETH_TYPE_QINQ):
                is_vlan = True
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
        eth_type = ethertype

        if ethertype == ETH_TYPE_IPV4:
            ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality, is_ipv4_fragment = _parse_ipv4(data, offset)
            quality |= l3_quality
            protocol_stack.append("IP4")
            if l4_offset is None:
                return _finalize(raw, protocol_stack, ip_version, src_ip, dst_ip, l4_protocol,
                                 ip_protocol, src_port, dst_port, tcp_flags, ttl, quality,
                                 eth_type, src_mac, dst_mac, is_vlan, is_arp, is_multicast, is_broadcast,
                                 is_ipv4_fragment, is_ipv6_fragment,
                                 tcp_seq, tcp_ack, tcp_window, tcp_mss,
                                 arp_sender_ip, arp_sender_mac,
                                 dns_qname, dns_is_query, dns_is_response, dns_rcode)
            l4_protocol, src_port, dst_port, tcp_flags, tcp_seq, tcp_ack, tcp_window, tcp_mss, l4_payload_offset, tcp_header_len, l4_quality = _parse_l4(data, l4_offset, ip_protocol)
            quality |= l4_quality
            if l4_protocol:
                protocol_stack.append(l4_protocol)
        elif ethertype == ETH_TYPE_IPV6:
            ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality, is_ipv6_fragment = _parse_ipv6(data, offset)
            quality |= l3_quality
            protocol_stack.append("IP6")
            if l4_offset is None:
                return _finalize(raw, protocol_stack, ip_version, src_ip, dst_ip, l4_protocol,
                                 ip_protocol, src_port, dst_port, tcp_flags, ttl, quality,
                                 eth_type, src_mac, dst_mac, is_vlan, is_arp, is_multicast, is_broadcast,
                                 is_ipv4_fragment, is_ipv6_fragment,
                                 tcp_seq, tcp_ack, tcp_window, tcp_mss,
                                 arp_sender_ip, arp_sender_mac,
                                 dns_qname, dns_is_query, dns_is_response, dns_rcode)
            l4_protocol, src_port, dst_port, tcp_flags, tcp_seq, tcp_ack, tcp_window, tcp_mss, l4_payload_offset, tcp_header_len, l4_quality = _parse_l4(data, l4_offset, ip_protocol)
            quality |= l4_quality
            if l4_protocol:
                protocol_stack.append(l4_protocol)
        elif ethertype == ETH_TYPE_ARP:
            protocol_stack.append("ARP")
            is_arp = True
            arp_sender_mac, arp_sender_ip = _parse_arp(data, offset)
        else:
            quality |= DecodeQuality.UNKNOWN_L3

    elif raw.link_type == DLT_RAW:
        # Raw IP without L2 header
        if cap_len < 1:
            quality |= DecodeQuality.MALFORMED_L3
            return DecodedPacket(raw_packet=raw, quality_flags=int(quality))
        version = data[0] >> 4
        if version == 4:
            ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality, is_ipv4_fragment = _parse_ipv4(data, 0)
            quality |= l3_quality
            protocol_stack.append("IP4")
        elif version == 6:
            ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality, is_ipv6_fragment = _parse_ipv6(data, 0)
            quality |= l3_quality
            protocol_stack.append("IP6")
        else:
            quality |= DecodeQuality.UNKNOWN_L3
            l4_offset = None
        if l4_offset is not None:
            l4_protocol, src_port, dst_port, tcp_flags, tcp_seq, tcp_ack, tcp_window, tcp_mss, l4_payload_offset, tcp_header_len, l4_quality = _parse_l4(data, l4_offset, ip_protocol)
            quality |= l4_quality
            if l4_protocol:
                protocol_stack.append(l4_protocol)

    elif raw.link_type == DLT_LINUX_SLL:
        protocol_stack.append("SLL")
        if cap_len < 16:
            quality |= DecodeQuality.MALFORMED_L2
            return DecodedPacket(raw_packet=raw, protocol_stack=tuple(protocol_stack), quality_flags=int(quality))
        ethertype = struct.unpack_from("!H", data, 14)[0]
        eth_type = ethertype
        offset = 16
        if ethertype == ETH_TYPE_IPV4:
            ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality, is_ipv4_fragment = _parse_ipv4(data, offset)
            quality |= l3_quality
            protocol_stack.append("IP4")
            if l4_offset is not None:
                l4_protocol, src_port, dst_port, tcp_flags, tcp_seq, tcp_ack, tcp_window, tcp_mss, l4_payload_offset, tcp_header_len, l4_quality = _parse_l4(data, l4_offset, ip_protocol)
                quality |= l4_quality
                if l4_protocol:
                    protocol_stack.append(l4_protocol)
        elif ethertype == ETH_TYPE_IPV6:
            ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality, is_ipv6_fragment = _parse_ipv6(data, offset)
            quality |= l3_quality
            protocol_stack.append("IP6")
            if l4_offset is not None:
                l4_protocol, src_port, dst_port, tcp_flags, tcp_seq, tcp_ack, tcp_window, tcp_mss, l4_payload_offset, tcp_header_len, l4_quality = _parse_l4(data, l4_offset, ip_protocol)
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
                ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality, is_ipv4_fragment = _parse_ipv4(data, offset)
                quality |= l3_quality
                protocol_stack.append("IP4")
            elif family in (24, 28, 30):
                ip_version, src_ip, dst_ip, ip_protocol, ttl, l4_offset, l3_quality, is_ipv6_fragment = _parse_ipv6(data, offset)
                quality |= l3_quality
                protocol_stack.append("IP6")
            else:
                quality |= DecodeQuality.UNKNOWN_L3
                l4_offset = None
            if l4_offset is not None:
                l4_protocol, src_port, dst_port, tcp_flags, tcp_seq, tcp_ack, tcp_window, tcp_mss, l4_payload_offset, tcp_header_len, l4_quality = _parse_l4(data, l4_offset, ip_protocol)
                quality |= l4_quality
                if l4_protocol:
                    protocol_stack.append(l4_protocol)

    else:
        quality |= DecodeQuality.UNSUPPORTED_LINKTYPE

    # IP-level multicast/broadcast detection (fallback for non-ethernet sources)
    if dst_ip:
        try:
            ip_obj = ipaddress.ip_address(dst_ip)
            if ip_obj.is_multicast:
                is_multicast = True
            if ip_obj.version == 4 and dst_ip == "255.255.255.255":
                is_broadcast = True
        except Exception:
            pass

    if l4_protocol in ("UDP", "TCP"):
        dns_qname, dns_is_query, dns_is_response, dns_rcode = _maybe_parse_dns(
            data,
            l4_protocol,
            src_port,
            dst_port,
            payload_offset=l4_payload_offset,
            tcp_header_len=tcp_header_len,
        )

    return _finalize(raw, protocol_stack, ip_version, src_ip, dst_ip, l4_protocol,
                     ip_protocol, src_port, dst_port, tcp_flags, ttl, quality,
                     eth_type, src_mac, dst_mac, is_vlan, is_arp, is_multicast, is_broadcast,
                     is_ipv4_fragment, is_ipv6_fragment,
                     tcp_seq, tcp_ack, tcp_window, tcp_mss,
                     arp_sender_ip, arp_sender_mac,
                     dns_qname, dns_is_query, dns_is_response, dns_rcode)


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
              quality: DecodeQuality,
              eth_type: Optional[int],
              src_mac: Optional[str],
              dst_mac: Optional[str],
              is_vlan: bool,
              is_arp: bool,
              is_multicast: bool,
              is_broadcast: bool,
              is_ipv4_fragment: bool,
              is_ipv6_fragment: bool,
              tcp_seq: Optional[int],
              tcp_ack: Optional[int],
              tcp_window: Optional[int],
              tcp_mss: Optional[int],
              arp_sender_ip: Optional[str],
              arp_sender_mac: Optional[str],
              dns_qname: Optional[str],
              dns_is_query: Optional[bool],
              dns_is_response: Optional[bool],
              dns_rcode: Optional[int]) -> DecodedPacket:
    return DecodedPacket(
        raw_packet=raw,
        protocol_stack=tuple(protocol_stack),
        eth_type=eth_type,
        src_mac=src_mac,
        dst_mac=dst_mac,
        is_vlan=is_vlan,
        is_arp=is_arp,
        is_multicast=is_multicast,
        is_broadcast=is_broadcast,
        is_ipv4_fragment=is_ipv4_fragment,
        is_ipv6_fragment=is_ipv6_fragment,
        ip_version=ip_version,
        src_ip=src_ip,
        dst_ip=dst_ip,
        l4_protocol=l4_protocol,
        ip_protocol=ip_protocol,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        tcp_seq=tcp_seq,
        tcp_ack=tcp_ack,
        tcp_window=tcp_window,
        tcp_mss=tcp_mss,
        arp_sender_ip=arp_sender_ip,
        arp_sender_mac=arp_sender_mac,
        dns_qname=dns_qname,
        dns_is_query=dns_is_query,
        dns_is_response=dns_is_response,
        dns_rcode=dns_rcode,
        ttl=ttl,
        quality_flags=int(quality),
    )
