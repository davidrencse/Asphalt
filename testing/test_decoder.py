"""
Tests for packet decoding MVP (L2/L3/L4).
Run with: python testing\test_decoder.py
"""
import os
import sys
import struct

# Add src to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_path = os.path.join(project_root, "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from models.packet import RawPacket
from capture.packet_decoder import decode_packet, DecodeQuality
from pcap_loader.packet_index import PacketIndexBuilder


def _build_ipv4_tcp_packet(
    src_ip=(192, 168, 1, 1),
    dst_ip=(8, 8, 8, 8),
    src_port=12345,
    dst_port=80,
    flags=0x12,  # SYN+ACK
):
    # Ethernet
    eth_dst = b"\xaa\xbb\xcc\xdd\xee\xff"
    eth_src = b"\x11\x22\x33\x44\x55\x66"
    eth_type = b"\x08\x00"  # IPv4

    # IPv4 header (20 bytes)
    version_ihl = 0x45
    dscp_ecn = 0
    total_length = 20 + 20  # IP header + TCP header
    identification = 0
    flags_fragment = 0
    ttl = 64
    protocol = 6  # TCP
    hdr_checksum = 0
    ip_header = struct.pack(
        "!BBHHHBBH4B4B",
        version_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        hdr_checksum,
        *src_ip,
        *dst_ip,
    )

    # TCP header (20 bytes)
    seq = 1
    ack = 0
    data_offset = 5  # 20 bytes
    offset_flags = (data_offset << 12) | flags
    window = 1024
    checksum = 0
    urg_ptr = 0
    tcp_header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_flags,
        window,
        checksum,
        urg_ptr,
    )

    return eth_dst + eth_src + eth_type + ip_header + tcp_header


def test_ipv4_tcp_decode():
    data = _build_ipv4_tcp_packet()
    pkt = RawPacket(
        packet_id=1,
        timestamp_us=1700000000000000,
        captured_length=len(data),
        original_length=len(data),
        link_type=1,  # DLT_EN10MB
        data=data,
        pcap_ref="0:0:0",
    )

    decoded = decode_packet(pkt)

    assert decoded.stack_summary == "ETH/IP4/TCP", f"stack_summary: {decoded.stack_summary}"
    assert decoded.ip_version == 4
    assert decoded.src_ip == "192.168.1.1"
    assert decoded.dst_ip == "8.8.8.8"
    assert decoded.l4_protocol == "TCP"
    assert decoded.src_port == 12345
    assert decoded.dst_port == 80
    assert decoded.tcp_flags == 0x12
    assert decoded.quality_flags == 0


def test_truncated_packet_sets_flags():
    data = _build_ipv4_tcp_packet()
    truncated = data[:30]
    pkt = RawPacket(
        packet_id=1,
        timestamp_us=1700000000000000,
        captured_length=len(truncated),
        original_length=len(data),
        link_type=1,
        data=truncated,
        pcap_ref="0:0:0",
    )

    decoded = decode_packet(pkt)
    assert decoded.quality_flags & DecodeQuality.TRUNCATED
    assert decoded.quality_flags & DecodeQuality.MALFORMED_L3


def test_index_enrichment():
    data = _build_ipv4_tcp_packet()
    pkt = RawPacket(
        packet_id=1,
        timestamp_us=1700000000000000,
        captured_length=len(data),
        original_length=len(data),
        link_type=1,
        data=data,
        pcap_ref="0:0:0",
    )
    decoded = decode_packet(pkt)
    builder = PacketIndexBuilder(session_id="test_session")

    record = builder.create_index_record(pkt, decoded=decoded)

    assert record.src_ip == "192.168.1.1"
    assert record.dst_ip == "8.8.8.8"
    assert record.src_port == 12345
    assert record.dst_port == 80
    assert record.protocol == 6
    assert record.stack_summary == "ETH/IP4/TCP"
    assert record.flags == 0x12


def test_decoded_to_dict_contract():
    data = _build_ipv4_tcp_packet()
    pkt = RawPacket(
        packet_id=1,
        timestamp_us=1700000000000000,
        captured_length=len(data),
        original_length=len(data),
        link_type=1,
        data=data,
        pcap_ref="0:0:0",
    )
    decoded = decode_packet(pkt)
    payload = decoded.to_dict()
    expected_keys = [
        "packet_id",
        "timestamp_us",
        "captured_length",
        "original_length",
        "link_type",
        "pcap_ref",
        "interface_id",
        "stack_summary",
        "ip_version",
        "src_ip",
        "dst_ip",
        "l4_protocol",
        "ip_protocol",
        "src_port",
        "dst_port",
        "tcp_flags",
        "tcp_flags_names",
        "ttl",
        "quality_flags",
        "quality_names",
        "flow_key",
    ]
    assert list(payload.keys()) == expected_keys
    assert payload["stack_summary"] == "ETH/IP4/TCP"
    assert payload["flow_key"] == ["192.168.1.1", "8.8.8.8", 12345, 80, 6]


def main():
    tests = [
        test_ipv4_tcp_decode,
        test_truncated_packet_sets_flags,
        test_index_enrichment,
        test_decoded_to_dict_contract,
    ]

    print("=" * 60)
    print("Testing packet decoding")
    print("=" * 60)

    all_passed = True
    for test in tests:
        try:
            test()
            print(f"\u2705 {test.__name__} passed")
        except AssertionError as e:
            print(f"\u274c {test.__name__} failed: {e}")
            all_passed = False
        except Exception as e:
            print(f"\u274c {test.__name__} crashed: {e}")
            all_passed = False

    print("=" * 60)
    if all_passed:
        print("\u2705 ALL TESTS PASSED")
    else:
        print("\u274c SOME TESTS FAILED")
    print("=" * 60)

    return all_passed


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
