"""
Tests for offline analysis subsystem.
Run with: python testing\test_analysis.py
"""
import os
import sys

# Add src to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_path = os.path.join(project_root, "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from models.packet import RawPacket, DecodedPacket
from analysis.engine import AnalysisEngine
from analysis.analyzers.global_stats import GlobalStatsAnalyzer
from analysis.analyzers.time_series import TimeSeriesAnalyzer
from analysis.analyzers.protocol_mix import ProtocolMixAnalyzer
from analysis.analyzers.tcp_handshakes import TcpHandshakeAnalyzer
from analysis.analyzers.abnormal_activity import AbnormalActivityAnalyzer
from analysis.analyzers.packet_chunks import PacketChunksAnalyzer
from analysis.analyzers.capture_health import CaptureHealthAnalyzer
from analysis.analyzers.throughput_peaks import ThroughputPeaksAnalyzer
from analysis.analyzers.packet_size_stats import PacketSizeStatsAnalyzer
from analysis.analyzers.l2_l3_breakdown import L2L3BreakdownAnalyzer
from analysis.analyzers.top_entities import TopEntitiesAnalyzer
from analysis.analyzers.flow_analytics import FlowAnalyticsAnalyzer
from analysis.analyzers.tcp_reliability import TcpReliabilityAnalyzer
from analysis.analyzers.tcp_performance import TcpPerformanceAnalyzer


def _make_decoded(packet_id: int,
                  ts_us: int,
                  src_ip: str,
                  dst_ip: str,
                  src_port: int,
                  dst_port: int,
                  ip_proto: int = 6,
                  l4: str = "TCP",
                  ip_version: int = 4,
                  tcp_flags: int = 0x10,
                  ttl: int = 64,
                  captured_len: int = 60,
                  quality_flags: int = 0):
    data = b"\x00" * captured_len
    raw = RawPacket(
        packet_id=packet_id,
        timestamp_us=ts_us,
        captured_length=captured_len,
        original_length=captured_len,
        link_type=1,
        data=data,
        pcap_ref="0:0:0",
    )
    return DecodedPacket(
        raw_packet=raw,
        protocol_stack=("ETH", "IP4", l4),
        ip_version=ip_version,
        src_ip=src_ip,
        dst_ip=dst_ip,
        l4_protocol=l4,
        ip_protocol=ip_proto,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        ttl=ttl,
        quality_flags=quality_flags,
    )


def _packet_dict(packet_id: int,
                 ts_us: int,
                 captured_len: int,
                 original_len: int,
                 ip_version: int = 4,
                 ip_proto: int = 6,
                 src_ip: str = "10.0.0.1",
                 dst_ip: str = "10.0.0.2",
                 l4: str = "TCP",
                 src_mac: str = "00:1b:63:aa:bb:cc",
                 dst_mac: str = "00:1a:2b:11:22:33",
                 src_port: int = 1234,
                 dst_port: int = 80,
                 tcp_flags: int = None,
                 tcp_seq: int = None,
                 tcp_ack: int = None,
                 tcp_window: int = None,
                 tcp_mss: int = None,
                 is_vlan: bool = False,
                 is_arp: bool = False,
                 is_multicast: bool = False,
                 is_broadcast: bool = False,
                 is_ipv4_fragment: bool = False,
                 is_ipv6_fragment: bool = False):
    effective_tcp_flags = tcp_flags
    if effective_tcp_flags is None and l4 == "TCP":
        effective_tcp_flags = 0x10
    return {
        "packet_id": packet_id,
        "timestamp_us": ts_us,
        "captured_length": captured_len,
        "original_length": original_len,
        "link_type": 1,
        "eth_type": 0x0800,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "ip_version": ip_version,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ip_protocol": ip_proto,
        "l4_protocol": l4,
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_flags": effective_tcp_flags,
        "tcp_seq": tcp_seq,
        "tcp_ack": tcp_ack,
        "tcp_window": tcp_window,
        "tcp_mss": tcp_mss,
        "ttl": 64,
        "quality_flags": 0,
        "stack_summary": "ETH/IP4/TCP",
        "is_vlan": is_vlan,
        "is_arp": is_arp,
        "is_multicast": is_multicast,
        "is_broadcast": is_broadcast,
        "is_ipv4_fragment": is_ipv4_fragment,
        "is_ipv6_fragment": is_ipv6_fragment,
    }


def test_flow_state_direction_counts():
    engine = AnalysisEngine(analyzers=[])

    pkt1 = _make_decoded(
        packet_id=1,
        ts_us=1_000_000,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=80,
    )
    pkt2 = _make_decoded(
        packet_id=2,
        ts_us=1_100_000,
        src_ip="10.0.0.2",
        dst_ip="10.0.0.1",
        src_port=80,
        dst_port=1234,
    )

    engine.process_packet(pkt1)
    engine.process_packet(pkt2)

    assert len(engine.context.flow_table) == 1
    flow = list(engine.context.flow_table.values())[0]
    assert flow.packets_total == 2
    assert flow.packets_fwd == 1
    assert flow.packets_rev == 1
    assert flow.bytes_captured_total == 120


def test_global_stats_analyzer():
    analyzer = GlobalStatsAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])

    pkt1 = _make_decoded(
        packet_id=1,
        ts_us=2_000_000,
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=5555,
        dst_port=53,
        ip_proto=17,
        l4="UDP",
    )
    pkt2 = _make_decoded(
        packet_id=2,
        ts_us=2_500_000,
        src_ip="192.168.1.20",
        dst_ip="192.168.1.10",
        src_port=53,
        dst_port=5555,
        ip_proto=17,
        l4="UDP",
    )

    engine.process_packet(pkt1)
    engine.process_packet(pkt2)
    report = engine.finalize()

    stats = report.global_results["global_stats"]
    assert stats["packets_total"] == 2
    assert stats["bytes_captured_total"] == 120
    assert stats["ip_versions"]["4"] == 2
    assert stats["l4_protocols"]["UDP"] == 2


def test_time_series_analyzer():
    analyzer = TimeSeriesAnalyzer(bucket_ms=1000)
    engine = AnalysisEngine(analyzers=[analyzer])

    pkt1 = _make_decoded(
        packet_id=1,
        ts_us=1_000_000,
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        src_port=1,
        dst_port=2,
    )
    pkt2 = _make_decoded(
        packet_id=2,
        ts_us=1_500_000,
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        src_port=1,
        dst_port=2,
    )
    pkt3 = _make_decoded(
        packet_id=3,
        ts_us=2_100_000,
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        src_port=1,
        dst_port=2,
    )

    engine.process_packet(pkt1)
    engine.process_packet(pkt2)
    engine.process_packet(pkt3)
    report = engine.finalize()

    series = report.time_series["time_series"]["traffic"]
    assert len(series) == 2
    assert series[0]["start_us"] == 1_000_000
    assert series[0]["packets"] == 2
    assert series[1]["start_us"] == 2_000_000
    assert series[1]["packets"] == 1


def test_protocol_mix_percentages():
    analyzer = ProtocolMixAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])

    pkt1 = _make_decoded(
        packet_id=1,
        ts_us=1_000_000,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1111,
        dst_port=80,
        ip_proto=6,
        l4="TCP",
    )
    pkt2 = _make_decoded(
        packet_id=2,
        ts_us=1_100_000,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1111,
        dst_port=53,
        ip_proto=17,
        l4="UDP",
    )

    engine.process_packet(pkt1)
    engine.process_packet(pkt2)
    report = engine.finalize()

    mix = report.global_results["protocol_mix"]
    assert mix["protocol_counts"]["TCP"] == 1
    assert mix["protocol_counts"]["UDP"] == 1
    assert mix["protocol_percentages"]["TCP"] == 50.0


def test_tcp_handshake_grouping():
    analyzer = TcpHandshakeAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])

    syn = _make_decoded(
        packet_id=1,
        ts_us=1_000_000,
        src_ip="192.168.0.2",
        dst_ip="192.168.0.1",
        src_port=12345,
        dst_port=80,
        tcp_flags=0x02,  # SYN
    )
    synack = _make_decoded(
        packet_id=2,
        ts_us=1_050_000,
        src_ip="192.168.0.1",
        dst_ip="192.168.0.2",
        src_port=80,
        dst_port=12345,
        tcp_flags=0x12,  # SYN+ACK
    )
    ack = _make_decoded(
        packet_id=3,
        ts_us=1_060_000,
        src_ip="192.168.0.2",
        dst_ip="192.168.0.1",
        src_port=12345,
        dst_port=80,
        tcp_flags=0x10,  # ACK
    )

    engine.process_packet(syn)
    engine.process_packet(synack)
    engine.process_packet(ack)
    report = engine.finalize()

    summary = report.global_results["tcp_handshakes"]
    assert summary["handshakes_total"] == 1
    assert summary["handshakes_complete"] == 1
    handshakes = report.flow_results["tcp_handshakes"]["handshakes"]
    assert handshakes[0]["status"] == "complete"


def test_abnormal_activity_scan_and_syn_only():
    analyzer = AbnormalActivityAnalyzer(scan_port_threshold=3, rst_ratio_threshold=0.5)
    engine = AnalysisEngine(analyzers=[analyzer])

    syn1 = _make_decoded(
        packet_id=1,
        ts_us=1_000_000,
        src_ip="10.1.1.1",
        dst_ip="10.1.1.2",
        src_port=40000,
        dst_port=22,
        tcp_flags=0x02,
    )
    syn2 = _make_decoded(
        packet_id=2,
        ts_us=1_010_000,
        src_ip="10.1.1.1",
        dst_ip="10.1.1.2",
        src_port=40001,
        dst_port=23,
        tcp_flags=0x02,
    )
    syn3 = _make_decoded(
        packet_id=3,
        ts_us=1_020_000,
        src_ip="10.1.1.1",
        dst_ip="10.1.1.2",
        src_port=40002,
        dst_port=80,
        tcp_flags=0x02,
    )

    engine.process_packet(syn1)
    engine.process_packet(syn2)
    engine.process_packet(syn3)
    report = engine.finalize()

    findings = report.global_results["abnormal_activity"]["findings"]
    types = {item["type"] for item in findings}
    assert "possible_port_scan" in types
    assert "syn_without_reply" in types


def test_packet_chunks():
    analyzer = PacketChunksAnalyzer(chunk_size=2)
    engine = AnalysisEngine(analyzers=[analyzer])

    pkt1 = _make_decoded(1, 1_000_000, "1.1.1.1", "2.2.2.2", 1, 2)
    pkt2 = _make_decoded(2, 1_100_000, "1.1.1.1", "2.2.2.2", 1, 2)
    pkt3 = _make_decoded(3, 1_200_000, "1.1.1.1", "2.2.2.2", 1, 2)

    engine.process_packet(pkt1)
    engine.process_packet(pkt2)
    engine.process_packet(pkt3)
    report = engine.finalize()

    chunks = report.time_series["packet_chunks"]["chunks"]
    assert len(chunks) == 2
    assert chunks[0]["packets"] == 2
    assert chunks[1]["packets"] == 1


def test_capture_health_decode_stats():
    analyzer = CaptureHealthAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])

    pkt1 = _make_decoded(1, 1_000_000, "1.1.1.1", "2.2.2.2", 1, 2)
    pkt2 = _make_decoded(
        2,
        1_100_000,
        "1.1.1.1",
        "2.2.2.2",
        1,
        2,
        quality_flags=(1 << 3),
    )

    engine.process_packet(pkt1)
    engine.process_packet(pkt2)
    report = engine.finalize()

    health = report.global_results["capture_health"]
    decode = health["decode_health"]
    assert decode["decode_success_rate"] == 0.5
    assert decode["malformed_packets"] == 1


def test_throughput_peaks_empty():
    analyzer = ThroughputPeaksAnalyzer(bucket_ms=1000)
    engine = AnalysisEngine(analyzers=[analyzer])
    report = engine.finalize()
    summary = report.global_results["throughput_peaks"]
    assert summary["bps_now"] == 0.0
    assert summary["peak_bps_timestamp"] is None


def test_throughput_peaks_mixed():
    analyzer = ThroughputPeaksAnalyzer(bucket_ms=1000)
    engine = AnalysisEngine(analyzers=[analyzer])
    engine.process_packet_dict(_packet_dict(1, 1_000_000, 1000, 1000))
    engine.process_packet_dict(_packet_dict(2, 1_200_000, 1000, 1000))
    engine.process_packet_dict(_packet_dict(3, 2_000_000, 4000, 4000))
    report = engine.finalize()
    summary = report.global_results["throughput_peaks"]
    assert summary["bps_now"] == 32000.0
    assert summary["pps_now"] == 1.0
    assert summary["bps_avg"] == 24000.0
    assert summary["pps_avg"] == 1.5
    assert summary["peak_bps_timestamp"] == 2_000_000
    assert summary["peak_pps_timestamp"] == 1_000_000
    assert summary["peak_timestamp"] is None


def test_packet_size_stats_histogram_and_quantiles():
    analyzer = PacketSizeStatsAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])
    sizes = [60, 100, 200, 600, 1400, 1600]
    for idx, size in enumerate(sizes, start=1):
        engine.process_packet_dict(_packet_dict(idx, 1_000_000 + idx * 10, size, size))
    report = engine.finalize()
    stats = report.global_results["packet_size_stats"]
    captured = stats["captured_length"]
    assert captured["min"] == 60
    assert captured["max"] == 1600
    assert captured["median"] == 400.0
    assert captured["p95"] == 1550.0
    hist = stats["histogram"]
    assert hist["0-63"] == 1
    assert hist["64-127"] == 1
    assert hist["128-511"] == 1
    assert hist["512-1023"] == 1
    assert hist["1024-1514"] == 1
    assert hist["jumbo"] == 1


def test_packet_size_stats_empty():
    analyzer = PacketSizeStatsAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])
    report = engine.finalize()
    stats = report.global_results["packet_size_stats"]
    assert stats["captured_length"]["median"] is None
    assert stats["original_length"]["median"] is None
    assert stats["histogram"]["jumbo"] == 0


def test_packet_size_stats_fragments():
    analyzer = PacketSizeStatsAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])
    engine.process_packet_dict(_packet_dict(1, 1_000_000, 100, 100, is_ipv4_fragment=True))
    engine.process_packet_dict(_packet_dict(2, 1_100_000, 120, 120, is_ipv6_fragment=True))
    report = engine.finalize()
    fragments = report.global_results["packet_size_stats"]["fragments"]
    assert fragments["ipv4_fragments"] == 1
    assert fragments["ipv6_fragments"] == 1


def test_l2_l3_breakdown_counts():
    analyzer = L2L3BreakdownAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])
    engine.process_packet_dict(_packet_dict(1, 1_000_000, 100, 100, is_vlan=True))
    engine.process_packet_dict(_packet_dict(2, 1_010_000, 100, 100, ip_proto=1))
    engine.process_packet_dict(_packet_dict(3, 1_020_000, 100, 100, ip_proto=58))
    engine.process_packet_dict(_packet_dict(4, 1_030_000, 100, 100, is_arp=True))
    engine.process_packet_dict(_packet_dict(5, 1_040_000, 100, 100, is_multicast=True))
    engine.process_packet_dict(_packet_dict(6, 1_050_000, 100, 100, is_broadcast=True))
    report = engine.finalize()
    breakdown = report.global_results["l2_l3_breakdown"]
    assert breakdown["ethernet_frames"] == 6
    assert breakdown["vlan_frames"] == 1
    assert breakdown["arp_packets"] == 1
    assert breakdown["icmp_packets"] == 1
    assert breakdown["icmpv6_packets"] == 1
    assert breakdown["multicast_packets"] == 1
    assert breakdown["broadcast_packets"] == 1


def test_l2_l3_breakdown_empty():
    analyzer = L2L3BreakdownAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])
    report = engine.finalize()
    breakdown = report.global_results["l2_l3_breakdown"]
    assert breakdown["ethernet_frames"] == 0
    assert breakdown["broadcast_packets"] == 0


def test_top_entities_empty():
    analyzer = TopEntitiesAnalyzer(top_n=3)
    engine = AnalysisEngine(analyzers=[analyzer])
    report = engine.finalize()
    top = report.global_results["top_entities"]
    assert top["ip_talkers"]["top_src"] == []
    assert top["mac_talkers"]["top_src"] == []
    assert top["ports"]["tcp"]["top_dst_ports"] == []


def test_top_entities_mixed():
    analyzer = TopEntitiesAnalyzer(top_n=2)
    engine = AnalysisEngine(analyzers=[analyzer])
    engine.process_packet_dict(_packet_dict(
        1, 1_000_000, 500, 500,
        src_ip="10.0.0.1", dst_ip="8.8.8.8",
        src_mac="00:1b:63:aa:bb:cc", dst_mac="5c:51:4f:00:11:22",
        ip_proto=6, l4="TCP",
    ))
    engine.process_packet_dict(_packet_dict(
        2, 1_010_000, 700, 700,
        src_ip="10.0.0.2", dst_ip="1.1.1.1",
        src_mac="00:0c:29:aa:bb:cc", dst_mac="00:1b:63:aa:bb:cc",
        ip_proto=17, l4="UDP",
    ))
    engine.process_packet_dict(_packet_dict(
        3, 1_020_000, 200, 200,
        src_ip="10.0.0.1", dst_ip="8.8.8.8",
        src_mac="00:1b:63:aa:bb:cc", dst_mac="5c:51:4f:00:11:22",
        ip_proto=6, l4="TCP", dst_port=443,
    ))
    report = engine.finalize()
    top = report.global_results["top_entities"]
    src = top["ip_talkers"]["top_src"][0]
    assert src["ip"] == "10.0.0.1"
    assert src["bytes"] == 700
    split = top["ip_talkers"]["internal_external"]
    assert split["internal_bytes_pct"] == 100.0

    macs = top["mac_talkers"]["top_src"]
    assert macs[0]["vendor"] in ("Apple", "Unknown")

    tcp_ports = top["ports"]["tcp"]["top_dst_ports"]
    assert tcp_ports[0]["port"] in (80, 443)


def test_top_entities_vendor_lookup_and_ports_pct():
    analyzer = TopEntitiesAnalyzer(top_n=3)
    engine = AnalysisEngine(analyzers=[analyzer])
    engine.process_packet_dict(_packet_dict(
        1, 1_000_000, 100, 100,
        src_mac="00:1b:63:aa:bb:cc", dst_mac="ff:ff:ff:ff:ff:ff",
        ip_proto=6, l4="TCP", dst_port=80
    ))
    engine.process_packet_dict(_packet_dict(
        2, 1_010_000, 100, 100,
        src_mac="00:1b:63:aa:bb:cc", dst_mac="00:0c:29:11:22:33",
        ip_proto=6, l4="TCP", dst_port=80
    ))
    engine.process_packet_dict(_packet_dict(
        3, 1_020_000, 100, 100,
        src_mac="00:0c:29:aa:bb:cc", dst_mac="00:0c:29:11:22:33",
        ip_proto=17, l4="UDP", dst_port=53
    ))
    engine.process_packet_dict(_packet_dict(
        4, 1_030_000, 50, 50,
        src_mac="aa:bb:cc:dd:ee:ff", dst_mac="00:0c:29:11:22:33",
        ip_proto=17, l4="UDP", dst_port=53
    ))
    report = engine.finalize()
    top = report.global_results["top_entities"]
    mac_entry = top["mac_talkers"]["top_src"][0]
    assert mac_entry["vendor"] in ("Apple", "VMware", "Unknown")
    vendors = {item["vendor"] for item in top["mac_talkers"]["vendor_distribution"]}
    assert "Unknown" in vendors
    tcp = top["ports"]["tcp"]["top_dst_ports"]
    assert tcp[0]["port"] == 80
    assert tcp[0]["packets_pct"] == 100.0
    udp = top["ports"]["udp"]["top_dst_ports"]
    assert udp[0]["port"] == 53
    assert udp[0]["packets_pct"] == 100.0


def test_top_entities_internal_external_split():
    analyzer = TopEntitiesAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])
    engine.process_packet_dict(_packet_dict(
        1, 1_000_000, 100, 100,
        src_ip="10.0.0.5", dst_ip="8.8.8.8",
        ip_proto=6, l4="TCP", dst_port=80
    ))
    engine.process_packet_dict(_packet_dict(
        2, 1_010_000, 300, 300,
        src_ip="1.2.3.4", dst_ip="10.0.0.5",
        ip_proto=17, l4="UDP", dst_port=53
    ))
    report = engine.finalize()
    split = report.global_results["top_entities"]["ip_talkers"]["internal_external"]
    assert split["internal_bytes_pct"] == 25.0
    assert split["external_bytes_pct"] == 75.0


def test_top_entities_schema_keys():
    analyzer = TopEntitiesAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])
    engine.process_packet_dict(_packet_dict(1, 1_000_000, 60, 60))
    report = engine.finalize()
    top = report.global_results["top_entities"]
    assert "ip_talkers" in top
    assert "mac_talkers" in top
    assert "ports" in top


def test_flow_analytics_empty():
    analyzer = FlowAnalyticsAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])
    report = engine.finalize()
    analytics = report.global_results["flow_analytics"]
    assert analytics["summary"]["total_flows"] == 0
    assert analytics["heavy_hitters"]["top_by_bytes"] == []
    assert analytics["states"]["tcp_established"] == 0


def test_flow_analytics_rates_and_percentiles():
    analyzer = FlowAnalyticsAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])
    engine.process_packet_dict(_packet_dict(
        1, 1_000_000, 100, 100,
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=1111, dst_port=80, ip_proto=6, l4="TCP",
        tcp_flags=0x02,
    ))
    engine.process_packet_dict(_packet_dict(
        2, 2_000_000, 200, 200,
        src_ip="10.0.0.3", dst_ip="10.0.0.4",
        src_port=2222, dst_port=443, ip_proto=6, l4="TCP",
        tcp_flags=0x02,
    ))
    report = engine.finalize()
    summary = report.global_results["flow_analytics"]["summary"]
    assert summary["total_flows"] == 2
    assert summary["new_flows_per_sec"] == 2.0
    assert summary["bytes_per_flow_avg"] == 150.0


def test_flow_analytics_heavy_hitters_and_duration():
    analyzer = FlowAnalyticsAnalyzer(top_n=1)
    engine = AnalysisEngine(analyzers=[analyzer])
    engine.process_packet_dict(_packet_dict(
        1, 1_000_000, 500, 500,
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=1111, dst_port=80, ip_proto=6, l4="TCP",
        tcp_flags=0x02,
    ))
    engine.process_packet_dict(_packet_dict(
        2, 1_500_000, 500, 500,
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=1111, dst_port=80, ip_proto=6, l4="TCP",
        tcp_flags=0x10,
    ))
    report = engine.finalize()
    heavy = report.global_results["flow_analytics"]["heavy_hitters"]["top_by_bytes"][0]
    assert heavy["bytes"] == 1000
    assert heavy["duration_us"] == 500_000
    assert "label" in heavy


def test_flow_analytics_states_tcp_udp():
    analyzer = FlowAnalyticsAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])
    # TCP established
    engine.process_packet_dict(_packet_dict(
        1, 1_000_000, 100, 100,
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=1111, dst_port=80, ip_proto=6, l4="TCP",
        tcp_flags=0x02,
    ))
    engine.process_packet_dict(_packet_dict(
        2, 1_010_000, 100, 100,
        src_ip="10.0.0.2", dst_ip="10.0.0.1",
        src_port=80, dst_port=1111, ip_proto=6, l4="TCP",
        tcp_flags=0x12,
    ))
    engine.process_packet_dict(_packet_dict(
        3, 1_020_000, 100, 100,
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=1111, dst_port=80, ip_proto=6, l4="TCP",
        tcp_flags=0x10,
    ))
    # TCP half-open
    engine.process_packet_dict(_packet_dict(
        4, 1_030_000, 100, 100,
        src_ip="10.0.0.3", dst_ip="10.0.0.4",
        src_port=2222, dst_port=81, ip_proto=6, l4="TCP",
        tcp_flags=0x02,
    ))
    # TCP reset/failed
    engine.process_packet_dict(_packet_dict(
        5, 1_040_000, 100, 100,
        src_ip="10.0.0.5", dst_ip="10.0.0.6",
        src_port=3333, dst_port=82, ip_proto=6, l4="TCP",
        tcp_flags=0x04,
    ))
    # UDP paired and unpaired
    engine.process_packet_dict(_packet_dict(
        6, 1_050_000, 100, 100,
        src_ip="10.0.0.7", dst_ip="10.0.0.8",
        src_port=4000, dst_port=53, ip_proto=17, l4="UDP",
    ))
    engine.process_packet_dict(_packet_dict(
        7, 1_060_000, 100, 100,
        src_ip="10.0.0.8", dst_ip="10.0.0.7",
        src_port=53, dst_port=4000, ip_proto=17, l4="UDP",
    ))
    engine.process_packet_dict(_packet_dict(
        8, 1_070_000, 100, 100,
        src_ip="10.0.0.9", dst_ip="10.0.0.10",
        src_port=5000, dst_port=53, ip_proto=17, l4="UDP",
    ))

    report = engine.finalize()
    states = report.global_results["flow_analytics"]["states"]
    assert states["tcp_established"] == 1
    assert states["tcp_half_open"] == 1
    assert states["tcp_reset_failed"] == 1
    assert states["udp_paired"] == 1
    assert states["udp_unpaired"] == 1


def test_tcp_reliability_metrics():
    analyzer = TcpReliabilityAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])
    # retransmission: same seq twice
    engine.process_packet_dict(_packet_dict(
        1, 1_000_000, 100, 100,
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80,
        ip_proto=6, l4="TCP", tcp_flags=0x10, tcp_seq=100, tcp_ack=0
    ))
    engine.process_packet_dict(_packet_dict(
        2, 1_010_000, 100, 100,
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80,
        ip_proto=6, l4="TCP", tcp_flags=0x10, tcp_seq=100, tcp_ack=0
    ))
    # out of order: seq regression
    engine.process_packet_dict(_packet_dict(
        3, 1_020_000, 100, 100,
        src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=80, dst_port=1000,
        ip_proto=6, l4="TCP", tcp_flags=0x10, tcp_seq=300, tcp_ack=0
    ))
    engine.process_packet_dict(_packet_dict(
        4, 1_030_000, 100, 100,
        src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=80, dst_port=1000,
        ip_proto=6, l4="TCP", tcp_flags=0x10, tcp_seq=200, tcp_ack=0
    ))
    # dup ack + rst
    engine.process_packet_dict(_packet_dict(
        5, 1_040_000, 100, 100,
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80,
        ip_proto=6, l4="TCP", tcp_flags=0x10, tcp_seq=150, tcp_ack=400
    ))
    engine.process_packet_dict(_packet_dict(
        6, 1_050_000, 100, 100,
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80,
        ip_proto=6, l4="TCP", tcp_flags=0x10, tcp_seq=160, tcp_ack=400
    ))
    engine.process_packet_dict(_packet_dict(
        7, 1_060_000, 100, 100,
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80,
        ip_proto=6, l4="TCP", tcp_flags=0x04, tcp_seq=170, tcp_ack=0
    ))
    report = engine.finalize()
    rel = report.global_results["tcp_reliability"]
    assert rel["retransmissions"] == 1
    assert rel["out_of_order"] == 1
    assert rel["dup_acks"] == 1
    assert rel["rst_packets"] == 1


def test_tcp_performance_metrics():
    analyzer = TcpPerformanceAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])
    engine.process_packet_dict(_packet_dict(
        1, 1_000_000, 100, 100,
        ip_proto=6, l4="TCP", tcp_flags=0x12, tcp_window=1000, tcp_mss=1460
    ))
    engine.process_packet_dict(_packet_dict(
        2, 1_010_000, 100, 100,
        ip_proto=6, l4="TCP", tcp_flags=0x10, tcp_window=2000
    ))
    engine.process_packet_dict(_packet_dict(
        3, 1_020_000, 100, 100,
        ip_proto=6, l4="TCP", tcp_flags=0x10, tcp_window=3000
    ))
    engine.process_packet_dict(_packet_dict(
        4, 1_030_000, 100, 100,
        ip_proto=6, l4="TCP", tcp_flags=0x10, tcp_window=0
    ))
    report = engine.finalize()
    perf = report.global_results["tcp_performance"]
    assert perf["window_median"] == 2000.0
    assert perf["window_p95"] == 2900.0
    assert perf["zero_window"] == 1
    assert perf["mss_top_value"] == 1460


def test_tcp_handshake_rtt_quantiles():
    analyzer = TcpHandshakeAnalyzer()
    engine = AnalysisEngine(analyzers=[analyzer])
    # flow 1: 50ms
    engine.process_packet_dict(_packet_dict(
        1, 1_000_000, 100, 100,
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80,
        ip_proto=6, l4="TCP", tcp_flags=0x02, tcp_seq=100
    ))
    engine.process_packet_dict(_packet_dict(
        2, 1_050_000, 100, 100,
        src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=80, dst_port=1000,
        ip_proto=6, l4="TCP", tcp_flags=0x12, tcp_seq=200
    ))
    engine.process_packet_dict(_packet_dict(
        3, 1_060_000, 100, 100,
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80,
        ip_proto=6, l4="TCP", tcp_flags=0x10, tcp_seq=101
    ))
    # flow 2: 100ms
    engine.process_packet_dict(_packet_dict(
        4, 2_000_000, 100, 100,
        src_ip="10.0.0.3", dst_ip="10.0.0.4", src_port=2000, dst_port=443,
        ip_proto=6, l4="TCP", tcp_flags=0x02, tcp_seq=100
    ))
    engine.process_packet_dict(_packet_dict(
        5, 2_100_000, 100, 100,
        src_ip="10.0.0.4", dst_ip="10.0.0.3", src_port=443, dst_port=2000,
        ip_proto=6, l4="TCP", tcp_flags=0x12, tcp_seq=200
    ))
    engine.process_packet_dict(_packet_dict(
        6, 2_110_000, 100, 100,
        src_ip="10.0.0.3", dst_ip="10.0.0.4", src_port=2000, dst_port=443,
        ip_proto=6, l4="TCP", tcp_flags=0x10, tcp_seq=101
    ))
    report = engine.finalize()
    handshakes = report.global_results["tcp_handshakes"]
    assert handshakes["completion_rate"] == 1.0
    assert handshakes["rtt_median_ms"] == 75.0
    assert handshakes["rtt_p95_ms"] == 97.5


def test_tcp_reliability_bounded_memory():
    analyzer = TcpReliabilityAnalyzer(max_flows=1)
    engine = AnalysisEngine(analyzers=[analyzer])
    engine.process_packet_dict(_packet_dict(
        1, 1_000_000, 100, 100,
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80,
        ip_proto=6, l4="TCP", tcp_flags=0x10, tcp_seq=100
    ))
    engine.process_packet_dict(_packet_dict(
        2, 1_010_000, 100, 100,
        src_ip="10.0.0.3", dst_ip="10.0.0.4", src_port=2000, dst_port=80,
        ip_proto=6, l4="TCP", tcp_flags=0x10, tcp_seq=200
    ))
    report = engine.finalize()
    rel = report.global_results["tcp_reliability"]
    assert rel["tcp_packets"] == 2

def main():
    tests = [
        test_flow_state_direction_counts,
        test_global_stats_analyzer,
        test_time_series_analyzer,
        test_protocol_mix_percentages,
        test_tcp_handshake_grouping,
        test_abnormal_activity_scan_and_syn_only,
        test_packet_chunks,
        test_capture_health_decode_stats,
        test_throughput_peaks_empty,
        test_throughput_peaks_mixed,
        test_packet_size_stats_histogram_and_quantiles,
        test_packet_size_stats_empty,
        test_packet_size_stats_fragments,
        test_l2_l3_breakdown_counts,
        test_l2_l3_breakdown_empty,
        test_top_entities_empty,
        test_top_entities_mixed,
        test_top_entities_vendor_lookup_and_ports_pct,
        test_top_entities_internal_external_split,
        test_top_entities_schema_keys,
        test_flow_analytics_empty,
        test_flow_analytics_rates_and_percentiles,
        test_flow_analytics_heavy_hitters_and_duration,
        test_flow_analytics_states_tcp_udp,
        test_tcp_reliability_metrics,
        test_tcp_performance_metrics,
        test_tcp_handshake_rtt_quantiles,
        test_tcp_reliability_bounded_memory,
    ]

    print("=" * 60)
    print("Testing analysis subsystem")
    print("=" * 60)

    all_passed = True
    for test in tests:
        try:
            test()
            print(f"[PASS] {test.__name__}")
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            all_passed = False
        except Exception as e:
            print(f"[CRASH] {test.__name__}: {e}")
            all_passed = False

    print("=" * 60)
    if all_passed:
        print("ALL TESTS PASSED")
    else:
        print("SOME TESTS FAILED")
    print("=" * 60)

    return all_passed


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
