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
