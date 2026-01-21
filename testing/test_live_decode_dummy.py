"""
Live capture -> decode pipeline test using DummyBackend.
Run with: python testing\\test_live_decode_dummy.py
"""
import os
import sys
import time

# Add src to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_path = os.path.join(project_root, "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from models.packet import RawPacket
from capture.dummy_backend import DummyBackend
from capture.icapture_backend import CaptureConfig
from capture.packet_decoder import decode_packet


def test_live_pipeline_dummy():
    backend = DummyBackend()
    config = CaptureConfig(interface="dummy0", buffer_size=1000)
    session_id = backend.start(config)

    packets = []
    start = time.time()
    while len(packets) < 5 and (time.time() - start) < 2.0:
        packets.extend(backend.get_packets(session_id, count=50))
        if not packets:
            time.sleep(0.01)

    backend.stop(session_id)

    assert packets, "No packets captured from dummy backend"

    decoded_any = False
    packet_id = 0
    for pkt in packets[:5]:
        packet_id += 1
        raw = RawPacket(
            packet_id=packet_id,
            timestamp_us=int(pkt["ts"] * 1_000_000),
            captured_length=len(pkt["data"]),
            original_length=pkt.get("wirelen", len(pkt["data"])),
            link_type=1,  # Ethernet
            data=pkt["data"],
            pcap_ref="live:0:0",
        )
        decoded = decode_packet(raw)
        if decoded.protocol_stack:
            decoded_any = True
        assert decoded.raw_packet.packet_id == packet_id

    assert decoded_any, "Decoded packets have empty protocol stack"


def main():
    print("=" * 60)
    print("Testing live capture decode pipeline (dummy)")
    print("=" * 60)
    try:
        test_live_pipeline_dummy()
        print("\u2705 test_live_pipeline_dummy passed")
        return True
    except AssertionError as e:
        print(f"\u274c test_live_pipeline_dummy failed: {e}")
        return False
    except Exception as e:
        print(f"\u274c test_live_pipeline_dummy crashed: {e}")
        return False


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
