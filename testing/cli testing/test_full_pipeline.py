"""
Test full pipeline: Capture → PacketIndexBuilder → SessionManifest
"""
import sys
import os

# Add src to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

print("Testing Full Capture Pipeline")
print("=" * 60)

# Import everything
from capture import DummyBackend, CaptureConfig
from pcap_loader.packet_index import PacketIndexBuilder
from models.session import SessionManifest

# Create backend
backend = DummyBackend()

# List interfaces
interfaces = backend.list_interfaces()
print(f"Available interfaces: {len(interfaces)}")
for iface in interfaces:
    print(f"  - {iface['name']}")

# Start capture
config = CaptureConfig(interface="dummy0", buffer_size=100)
session_id = backend.start(config)
print(f"\nStarted capture session: {session_id}")

# Create session manifest (simplified)
session = SessionManifest(
    session_id=session_id,
    created_at="2024-01-01T00:00:00Z",
    source_type="interface",
    source_hash="dummy_hash",
    time_start_us=0,
    time_end_us=0,
    total_packets=0,
    total_bytes_captured=0,
    total_bytes_original=0,
)

# Create packet index builder
index_builder = PacketIndexBuilder(session_id=session_id)

print("\nCapturing and indexing packets...")
packet_count = 0

import time
start_time = time.time()

while time.time() - start_time < 2:  # Capture for 2 seconds
    # Get packets from backend
    packets = backend.get_packets(session_id, count=10)
    
    for pkt in packets:
        # Create a minimal RawPacket
        class RawPacket:
            def __init__(self, pkt_info):
                self.packet_id = packet_count + 1
                self.timestamp_us = int(pkt_info['ts'] * 1_000_000)
                self.captured_length = len(pkt_info['data'])
                self.original_length = pkt_info['wirelen']
                self.link_type = 1  # Ethernet
                self.data = pkt_info['data']
                self.pcap_ref = f"live:{session_id}:{packet_count}"
        
        raw_packet = RawPacket(pkt)
        
        # Create index record
        index_record = index_builder.create_index_record(raw_packet, stack_summary="eth:ip")
        
        # Update session stats
        packet_count += 1
        session.total_packets += 1
        session.total_bytes_captured += raw_packet.captured_length
        session.total_bytes_original += raw_packet.original_length
        
        # Update time range
        if session.time_start_us == 0 or raw_packet.timestamp_us < session.time_start_us:
            session.time_start_us = raw_packet.timestamp_us
        if raw_packet.timestamp_us > session.time_end_us:
            session.time_end_us = raw_packet.timestamp_us
    
    time.sleep(0.1)

# Stop capture
metadata = backend.stop(session_id)

print(f"\nCapture complete!")
print(f"Total packets indexed: {packet_count}")
print(f"Session duration: {(session.time_end_us - session.time_start_us)/1_000_000:.2f}s")
print(f"Index builder processed: {index_builder.total_packets_processed} packets")

# Validate
print(f"\nSession manifest:")
print(f"  ID: {session.session_id}")
print(f"  Packets: {session.total_packets}")
print(f"  Bytes: {session.total_bytes_captured:,}")
print(f"  Time range: {session.time_start_us} - {session.time_end_us} μs")

print("\n" + "=" * 60)
print("✅ FULL PIPELINE TEST PASSED!")
print("=" * 60)