"""
Test the PacketIndexBuilder.
Run with: python -m tests.test_packet_index
"""
#!/usr/bin/env python3
"""Test the PacketIndexBuilder."""

# DEBUG: Show where we are
import os
print(f"Current directory: {os.getcwd()}")
print(f"Test file location: {__file__}")

# Add src to path
import sys
src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
print(f"Looking for src at: {src_path}")
print(f"Exists: {os.path.exists(src_path)}")

if os.path.exists(src_path):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
else:
    print("ERROR: Cannot find src/ directory!")
    print("Try running from project root: cd /path/to/ASPHALT")
    sys.exit(1)

# Now try imports
from src.models.packet import RawPacket
from src.pcap_loader.packet_index import PacketIndexBuilder


import sys
import os

# Add src to path so we can import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.models.packet import RawPacket
from src.pcap_loader.packet_index import PacketIndexBuilder

def test_basic_creation():
    """Test creating a simple index record."""
    print("Test 1: Basic creation")
    
    # Create builder
    builder = PacketIndexBuilder(session_id="test_session_123")
    
    # Create a test packet
    packet = RawPacket(
        packet_id=1,  # MUST start at 1
        timestamp_us=1700000000000000,  # Some timestamp
        captured_length=64,
        original_length=64,
        link_type=1,  # Ethernet
        data=b'\x00\x01\x02\x03' * 16,  # 64 bytes of test data
        pcap_ref="0:100:116"
    )
    
    # Create index record
    record = builder.create_index_record(packet)
    
    # Verify fields
    assert record.packet_id == 1, f"Expected packet_id=1, got {record.packet_id}"
    assert record.session_id == "test_session_123"
    assert record.timestamp_us == 1700000000000000
    assert record.captured_length == 64
    assert record.original_length == 64
    assert record.pcap_ref == "0:100:116"
    assert record.src_ip == "0.0.0.0"  # Placeholder
    assert record.dst_ip == "0.0.0.0"  # Placeholder
    assert record.stack_summary == "raw"
    assert len(record.packet_hash) == 32  # 16 bytes = 32 hex chars
    
    print("  ✅ Basic creation passed")
    return record

def test_deterministic_hash():
    """Test that same input produces same hash."""
    print("\nTest 2: Deterministic hash")
    
    # Create identical packets
    packet_data = b'\x01\x02\x03\x04' * 8  # 32 bytes
    
    packet1 = RawPacket(
        packet_id=1,
        timestamp_us=1000,
        captured_length=32,
        original_length=32,
        link_type=1,
        data=packet_data,
        pcap_ref="0:100:116"
    )
    
    packet2 = RawPacket(
        packet_id=1,  # Same packet_id
        timestamp_us=1000,  # Same timestamp
        captured_length=32,  # Same lengths
        original_length=32,
        link_type=1,  # Same link type
        data=packet_data,  # Same data
        pcap_ref="0:100:116"  # Same location
    )
    
    # Create two builders (fresh state each time)
    builder1 = PacketIndexBuilder(session_id="test")
    builder2 = PacketIndexBuilder(session_id="test")
    
    # Create records
    record1 = builder1.create_index_record(packet1)
    record2 = builder2.create_index_record(packet2)
    
    # Hashes MUST be identical
    assert record1.packet_hash == record2.packet_hash, \
        f"Hashes differ: {record1.packet_hash} vs {record2.packet_hash}"
    
    print("  ✅ Deterministic hash passed")

def test_packet_id_sequence():
    """Test that packet IDs increment correctly."""
    print("\nTest 3: Packet ID sequence")
    
    builder = PacketIndexBuilder(session_id="test")
    
    # Create multiple packets
    packets = []
    for i in range(5):
        packet = RawPacket(
            packet_id=i + 1,  # 1, 2, 3, 4, 5
            timestamp_us=1000 + i,
            captured_length=64,
            original_length=64,
            link_type=1,
            data=bytes([i]) * 64,
            pcap_ref=f"0:{i*100}:{i*100 + 16}"
        )
        packets.append(packet)
    
    # Process them
    records = []
    for packet in packets:
        record = builder.create_index_record(packet)
        records.append(record)
    
    # Check IDs: 1, 2, 3, 4, 5
    expected_ids = [1, 2, 3, 4, 5]
    actual_ids = [r.packet_id for r in records]
    
    assert actual_ids == expected_ids, f"Expected {expected_ids}, got {actual_ids}"
    print(f"  ✅ Packet IDs: {actual_ids}")

def test_validation_error():
    """Test that wrong packet_id raises error."""
    print("\nTest 4: Validation error on mismatch")
    
    builder = PacketIndexBuilder(session_id="test")
    
    # Packet with wrong ID (should be 1, but we give 99)
    packet = RawPacket(
        packet_id=99,  # WRONG! Should be 1
        timestamp_us=1000,
        captured_length=64,
        original_length=64,
        link_type=1,
        data=b'test',
        pcap_ref="0:100:116"
    )
    
    try:
        builder.create_index_record(packet)
        print("  ❌ Should have raised ValueError!")
        return False
    except ValueError as e:
        print(f"  ✅ Correctly raised error: {e}")
        return True

def test_reset_function():
    """Test the reset() method."""
    print("\nTest 5: Reset functionality")
    
    builder = PacketIndexBuilder(session_id="test")
    
    # Process some packets
    for i in range(3):
        packet = RawPacket(
            packet_id=i + 1,
            timestamp_us=1000 + i,
            captured_length=64,
            original_length=64,
            link_type=1,
            data=bytes([i]) * 64,
            pcap_ref=f"0:{i*100}:{i*100 + 16}"
        )
        builder.create_index_record(packet)
    
    assert builder.total_packets_processed == 3
    print(f"  ✅ Processed {builder.total_packets_processed} packets")
    
    # Reset
    builder.reset()
    assert builder.total_packets_processed == 0
    print("  ✅ Reset to 0 packets")
    
    # Should be able to start again at packet_id=1
    packet = RawPacket(
        packet_id=1,  # Can use 1 again after reset
        timestamp_us=2000,
        captured_length=64,
        original_length=64,
        link_type=1,
        data=b'new',
        pcap_ref="0:500:516"
    )
    
    record = builder.create_index_record(packet)
    assert record.packet_id == 1
    print("  ✅ Can start over at packet_id=1 after reset")

def test_properties():
    """Test the property getters."""
    print("\nTest 6: Property getters")
    
    builder = PacketIndexBuilder(session_id="test")
    
    # Before any packets
    assert builder.current_packet_id == 0
    assert builder.total_packets_processed == 0
    print(f"  ✅ Initial: current={builder.current_packet_id}, total={builder.total_packets_processed}")
    
    # After one packet
    packet = RawPacket(
        packet_id=1,
        timestamp_us=1000,
        captured_length=64,
        original_length=64,
        link_type=1,
        data=b'test',
        pcap_ref="0:100:116"
    )
    builder.create_index_record(packet)
    
    assert builder.current_packet_id == 1
    assert builder.total_packets_processed == 1
    print(f"  ✅ After 1 packet: current={builder.current_packet_id}, total={builder.total_packets_processed}")
    
    # After more packets
    for i in range(2, 4):
        packet = RawPacket(
            packet_id=i,
            timestamp_us=1000 + i,
            captured_length=64,
            original_length=64,
            link_type=1,
            data=bytes([i]) * 64,
            pcap_ref=f"0:{i*100}:{i*100 + 16}"
        )
        builder.create_index_record(packet)
    
    assert builder.current_packet_id == 3
    assert builder.total_packets_processed == 3
    print(f"  ✅ After 3 packets: current={builder.current_packet_id}, total={builder.total_packets_processed}")

def main():
    """Run all tests."""
    print("=" * 60)
    print("Testing PacketIndexBuilder")
    print("=" * 60)
    
    all_passed = True
    
    # Run tests
    tests = [
        test_basic_creation,
        test_deterministic_hash,
        test_packet_id_sequence,
        test_validation_error,
        test_reset_function,
        test_properties
    ]
    
    for test_func in tests:
        try:
            test_func()
        except AssertionError as e:
            print(f"  ❌ {test_func.__name__} failed: {e}")
            all_passed = False
        except Exception as e:
            print(f"  ❌ {test_func.__name__} crashed: {e}")
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✅ ALL TESTS PASSED!")
    else:
        print("❌ SOME TESTS FAILED")
    print("=" * 60)
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)


"""
Exists: True
============================================================
Testing PacketIndexBuilder
============================================================
Test 1: Basic creation
  ✅ Basic creation passed

Test 2: Deterministic hash
  ✅ Deterministic hash passed

Test 3: Packet ID sequence
  ✅ Packet IDs: [1, 2, 3, 4, 5]

Test 4: Validation error on mismatch
  ✅ Correctly raised error: Packet ID mismatch: expected 1, got 99. Packet sources must maintain monotonic packet_id starting at 1.

Test 5: Reset functionality
  ✅ Processed 3 packets
  ✅ Reset to 0 packets
  ✅ Can start over at packet_id=1 after reset

Test 6: Property getters
  ✅ Initial: current=0, total=0
  ✅ After 1 packet: current=1, total=1
  ✅ After 3 packets: current=3, total=3

============================================================
✅ ALL TESTS PASSED!
============================================================
"""