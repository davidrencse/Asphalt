#!/usr/bin/env python3
"""Test PcapReader implementation."""

#!/usr/bin/env python3
"""Test PcapReader implementation."""

import sys
import os

# Determine the correct path
def setup_paths():
    """Add project root to Python path."""
    # Method 1: If running from project root
    if os.path.exists('src'):
        sys.path.insert(0, os.getcwd())
        return
    
    # Method 2: If running from testing directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    if os.path.exists(os.path.join(parent_dir, 'src')):
        sys.path.insert(0, parent_dir)
        return
    
    # Method 3: Manual override
    print("Could not find src/ directory automatically.")
    print(f"Current directory: {os.getcwd()}")
    print(f"Script location: {__file__}")
    
    # Try common locations
    common_parents = [
        os.path.dirname(os.path.dirname(__file__)),  # Go up 2 levels
        os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop', 'all projects', 'Cybersecurity', 'Asphalt [TODO]')
    ]
    
    for path in common_parents:
        if os.path.exists(os.path.join(path, 'src')):
            sys.path.insert(0, path)
            print(f"Found src at: {path}")
            return
    
    raise ImportError("Cannot find src/ directory. Run from project root.")

setup_paths()

# Now imports should work
from src.pcap_loader.pcap_reader import PcapReader

def test_initialization():
    """Test that PcapReader initializes correctly."""
    print("Test 1: Initialization")
    
    reader = PcapReader("dummy.pcap")
    
    # Check all variables exist
    print(f"  filepath: {reader.filepath}")
    print(f"  file_handle: {reader.file_handle}")
    print(f"  mmap: {reader.mmap}")
    print(f"  byte_order: {reader.byte_order}")
    print(f"  is_nanosecond: {reader.is_nanosecond}")
    print(f"  link_type: {reader.link_type}")
    print(f"  _packet_count: {reader._packet_count}")
    
    # CRITICAL: Check _time_range (not _time.range!)
    try:
        print(f"  _time_range: {reader._time_range}")
        print("  ✅ _time_range exists correctly")
    except AttributeError as e:
        print(f"  ❌ ERROR: {e}")
        print("  You have 'self._time.range' instead of 'self._time_range' in __init__!")
        return False
    
    print(f"  _file_size: {reader._file_size}")
    print(f"  _current_offset: {reader._current_offset}")
    
    return True

def test_open_error_handling():
    """Test that open() raises proper errors."""
    print("\nTest 2: Open error handling")
    
    # Test with non-existent file
    reader = PcapReader("non_existent_file.pcap")
    try:
        reader.open()
        print("  ❌ Should have raised FileNotFoundError!")
        return False
    except FileNotFoundError as e:
        print(f"  ✅ Correctly raised FileNotFoundError: {e}")
    except Exception as e:
        print(f"  ❌ Wrong exception: {type(e).__name__}: {e}")
        return False
    
    return True

def test_context_manager():
    """Test that 'with' statement works."""
    print("\nTest 3: Context manager")
    
    # Create a dummy file for testing
    test_file = "test_dummy.pcap"
    with open(test_file, 'wb') as f:
        # Write minimal valid PCAP header (24 bytes)
        # Magic: 0xA1B2C3D4 (big-endian, microsecond)
        f.write(b'\xa1\xb2\xc3\xd4')  # Magic
        f.write(b'\x02\x00\x04\x00')  # Version 2.4
        f.write(b'\x00\x00\x00\x00')  # Timezone
        f.write(b'\x00\x00\x00\x00')  # Timestamp accuracy
        f.write(b'\xff\xff\x00\x00')  # Snaplen 65535
        f.write(b'\x01\x00\x00\x00')  # Link type 1 (Ethernet)
    
    try:
        with PcapReader(test_file) as reader:
            print(f"  ✅ Successfully opened with 'with' statement")
            print(f"  file_handle: {reader.file_handle}")
            print(f"  mmap: {reader.mmap}")
            
            # Try to iterate (no packets, just header)
            packets = list(reader)
            print(f"  Read {len(packets)} packets (should be 0)")
            
    except Exception as e:
        print(f"  ❌ Error in context manager: {type(e).__name__}: {e}")
        return False
    finally:
        # Clean up test file
        if os.path.exists(test_file):
            os.remove(test_file)
    
    return True

def test_get_session_info():
    """Test get_session_info() method."""
    print("\nTest 4: get_session_info()")
    
    reader = PcapReader("dummy.pcap")
    
    # Simulate some state
    reader._packet_count = 100
    reader._time_range = (1700000000000000, 1700000100000000)
    reader._file_size = 1024000
    reader.link_type = 1
    reader.byte_order = '>'
    reader.is_nanosecond = False
    
    info = reader.get_session_info()
    
    required_keys = ['packet_count', 'time_range', 'link_types', 'file_size', 
                     'format', 'byte_order', 'is_nanosecond', 'link_type']
    
    for key in required_keys:
        if key not in info:
            print(f"  ❌ Missing key: {key}")
            return False
    
    print(f"  ✅ All keys present: {list(info.keys())}")
    print(f"  packet_count: {info['packet_count']} (should be 100)")
    print(f"  time_range: {info['time_range']}")
    print(f"  link_types: {info['link_types']} (should be [1])")
    
    return True

def test_get_index_record():
    """Test get_index_record() method."""
    print("\nTest 5: get_index_record()")
    
    reader = PcapReader("dummy.pcap")
    
    # Create a dummy packet
    from src.models.packet import RawPacket
    
    packet = RawPacket(
        packet_id=1,
        timestamp_us=1700000000000000,
        captured_length=64,
        original_length=64,
        link_type=1,
        data=b'\x00' * 64,
        pcap_ref="0:100:116"
    )
    
    try:
        index_record = reader.get_index_record(packet, 1)
        print(f"  ✅ Successfully created index record")
        print(f"  packet_id: {index_record.packet_id} (should be 1)")
        print(f"  session_id: {index_record.session_id}")
        print(f"  hash length: {len(index_record.packet_hash)} chars")
        
        # Test determinism
        index_record2 = reader.get_index_record(packet, 1)
        if index_record.packet_hash == index_record2.packet_hash:
            print(f"  ✅ Hashes match (deterministic)")
        else:
            print(f"  ❌ Hashes don't match!")
            return False
            
    except Exception as e:
        print(f"  ❌ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

def main():
    """Run all tests."""
    print("=" * 60)
    print("Testing PcapReader")
    print("=" * 60)
    
    tests = [
        test_initialization,
        test_open_error_handling,
        test_context_manager,
        test_get_session_info,
        test_get_index_record,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                print(f"  ✅ {test.__name__} PASSED")
                passed += 1
            else:
                print(f"  ❌ {test.__name__} FAILED")
                failed += 1
        except Exception as e:
            print(f"  ❌ {test.__name__} CRASHED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)


"""
============================================================
Testing PcapReader
============================================================
Test 1: Initialization
  filepath: dummy.pcap
  file_handle: None
  mmap: None
  byte_order: >
  is_nanosecond: False
  link_type: 1
  _packet_count: 0
  _time_range: None
  ✅ _time_range exists correctly
  _file_size: 0
  _current_offset: 0
  ✅ test_initialization PASSED

Test 2: Open error handling
  ✅ Correctly raised FileNotFoundError: PCAP file not found: non_existent_file.pcap
  ✅ test_open_error_handling PASSED

Test 3: Context manager
  ✅ Successfully opened with 'with' statement
  file_handle: <_io.BufferedReader name='test_dummy.pcap'>
  mmap: <mmap.mmap closed=False, access=ACCESS_READ, length=24, pos=0, offset=0>
  Read 0 packets (should be 0)
  ✅ test_context_manager PASSED

Test 4: get_session_info()
  ✅ All keys present: ['packet_count', 'time_range', 'link_types', 'file_size', 'format', 'byte_order', 'is_nanosecond', 'link_type']
  packet_count: 100 (should be 100)
  time_range: (1700000000000000, 1700000100000000)
  link_types: [1] (should be [1])
  ✅ test_get_session_info PASSED

Test 5: get_index_record()
  ✅ Successfully created index record
  packet_id: 1 (should be 1)
  session_id: unknown_session
  hash length: 32 chars
  ✅ Hashes match (deterministic)
  ✅ test_get_index_record PASSED

============================================================
Results: 5 passed, 0 failed
============================================================

"""