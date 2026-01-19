#!/usr/bin/env python3
"""Test PCAPNG reader with real dhcp.pcapng file."""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from src.pcap_loader.pcapng_reader import PcapngReader

def main():
    print("Testing PCAPNG Reader with dhcp.pcapng")
    print("=" * 60)
    
    # Check if file exists
    if not os.path.exists("dhcp.pcapng"):
        print("❌ dhcp.pcapng not found in current directory!")
        print("Download it from: https://wiki.wireshark.org/SampleCaptures")
        print("Save it in:", os.getcwd())
        return False
    
    print(f"File exists: {os.path.getsize('dhcp.pcapng'):,} bytes")
    
    try:
        # Test 1: Basic open/close
        print("\n1. Opening file...")
        reader = PcapngReader("dhcp.pcapng")
        reader.open()
        
        print(f"   ✅ File opened successfully")
        print(f"   File size: {reader._file_size:,} bytes")
        print(f"   Memory mapped: {reader.mmap is not None}")
        
        # Test 2: Check interfaces
        print(f"\n2. Interfaces found: {len(reader.interfaces)}")
        for iface_id, iface_info in reader.interfaces.items():
            print(f"   Interface {iface_id}:")
            print(f"     Link type: {iface_info['link_type']}")
            print(f"     Snap length: {iface_info['snaplen']}")
            print(f"     Timestamp resolution: {iface_info.get('tsresol', 'N/A')}")
            print(f"     Name: {iface_info.get('name', 'N/A')}")
        
        # Test 3: Read some packets
        print("\n3. Reading packets...")
        packet_count = 0
        first_packet = None
        last_packet = None
        
        for packet in reader:
            packet_count += 1
            if packet_count == 1:
                first_packet = packet
            last_packet = packet
            
            # Show first few packets
            if packet_count <= 5:
                print(f"   Packet {packet_count}:")
                print(f"     ID: {packet.packet_id}")
                print(f"     Timestamp: {packet.timestamp_us} μs")
                print(f"     Size: {packet.captured_length}/{packet.original_length} bytes")
                print(f"     Link type: {packet.link_type}")
                print(f"     Interface ID: {packet.interface_id}")
                print(f"     pcap_ref: {packet.pcap_ref}")
                print()
            
            # Stop after 20 packets for quick test
            if packet_count >= 20:
                print(f"   ... (showing first 20 of many)")
                break
        
        print(f"   Total packets read: {packet_count}")
        
        # Test 4: Get session info
        print("\n4. Session metadata:")
        info = reader.get_session_info()
        print(f"   Format: {info['format']}")
        print(f"   Packet count: {info['packet_count']}")
        print(f"   Time range: {info['time_range'][0]} - {info['time_range'][1]} μs")
        
        duration_us = info['time_range'][1] - info['time_range'][0]
        duration_sec = duration_us / 1_000_000
        print(f"   Duration: {duration_sec:.2f} seconds")
        
        print(f"   Link types: {info['link_types']}")
        print(f"   File size: {info['file_size']:,} bytes")
        
        # Test 5: Create index record
        if first_packet:
            print("\n5. Creating index record for first packet...")
            index_record = reader.get_index_record(first_packet, first_packet.packet_id)
            print(f"   ✅ Index record created")
            print(f"   Packet ID: {index_record.packet_id}")
            print(f"   Session ID: {index_record.session_id}")
            print(f"   Packet hash: {index_record.packet_hash[:16]}...")
            print(f"   Hash length: {len(index_record.packet_hash)} chars")
        
        # Test 6: Test determinism
        print("\n6. Testing determinism...")
        reader.close()
        
        # Reopen and read first packet again
        reader2 = PcapngReader("dhcp.pcapng")
        reader2.open()
        
        packet2 = None
        for p in reader2:
            packet2 = p
            break
        
        if first_packet and packet2:
            same_hash = (reader.get_index_record(first_packet, 1).packet_hash == 
                        reader2.get_index_record(packet2, 1).packet_hash)
            if same_hash:
                print("   ✅ Hashes match (deterministic)")
            else:
                print("   ❌ Hashes don't match!")
        
        reader2.close()
        
        print("\n✅ All tests completed successfully!")
        
    except FileNotFoundError as e:
        print(f"❌ File not found: {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {type(e).__name__}")
        print(f"   Message: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)


"""

Testing PCAPNG Reader with dhcp.pcapng
============================================================
File exists: 1,508 bytes

1. Opening file...
   ✅ File opened successfully
   File size: 1,508 bytes
   Memory mapped: True

2. Interfaces found: 1
   Interface 0:
     Link type: 1
     Snap length: 65535
     Timestamp resolution: 6
     Name: None

3. Reading packets...
   Packet 1:
     ID: 1
     Timestamp: 1102274184317453 μs
     Size: 314/314 bytes
     Link type: 1
     Interface ID: 0
     pcap_ref: 0:60

   Packet 2:
     ID: 2
     Timestamp: 1102274184317748 μs
     Size: 342/342 bytes
     Link type: 1
     Interface ID: 0
     pcap_ref: 0:408

   Packet 3:
     ID: 3
     Timestamp: 1102274184387484 μs
     Size: 314/314 bytes
     Link type: 1
     Interface ID: 0
     pcap_ref: 0:784

   Packet 4:
     ID: 4
     Timestamp: 1102274184387798 μs
     Size: 342/342 bytes
     Link type: 1
     Interface ID: 0
     pcap_ref: 0:1132

   Total packets read: 4

4. Session metadata:
   Format: pcapng
   Packet count: 4
   Time range: 1102274184317453 - 1102274184387798 μs
   Duration: 0.07 seconds
   Link types: [1]
   File size: 1,508 bytes

5. Creating index record for first packet...
   ✅ Index record created
   Packet ID: 1
   Session ID: pcapng_session_placeholder
   Packet hash: e856dc4509846fe5...
   Hash length: 32 chars

6. Testing determinism...
   ✅ Hashes match (deterministic)

✅ All tests completed successfully!

"""