"""
Basic capture test - doesn't use the problematic live_source.py
"""
import sys
import os

# Add src to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

print("Testing capture backends directly...")

# Test 1: Import the backends directly
try:
    from capture.icapture_backend import CaptureConfig
    print("✓ Imported CaptureConfig")
    
    from capture.scapy_backend import ScapyBackend
    print("✓ Imported ScapyBackend")
    
    from capture.dummy_backend import DummyBackend
    print("✓ Imported DummyBackend")
    
except ImportError as e:
    print(f"✗ Import failed: {e}")
    print("\nChecking what files exist in capture directory...")
    capture_dir = os.path.join(src_path, 'capture')
    if os.path.exists(capture_dir):
        print("Files in capture directory:")
        for f in os.listdir(capture_dir):
            print(f"  - {f}")
    sys.exit(1)

# Test 2: List interfaces
print("\n=== Testing DummyBackend ===")
dummy = DummyBackend()
interfaces = dummy.list_interfaces()
print(f"Dummy interfaces found: {len(interfaces)}")
for iface in interfaces:
    print(f"  {iface['name']}: {iface['description']}")

# Test 3: Start dummy capture
print("\n=== Testing Dummy Capture ===")
config = CaptureConfig(interface="dummy0", buffer_size=50)
session_id = dummy.start(config)
print(f"Started capture session: {session_id}")

import time
for i in range(3):
    time.sleep(1)
    stats = dummy.get_stats(session_id)
    print(f"  After {i+1}s: {stats['packets_per_sec']} pps, "
          f"{stats['packets_total']} total packets")

# Get some packets
packets = dummy.get_packets(session_id, count=5)
print(f"\nRetrieved {len(packets)} sample packets:")

for i, pkt in enumerate(packets):
    print(f"  Packet {i+1}: {len(pkt['data'])} bytes "
          f"(timestamp: {pkt['ts']:.3f})")

# Stop capture
metadata = dummy.stop(session_id)
print(f"\nCapture stopped.")
print(f"Final count: {metadata['stats_summary']['packets_total']} packets")
print(f"Total bytes: {metadata['stats_summary']['bytes_total']}")
print(f"Drops: {metadata['stats_summary']['drops_total']}")

# Test 4: Try ScapyBackend if available
print("\n=== Testing ScapyBackend (real capture) ===")
try:
    scapy = ScapyBackend()
    real_interfaces = scapy.list_interfaces()
    print(f"Real interfaces found: {len(real_interfaces)}")
    
    if real_interfaces:
        print("Available real interfaces:")
        for iface in real_interfaces:
            print(f"  {iface['name']}: {iface['description']}")
            
        # Quick capture test
        response = input("\nTest real capture on first interface? (y/n): ")
        if response.lower() == 'y':
            iface_name = real_interfaces[0]['name']
            config = CaptureConfig(
                interface=iface_name,
                filter="tcp port 80 or tcp port 443",  # Web traffic
                buffer_size=1000
            )
            session_id = scapy.start(config)
            print(f"Started capture on {iface_name}...")
            print("Capturing for 3 seconds (press Ctrl+C to stop)...")
            
            try:
                for i in range(3):
                    time.sleep(1)
                    stats = scapy.get_stats(session_id)
                    print(f"  Stats: {stats['packets_per_sec']} pps, "
                          f"{stats['bytes_per_sec']} bps")
            except KeyboardInterrupt:
                print("\nStopped early.")
            
            metadata = scapy.stop(session_id)
            print(f"\nCapture complete!")
            print(f"Total: {metadata['stats_summary']['packets_total']} packets")
    
except Exception as e:
    print(f"ScapyBackend test failed: {e}")
    print("\nNote: For real packet capture:")
    print("1. Install NpCap from https://npcap.com/")
    print("2. Choose 'WinPcap API-compatible mode' during installation")
    print("3. Reboot if prompted")

print("\n✓ All tests completed!")