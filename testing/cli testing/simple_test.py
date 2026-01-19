"""
Simple test to verify everything works.
"""
import sys
import os

# Add src to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

print("Testing Asphalt components...")

# Test 1: Can we import capture modules?
try:
    from capture.dummy_backend import DummyBackend
    from capture.icapture_backend import CaptureConfig
    print("✓ Imported capture modules")
except ImportError as e:
    print(f"✗ Import failed: {e}")
    print("\nChecking directory structure...")
    import os
    capture_dir = os.path.join(src_path, 'capture')
    if os.path.exists(capture_dir):
        print(f"Capture directory exists: {capture_dir}")
        for f in os.listdir(capture_dir):
            print(f"  - {f}")
    sys.exit(1)

# Test 2: Create and test dummy backend
print("\nTesting DummyBackend...")
backend = DummyBackend()

# List interfaces
interfaces = backend.list_interfaces()
print(f"Found {len(interfaces)} interfaces:")
for iface in interfaces:
    print(f"  {iface['name']}: {iface['description']}")

# Start capture
config = CaptureConfig(interface="dummy0", buffer_size=100)
session_id = backend.start(config)
print(f"\nStarted capture: {session_id}")

import time
for i in range(3):
    time.sleep(1)
    stats = backend.get_stats(session_id)
    print(f"  Second {i+1}: {stats['packets_per_sec']} pps")

# Stop
metadata = backend.stop(session_id)
print(f"\nCapture complete!")
print(f"Total: {metadata['stats_summary']['packets_total']} packets")

print("\n✅ All tests passed!")



"""

Testing Asphalt components...
✓ Imported capture modules

Testing DummyBackend...
Found 2 interfaces:
  dummy0: Dummy Ethernet Interface
  dummy1: Dummy Wi-Fi Interface

Started capture: dummy_1768828068
  Second 1: 0 pps
  Second 2: 64 pps
  Second 3: 0 pps

Capture complete!
Total: 100 packets

✅ All tests passed!

"""