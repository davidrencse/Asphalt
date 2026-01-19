"""
Test capture WITHOUT importing problematic modules.
"""
import sys
import os

# Add src to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

print("Testing capture with manual imports...")

# MANUALLY define what we need to avoid import chains
# Define minimal RawPacket class
class RawPacket:
    def __init__(self, timestamp=0, data=b"", capture_length=0, wire_length=0, interface=""):
        self.timestamp = timestamp
        self.data = data
        self.capture_length = capture_length
        self.wire_length = wire_length
        self.interface = interface

# Read and execute icapture_backend.py manually
capture_dir = os.path.join(src_path, 'capture')
icapture_path = os.path.join(capture_dir, 'icapture_backend.py')

with open(icapture_path, 'r') as f:
    icapture_code = f.read()
    # Execute in isolated namespace
    exec_globals = {}
    exec(icapture_code, exec_globals)

# Extract classes
CaptureConfig = exec_globals['CaptureConfig']
ICaptureBackend = exec_globals['ICaptureBackend']

print("✓ Loaded CaptureConfig and ICaptureBackend")

# Now read dummy_backend.py
dummy_path = os.path.join(capture_dir, 'dummy_backend.py')
with open(dummy_path, 'r') as f:
    dummy_code = f.read()
    # Replace relative import
    dummy_code = dummy_code.replace('from .icapture_backend import', '# Import removed')
    # Execute with our already-loaded classes
    dummy_globals = {'ICaptureBackend': ICaptureBackend, 'CaptureConfig': CaptureConfig}
    exec(dummy_code, dummy_globals)

DummyBackend = dummy_globals['DummyBackend']

print("✓ Loaded DummyBackend")

# Test it!
print("\n=== Testing DummyBackend ===")
dummy = DummyBackend()

# List interfaces
interfaces = dummy.list_interfaces()
print(f"Found {len(interfaces)} interfaces:")
for iface in interfaces:
    print(f"  {iface['name']}: {iface['description']}")

# Start capture
config = CaptureConfig(interface="dummy0", buffer_size=100)
session_id = dummy.start(config)
print(f"\nStarted capture: {session_id}")

import time
for i in range(3):
    time.sleep(1)
    stats = dummy.get_stats(session_id)
    print(f"  After {i+1}s: {stats['packets_per_sec']} pps, "
          f"{stats['packets_total']} total")

# Stop
metadata = dummy.stop(session_id)
print(f"\nStopped. Total: {metadata['stats_summary']['packets_total']} packets")
print(f"Drops: {metadata['stats_summary']['drops_total']}")

print("\n✓ Test successful!")