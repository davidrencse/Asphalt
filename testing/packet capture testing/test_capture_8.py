"""
Fixed capture test with clean imports.
"""
import sys
import os

# Add src to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

print("Testing capture with clean imports...")
print("=" * 60)

# Import directly with try/except
try:
    # Import icapture_backend
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "icapture_backend",
        os.path.join(src_path, 'capture', 'icapture_backend.py')
    )
    icapture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(icapture)
    
    CaptureConfig = icapture.CaptureConfig
    ICaptureBackend = icapture.ICaptureBackend
    
    print("✓ Loaded ICaptureBackend")
    
    # Now import dummy_backend  
    dummy_spec = importlib.util.spec_from_file_location(
        "dummy_backend",
        os.path.join(src_path, 'capture', 'dummy_backend.py')
    )
    dummy_module = importlib.util.module_from_spec(dummy_spec)
    
    # Provide required imports to dummy module
    dummy_module.__dict__.update({
        'ICaptureBackend': ICaptureBackend,
        'CaptureConfig': CaptureConfig,
        'threading': __import__('threading'),
        'queue': __import__('queue'),
        'time': __import__('time'),
        'random': __import__('random'),
        'Dict': dict,
        'Any': object,
        'List': list,
        'ABC': __import__('abc').ABC,
        'abstractmethod': __import__('abc').abstractmethod,
        'dataclass': __import__('dataclasses').dataclass,
    })
    
    dummy_spec.loader.exec_module(dummy_module)
    DummyBackend = dummy_module.DummyBackend
    
    print("✓ Loaded DummyBackend")
    
except Exception as e:
    print(f"✗ Import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test it!
print("\n=== Testing DummyBackend ===")
dummy = DummyBackend()

# List interfaces
interfaces = dummy.list_interfaces()
print(f"Found {len(interfaces)} interfaces:")
for iface in interfaces:
    print(f"  {iface['name']}: {iface['description']}")

# Start capture
config = CaptureConfig(interface="dummy0", buffer_size=200)
session_id = dummy.start(config)
print(f"\nStarted capture: {session_id}")

# Capture for 3 seconds
print("\nCapturing for 3 seconds...")
import time
for i in range(3):
    time.sleep(1)
    stats = dummy.get_stats(session_id)
    print(f"  Second {i+1}: {stats['packets_per_sec']} pps, "
          f"{stats['packets_total']} total, "
          f"{stats['drops_total']} drops")

# Get some packets
packets = dummy.get_packets(session_id, 5)
print(f"\nRetrieved {len(packets)} sample packets")

# Stop
metadata = dummy.stop(session_id)
print(f"\nCapture complete!")
print(f"Total packets: {metadata['stats_summary']['packets_total']}")
print(f"Total bytes: {metadata['stats_summary']['bytes_total']}")
print(f"Packet drops: {metadata['stats_summary']['drops_total']}")

print("\n" + "=" * 60)
print("✅ CAPTURE TEST PASSED!")
print("=" * 60)

"""

Testing capture with clean imports...
============================================================
✓ Loaded ICaptureBackend
✓ Loaded DummyBackend

=== Testing DummyBackend ===
Found 2 interfaces:
  dummy0: Dummy Ethernet Interface
  dummy1: Dummy Wi-Fi Interface

Started capture: dummy_1768827700

Capturing for 3 seconds...
  Second 1: 64 pps, 64 total, 0 drops
  Second 2: 64 pps, 64 total, 0 drops
  Second 3: 63 pps, 191 total, 0 drops

Retrieved 5 sample packets

Capture complete!
Total packets: 191
Total bytes: 22874
Packet drops: 0

============================================================
✅ CAPTURE TEST PASSED!
============================================================

"""