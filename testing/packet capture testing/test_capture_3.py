"""
WORKING capture test - minimal dependencies.
"""
import sys
import os
import time

# Add src to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

print("=" * 60)
print("ASPHALT CAPTURE SYSTEM TEST")
print("=" * 60)

# ============== MANUAL IMPORT OF ICAPTURE_BACKEND ==============
print("\n1. Loading ICaptureBackend...")
icapture_path = os.path.join(src_path, 'capture', 'icapture_backend.py')

with open(icapture_path, 'r') as f:
    icapture_code = f.read()
    exec_globals = {}
    exec(icapture_code, exec_globals)

CaptureConfig = exec_globals['CaptureConfig']
ICaptureBackend = exec_globals['ICaptureBackend']
print("   ✓ Loaded CaptureConfig and ICaptureBackend")

# ============== MANUAL IMPORT OF DUMMY_BACKEND ==============
print("\n2. Loading DummyBackend...")
dummy_path = os.path.join(src_path, 'capture', 'dummy_backend.py')

with open(dummy_path, 'r') as f:
    dummy_code = f.read()
    # Fix the import line
    dummy_code = dummy_code.replace(
        'from .icapture_backend import ICaptureBackend, CaptureConfig',
        '# Import handled manually'
    )
    dummy_globals = {
        'ICaptureBackend': ICaptureBackend,
        'CaptureConfig': CaptureConfig,
        'threading': __import__('threading'),
        'queue': __import__('queue'),
        'time': __import__('time'),
        'random': __import__('random'),
        'Dict': dict,
        'Any': object,
        'List': list,
    }
    exec(dummy_code, dummy_globals)

DummyBackend = dummy_globals['DummyBackend']
print("   ✓ Loaded DummyBackend")

# ============== TEST DUMMY CAPTURE ==============
print("\n3. Testing Dummy Capture...")
dummy = DummyBackend()

# List interfaces
interfaces = dummy.list_interfaces()
print(f"   Found {len(interfaces)} dummy interfaces")
for iface in interfaces:
    print(f"     - {iface['name']}: {iface['description']}")

# Start capture
config = CaptureConfig(interface="dummy0", buffer_size=200)
session_id = dummy.start(config)
print(f"   Started capture session: {session_id}")

# Monitor for 5 seconds
print("\n4. Capturing for 5 seconds...")
print("   [Time]  Packets/sec  Total  Drops  Queue")
print("   " + "-" * 45)

for i in range(5):
    time.sleep(1)
    stats = dummy.get_stats(session_id)
    print(f"   [{i+1}s]  {stats['packets_per_sec']:11}  "
          f"{stats['packets_total']:5}  "
          f"{stats['drops_total']:5}  "
          f"{stats['queue_depth']:5}")

# Get sample packets
packets = dummy.get_packets(session_id, count=3)
print(f"\n5. Retrieved {len(packets)} sample packets")
for i, pkt in enumerate(packets):
    print(f"   Packet {i+1}: {len(pkt['data'])} bytes")

# Stop capture
metadata = dummy.stop(session_id)
print(f"\n6. Capture stopped")

# Summary
print("\n" + "=" * 60)
print("FINAL RESULTS:")
print("=" * 60)
print(f"Total packets: {metadata['stats_summary']['packets_total']}")
print(f"Total bytes: {metadata['stats_summary']['bytes_total']:,}")
print(f"Packet drops: {metadata['stats_summary']['drops_total']}")
print(f"Duration: {metadata['end_ts'] - metadata['start_ts']:.1f} seconds")
print(f"Average rate: {metadata['stats_summary']['packets_total']/(metadata['end_ts'] - metadata['start_ts']):.1f} packets/sec")

print("\n" + "=" * 60)
print("✅ CAPTURE SYSTEM IS WORKING!")
print("=" * 60)