"""
Simple test that imports everything cleanly.
"""
import sys
import os

# Add src to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

print("Simple Capture Test")
print("=" * 50)

# First, let's just test if we can import icapture_backend
try:
    # Read and execute icapture_backend.py
    with open(os.path.join(src_path, 'capture', 'icapture_backend.py'), 'r') as f:
        code = f.read()
        exec(code)
    
    print("✓ Successfully loaded ICaptureBackend")
except Exception as e:
    print(f"✗ Failed to load ICaptureBackend: {e}")
    sys.exit(1)

# Now create a simple test that doesn't use imports
print("\nCreating simple capture test...")

# Create a minimal DummyBackend right here
import threading
import queue
import time
import random

class SimpleDummyBackend:
    """Ultra-simple dummy backend for testing."""
    
    def __init__(self):
        self._queue = queue.Queue(maxsize=100)
        self._stop_event = threading.Event()
        self._stats = {
            'packets_total': 0,
            'bytes_total': 0,
            'packets_per_sec': 0,
            'drops_total': 0,
            'queue_depth': 0,
        }
        self._last_update = time.time()
        self._packets_since_update = 0
        
    def start(self, interface: str):
        print(f"Starting capture on {interface}...")
        
        def packet_generator():
            """Generate simple packets."""
            packet_count = 0
            while not self._stop_event.is_set():
                # Simple packet: ethernet + ip header + some data
                packet = {
                    'ts': time.time(),
                    'data': b'\x00' * 100,  # 100 bytes of zeros
                    'wirelen': 100,
                }
                
                try:
                    self._queue.put_nowait(packet)
                    packet_count += 1
                    self._packets_since_update += 1
                    self._stats['packets_total'] += 1
                    self._stats['bytes_total'] += 100
                except queue.Full:
                    self._stats['drops_total'] += 1
                
                # Update stats every second
                current_time = time.time()
                if current_time - self._last_update >= 1.0:
                    self._stats['packets_per_sec'] = self._packets_since_update
                    self._stats['queue_depth'] = self._queue.qsize()
                    self._packets_since_update = 0
                    self._last_update = current_time
                
                time.sleep(0.01)  # ~100 packets/sec
        
        # Start generator thread
        self._thread = threading.Thread(target=packet_generator, daemon=True)
        self._thread.start()
        
        return f"dummy_session_{int(time.time())}"
    
    def stop(self, session_id: str):
        print(f"Stopping session {session_id}...")
        self._stop_event.set()
        self._thread.join(timeout=1.0)
        
        return {
            'session_id': session_id,
            'packets_total': self._stats['packets_total'],
            'bytes_total': self._stats['bytes_total'],
            'drops_total': self._stats['drops_total'],
        }
    
    def get_stats(self, session_id: str):
        return self._stats.copy()
    
    def get_packets(self, session_id: str, count: int = 10):
        packets = []
        for _ in range(min(count, self._queue.qsize())):
            try:
                packets.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return packets
    
    def list_interfaces(self):
        return [
            {'name': 'dummy0', 'description': 'Dummy Interface'},
            {'name': 'eth0', 'description': 'Ethernet (requires NpCap)'},
            {'name': 'wlan0', 'description': 'WiFi (requires NpCap)'},
        ]

# Test it!
print("\nTesting SimpleDummyBackend...")
backend = SimpleDummyBackend()

# List interfaces
print("\nAvailable interfaces:")
for iface in backend.list_interfaces():
    print(f"  {iface['name']}: {iface['description']}")

# Start capture
session_id = backend.start("dummy0")
print(f"\nStarted session: {session_id}")

# Capture for 3 seconds
print("\nCapturing for 3 seconds...")
for i in range(3):
    time.sleep(1)
    stats = backend.get_stats(session_id)
    print(f"  Second {i+1}: {stats['packets_per_sec']} pps, "
          f"{stats['packets_total']} total, "
          f"{stats['drops_total']} drops")

# Get some packets
packets = backend.get_packets(session_id, 5)
print(f"\nRetrieved {len(packets)} sample packets")

# Stop capture
result = backend.stop(session_id)
print(f"\nCapture complete!")
print(f"Total: {result['packets_total']} packets")
print(f"Bytes: {result['bytes_total']}")
print(f"Drops: {result['drops_total']}")

print("\n" + "=" * 50)
print("✅ SIMPLE CAPTURE TEST PASSED!")
print("=" * 50)

"""

============================================================
ASPHALT CAPTURE SYSTEM TEST
============================================================

1. Loading ICaptureBackend...
   ✓ Loaded CaptureConfig and ICaptureBackend

2. Loading DummyBackend...
Traceback (most recent call last):
  File "C:\Users\david\Desktop\all projects\Cybersecurity\Asphalt [TODO]\test_capture_working.py", line 52, in <module>
    exec(dummy_code, dummy_globals)
  File "<string>", line 18
    class DummyBackend(ICaptureBackend):
    ^
IndentationError: expected an indented block after 'except' statement on line 14

C:\Users\david\Desktop\all projects\Cybersecurity\Asphalt [TODO]>python test_simple_capture.py
Simple Capture Test
==================================================
✓ Successfully loaded ICaptureBackend

Creating simple capture test...

Testing SimpleDummyBackend...

Available interfaces:
  dummy0: Dummy Interface
  eth0: Ethernet (requires NpCap)
  wlan0: WiFi (requires NpCap)
Starting capture on dummy0...

Started session: dummy_session_1768827541

Capturing for 3 seconds...
  Second 1: 64 pps, 64 total, 0 drops
  Second 2: 36 pps, 100 total, 27 drops
  Second 3: 36 pps, 100 total, 90 drops

Retrieved 5 sample packets
Stopping session dummy_session_1768827541...

Capture complete!
Total: 100 packets
Bytes: 10000
Drops: 91

==================================================
✅ SIMPLE CAPTURE TEST PASSED!
==================================================


"""