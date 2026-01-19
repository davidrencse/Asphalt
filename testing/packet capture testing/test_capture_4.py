"""
Test real packet capture with your existing pipeline.
"""
import sys
import os

# Add src to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

from capture import ScapyBackend, CaptureConfig
import time

print("Real Packet Capture Test")
print("=" * 50)

# Create backend
backend = ScapyBackend()

# List interfaces
interfaces = backend.list_interfaces()
print(f"Found {len(interfaces)} interfaces:\n")
for i, iface in enumerate(interfaces):
    print(f"{i+1}. {iface['name']}")
    print(f"   Description: {iface['description']}")
    if iface['ips']:
        print(f"   IP Addresses: {', '.join(iface['ips'])}")
    print()

# Ask user to select interface
if not interfaces:
    print("No interfaces found. Is NpCap installed?")
    sys.exit(1)

selection = input(f"Select interface (1-{len(interfaces)}), or enter name: ").strip()

if selection.isdigit():
    iface_index = int(selection) - 1
    if 0 <= iface_index < len(interfaces):
        interface_name = interfaces[iface_index]['name']
    else:
        print("Invalid selection")
        sys.exit(1)
else:
    # Try to find by name
    interface_name = selection
    found = False
    for iface in interfaces:
        if iface['name'] == interface_name or iface['description'] == interface_name:
            found = True
            break
    if not found:
        print(f"Interface '{interface_name}' not found")
        sys.exit(1)

# Ask for capture parameters
duration = input("Capture duration in seconds (default: 10): ").strip()
duration = int(duration) if duration else 10

filter_str = input("BPF filter (e.g., 'tcp port 80', leave empty for all): ").strip()
filter_str = filter_str if filter_str else None

print(f"\nStarting capture on '{interface_name}' for {duration} seconds...")
print("Press Ctrl+C to stop early\n")

# Start capture
config = CaptureConfig(
    interface=interface_name,
    filter=filter_str,
    buffer_size=10000,
    promisc=True
)

try:
    session_id = backend.start(config)
    print(f"Session ID: {session_id}")
    
    # Monitor stats
    start_time = time.time()
    last_display = start_time
    
    while time.time() - start_time < duration:
        time.sleep(0.5)  # Update twice per second
        
        stats = backend.get_stats(session_id)
        current_time = time.time()
        
        if current_time - last_display >= 1.0:  # Update display every second
            elapsed = current_time - start_time
            print(f"\r[{elapsed:.1f}s] {stats['packets_per_sec']} pps | "
                  f"{stats['bytes_per_sec']/1024:.1f} KB/s | "
                  f"Total: {stats['packets_total']} pkts | "
                  f"Drops: {stats['drops_total']} | "
                  f"Queue: {stats['queue_depth']}", end="", flush=True)
            last_display = current_time
        
except KeyboardInterrupt:
    print("\n\nStopping capture...")
except Exception as e:
    print(f"\nError during capture: {e}")
finally:
    # Stop capture
    metadata = backend.stop(session_id)
    
    print(f"\n\n{'='*50}")
    print("CAPTURE COMPLETE")
    print(f"{'='*50}")
    print(f"Session: {metadata['session_id']}")
    print(f"Interface: {metadata['interface']}")
    print(f"Duration: {metadata['end_ts'] - metadata['start_ts']:.1f}s")
    print(f"Total Packets: {metadata['stats_summary']['packets_total']}")
    print(f"Total Bytes: {metadata['stats_summary']['bytes_total']}")
    print(f"Average Rate: {metadata['stats_summary']['packets_total']/(metadata['end_ts'] - metadata['start_ts']):.1f} pps")
    print(f"Packet Drops: {metadata['stats_summary']['drops_total']}")
    
    # Show sample packets
    print(f"\nSample packets (first 5):")
    # We can't get packets after stop, but you could modify backend to keep them