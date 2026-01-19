"""
Simple test for live packet capture.
Run this from the project root directory.
"""
import sys
import os

# Add src to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

from capture import ScapyBackend, DummyBackend

def test_interfaces():
    """Test listing network interfaces."""
    print("=== Testing ScapyBackend (Real Capture) ===")
    try:
        backend = ScapyBackend()
        interfaces = backend.list_interfaces()
        print(f"Found {len(interfaces)} interface(s):")
        for i, iface in enumerate(interfaces):
            print(f"  {i+1}. {iface['name']} - {iface['description']}")
            print(f"     MAC: {iface['mac']}")
            print(f"     IPs: {', '.join(iface['ips']) if iface['ips'] else 'None'}")
    except Exception as e:
        print(f"✗ ScapyBackend failed: {e}")
        print("Note: You need NpCap installed from https://npcap.com/")
        print("      Make sure to install in 'WinPcap API-compatible mode'")
    
    print("\n=== Testing DummyBackend (Synthetic Packets) ===")
    try:
        dummy = DummyBackend()
        interfaces = dummy.list_interfaces()
        print(f"Found {len(interfaces)} dummy interface(s):")
        for i, iface in enumerate(interfaces):
            print(f"  {i+1}. {iface['name']} - {iface['description']}")
    except Exception as e:
        print(f"✗ DummyBackend failed: {e}")

def test_capture():
    """Test capturing packets."""
    print("\n=== Testing Capture (Dummy Mode) ===")
    
    # Use dummy backend first (works without NpCap)
    from capture.icapture_backend import CaptureConfig
    
    try:
        dummy = DummyBackend()
        
        # Start capture on dummy interface
        config = CaptureConfig(interface="dummy0", buffer_size=100)
        session_id = dummy.start(config)
        print(f"Started capture session: {session_id}")
        
        # Capture for 3 seconds
        import time
        for i in range(3):
            time.sleep(1)
            stats = dummy.get_stats(session_id)
            print(f"  After {i+1}s: {stats['packets_per_sec']} pps, "
                  f"{stats['packets_total']} total, "
                  f"{stats['drops_total']} drops")
        
        # Get some packets
        packets = dummy.get_packets(session_id, count=5)
        print(f"\nSample packets captured: {len(packets)}")
        for i, pkt in enumerate(packets):
            print(f"  Packet {i+1}: {len(pkt['data'])} bytes at {pkt['ts']:.3f}")
        
        # Stop capture
        metadata = dummy.stop(session_id)
        print(f"\nCapture stopped.")
        print(f"Final stats: {metadata['stats_summary']['packets_total']} packets, "
              f"{metadata['stats_summary']['bytes_total']} bytes")
        
    except Exception as e:
        print(f"✗ Capture test failed: {e}")
        import traceback
        traceback.print_exc()

def test_real_capture():
    """Test real capture if NpCap is available."""
    print("\n=== Testing Real Capture (requires NpCap) ===")
    
    from capture.icapture_backend import CaptureConfig
    
    try:
        backend = ScapyBackend()
        interfaces = backend.list_interfaces()
        
        if not interfaces:
            print("No interfaces found. Is NpCap installed?")
            return
        
        # Use first interface
        interface_name = interfaces[0]['name']
        print(f"Attempting capture on interface: {interface_name}")
        
        config = CaptureConfig(
            interface=interface_name,
            filter="tcp port 80 or tcp port 443",  # Web traffic only
            buffer_size=1000
        )
        
        session_id = backend.start(config)
        print(f"Started capture. Session ID: {session_id}")
        print("Capturing for 5 seconds (press Ctrl+C to stop early)...")
        
        try:
            import time
            start_time = time.time()
            while time.time() - start_time < 5:
                time.sleep(1)
                stats = backend.get_stats(session_id)
                print(f"  Stats: {stats['packets_per_sec']} pps, "
                      f"{stats['bytes_per_sec']} bps, "
                      f"{stats['queue_depth']} in queue")
        except KeyboardInterrupt:
            print("\nStopping early...")
        
        metadata = backend.stop(session_id)
        print(f"\nCapture complete!")
        print(f"Total: {metadata['stats_summary']['packets_total']} packets")
        print(f"Drops: {metadata['stats_summary']['drops_total']}")
        
    except Exception as e:
        print(f"✗ Real capture failed: {e}")
        print("\nTroubleshooting tips:")
        print("1. Install NpCap from https://npcap.com/")
        print("2. Choose 'WinPcap API-compatible mode' during installation")
        print("3. Reboot if prompted")
        print("4. Run as Administrator if needed")

if __name__ == "__main__":
    print("Asphalt Packet Capture Test")
    print("=" * 50)
    
    test_interfaces()
    test_capture()
    
    # Ask user if they want to try real capture
    response = input("\nDo you want to test REAL packet capture? (y/n): ")
    if response.lower() == 'y':
        test_real_capture()
    
    print("\nTest complete!")