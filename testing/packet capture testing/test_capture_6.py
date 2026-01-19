"""
Test full integration: Live capture → PacketIndexBuilder → SessionManifest
"""
import sys
import os

# Add src to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

# Import your existing components
try:
    from pcap_loader.packet_source import IPacketSource
    from pcap_loader.packet_index import PacketIndexBuilder
    from models.session import SessionManifest
    from models.packet import RawPacket as ExistingRawPacket
    print("✓ Imported existing pipeline components")
except ImportError as e:
    print(f"✗ Could not import existing components: {e}")
    print("Creating minimal versions for testing...")
    
    # Minimal versions for testing
    class IPacketSource:
        def open(self): pass
        def __iter__(self): pass
        def close(self): pass
    
    class PacketIndexBuilder:
        def __init__(self, session):
            self.session = session
            self.index = []
        
        def __enter__(self):
            return self
        
        def __exit__(self, *args):
            pass
        
        def create_index_record(self, packet):
            return {
                'timestamp': packet.timestamp,
                'length': len(packet.data),
                'interface': packet.interface
            }
        
        def add_record(self, record):
            self.index.append(record)
    
    class SessionManifest:
        def __init__(self):
            import uuid
            self.session_id = str(uuid.uuid4())
            self.packet_index = []
    
    class ExistingRawPacket:
        def __init__(self, timestamp=0, data=b"", capture_length=0, wire_length=0, interface=""):
            self.timestamp = timestamp
            self.data = data
            self.capture_length = capture_length
            self.wire_length = wire_length
            self.interface = interface

from capture import LiveCaptureSource

def test_integration():
    print("\n=== Full Pipeline Integration Test ===")
    print("This tests: LiveCapture → PacketIndexBuilder → SessionManifest")
    
    # Use dummy interface for reliable testing
    source = LiveCaptureSource(interface="dummy0")
    
    # Create session (your existing code)
    session = SessionManifest()
    
    # Use your existing PacketIndexBuilder
    with PacketIndexBuilder(session) as index_builder:
        print(f"Session ID: {session.session_id}")
        print("Starting capture... (5 seconds)")
        
        source.open()
        
        packet_count = 0
        try:
            for raw_packet in source:
                # This is where your existing pipeline processes packets!
                index_record = index_builder.create_index_record(raw_packet)
                index_builder.add_record(index_record)
                
                packet_count += 1
                
                # Show progress
                if packet_count % 20 == 0:
                    stats = source.get_stats()
                    print(f"  Processed {packet_count} packets, "
                          f"current rate: {stats['packets_per_sec']} pps")
                
                # Stop after 5 seconds or 100 packets
                if packet_count >= 100:
                    break
                    
        finally:
            metadata = source.close()
    
    print(f"\nCapture complete!")
    print(f"Total packets processed: {packet_count}")
    print(f"Session has {len(session.packet_index)} index records")
    
    # Show first few records
    if hasattr(session, 'packet_index') and session.packet_index:
        print("\nFirst 3 index records:")
        for i, record in enumerate(session.packet_index[:3]):
            if isinstance(record, dict):
                print(f"  {i+1}. ts={record.get('timestamp', 'N/A')}, "
                      f"len={record.get('length', 'N/A')}")
            else:
                print(f"  {i+1}. {record}")

if __name__ == "__main__":
    test_integration()