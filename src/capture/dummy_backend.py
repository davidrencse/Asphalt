"""
Dummy capture backend for testing without NpCap.
"""
import threading
import queue
import time
import random
from typing import Dict, Any, List

# Import from icapture_backend
try:
    # Try absolute import
    from capture.icapture_backend import ICaptureBackend, CaptureConfig
except ImportError:
    # Fallback to relative import
    try:
        from .icapture_backend import ICaptureBackend, CaptureConfig
    except ImportError:
        # Ultimate fallback: define locally
        from abc import ABC, abstractmethod
        from dataclasses import dataclass
        
        @dataclass
        class CaptureConfig:
            interface: str
            buffer_size: int = 10000
        
        class ICaptureBackend(ABC):
            @abstractmethod
            def start(self, config: CaptureConfig) -> str: pass
            @abstractmethod
            def stop(self, session_id: str) -> Dict[str, Any]: pass
            @abstractmethod
            def get_stats(self, session_id: str) -> Dict[str, Any]: pass
            @abstractmethod
            def get_packets(self, session_id: str, count: int = 100) -> List[Dict]: pass
            @abstractmethod
            def list_interfaces(self) -> List[Dict]: pass

class DummyBackend(ICaptureBackend):
    """Dummy backend that generates synthetic packets for testing."""
    
    def __init__(self):
        self._sessions: Dict[str, Dict] = {}
        self._lock = threading.RLock()
        self._packet_counter = 0
    
    def list_interfaces(self) -> List[Dict]:
        """Return dummy interfaces."""
        return [
            {
                'id': 'dummy0',
                'name': 'dummy0',
                'description': 'Dummy Ethernet Interface',
                'is_up': True,
                'mac': '00:11:22:33:44:55',
                'ips': ['192.168.1.100', '10.0.0.1'],
                'link_type': 'Ethernet',
            },
            {
                'id': 'dummy1',
                'name': 'dummy1',
                'description': 'Dummy Wi-Fi Interface',
                'is_up': True,
                'mac': 'AA:BB:CC:DD:EE:FF',
                'ips': ['192.168.1.101'],
                'link_type': 'Wi-Fi',
            }
        ]
    
    def start(self, config: CaptureConfig) -> str:
        with self._lock:
            session_id = f"dummy_{int(time.time())}"
            
            # Create packet queue
            packet_queue = queue.Queue(maxsize=config.buffer_size)
            stop_event = threading.Event()
            stats = {
                'packets_total': 0,
                'bytes_total': 0,
                'packets_per_sec': 0,
                'bytes_per_sec': 0,
                'drops_total': 0,
                'queue_depth': 0,
                'start_time': time.time(),
                'last_update': time.time(),
                'packets_since_update': 0,
                'bytes_since_update': 0,
            }
            
            def generate_packet():
                """Generate a dummy packet."""
                self._packet_counter += 1
                packet_types = [
                    b'\x08\x00',  # IPv4
                    b'\x08\x06',  # ARP
                    b'\x86\xdd',  # IPv6
                ]
                
                # Simple dummy packet
                eth_dst = b'\xff\xff\xff\xff\xff\xff'  # Broadcast
                eth_src = b'\x00\x11\x22\x33\x44\x55'
                eth_type = random.choice(packet_types)
                
                # Basic IP header for IPv4
                if eth_type == b'\x08\x00':
                    ip_header = bytes([
                        0x45, 0x00, 0x00, 0x28,  # Version, IHL, DSCP, ECN | Total Length
                        0x00, 0x01, 0x00, 0x00,  # Identification | Flags, Fragment Offset
                        0x40, 0x06, 0x00, 0x00,  # TTL, Protocol | Header Checksum
                        192, 168, 1, 1,          # Source IP
                        192, 168, 1, 100,        # Destination IP
                    ])
                    packet_data = eth_dst + eth_src + eth_type + ip_header + b'\x00' * 100
                else:
                    packet_data = eth_dst + eth_src + eth_type + b'\x00' * 100
                
                return packet_data
            
            def packet_generator():
                """Generate packets in background."""
                while not stop_event.is_set():
                    try:
                        packet_data = generate_packet()
                        packet_info = {
                            'ts': time.time(),
                            'data': packet_data,
                            'wirelen': len(packet_data),
                        }
                        
                        try:
                            packet_queue.put_nowait(packet_info)
                            stats['packets_since_update'] += 1
                            stats['bytes_since_update'] += len(packet_data)
                        except queue.Full:
                            stats['drops_total'] += 1
                        
                        # Update stats every second
                        current_time = time.time()
                        if current_time - stats['last_update'] >= 1.0:
                            stats['packets_per_sec'] = stats['packets_since_update']
                            stats['bytes_per_sec'] = stats['bytes_since_update']
                            stats['packets_total'] += stats['packets_since_update']
                            stats['bytes_total'] += stats['bytes_since_update']
                            stats['queue_depth'] = packet_queue.qsize()
                            stats['packets_since_update'] = 0
                            stats['bytes_since_update'] = 0
                            stats['last_update'] = current_time
                        
                        # Sleep to simulate packet rate
                        time.sleep(0.01)  # ~100 packets/sec
                        
                    except Exception as e:
                        print(f"Error in dummy packet generator: {e}")
            
            # Start packet generator thread
            generator_thread = threading.Thread(
                target=packet_generator,
                daemon=True
            )
            generator_thread.start()
            
            # Store session
            self._sessions[session_id] = {
                'queue': packet_queue,
                'stop_event': stop_event,
                'generator_thread': generator_thread,
                'config': config,
                'stats': stats,
                'stats_lock': threading.Lock(),
            }
            
            return session_id
    
    def stop(self, session_id: str) -> Dict[str, Any]:
        with self._lock:
            if session_id not in self._sessions:
                raise ValueError(f"Session {session_id} not found")
            
            session = self._sessions[session_id]
            
            # Signal stop
            session['stop_event'].set()
            session['generator_thread'].join(timeout=1.0)
            
            # Prepare metadata
            metadata = {
                'session_id': session_id,
                'backend': 'dummy',
                'interface': session['config'].interface,
                'start_ts': session['stats']['start_time'],
                'end_ts': time.time(),
                'config': {'interface': session['config'].interface, 'buffer_size': session['config'].buffer_size},
                'stats_summary': session['stats'].copy()
            }
            
            # Remove session
            del self._sessions[session_id]
            
            return metadata
    
    def get_stats(self, session_id: str) -> Dict[str, Any]:
        with self._lock:
            if session_id not in self._sessions:
                raise ValueError(f"Session {session_id} not found")
            
            session = self._sessions[session_id]
            return session['stats'].copy()
    
    def get_packets(self, session_id: str, count: int = 100) -> List[Dict]:
        with self._lock:
            if session_id not in self._sessions:
                raise ValueError(f"Session {session_id} not found")
            
            session = self._sessions[session_id]
            packets = []
            
            for _ in range(min(count, session['queue'].qsize())):
                try:
                    packets.append(session['queue'].get_nowait())
                except queue.Empty:
                    break
            
            return packets