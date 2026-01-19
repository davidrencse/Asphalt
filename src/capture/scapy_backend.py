import threading
import queue
import time
from typing import Dict, Any, Optional, List
# Try different import methods
try:
    # Try absolute import
    from capture.icapture_backend import ICaptureBackend, CaptureConfig
except ImportError:
    # Fallback to relative import
    from .icapture_backend import ICaptureBackend, CaptureConfig

try:
    from scapy.all import sniff, get_if_list, get_if_addr, conf, AsyncSniffer
    from scapy.interfaces import NetworkInterface
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class ScapyBackend(ICaptureBackend):
    """Scapy-based capture backend for Windows."""
    
    def __init__(self):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available. Install with: pip install scapy")
        
        self._sessions: Dict[str, Dict] = {}
        self._lock = threading.RLock()
    
    def list_interfaces(self) -> List[Dict]:
        """List Windows network interfaces using Scapy."""
        interfaces = []
        
        for iface_name in get_if_list():
            try:
                # Get interface details
                iface = NetworkInterface(iface_name)
                addresses = get_if_addr(iface)
                
                interfaces.append({
                    'id': iface_name,
                    'name': iface_name,
                    'description': iface.description if hasattr(iface, 'description') else iface_name,
                    'is_up': True,  # Scapy doesn't easily check this
                    'mac': iface.mac if hasattr(iface, 'mac') else None,
                    'ips': [addr for addr in addresses.values()] if addresses else [],
                    'link_type': 'Ethernet',  # Default assumption
                })
            except Exception as e:
                # Fallback minimal info
                interfaces.append({
                    'id': iface_name,
                    'name': iface_name,
                    'description': iface_name,
                    'is_up': True,
                    'mac': None,
                    'ips': [],
                    'link_type': 'Unknown',
                })
        
        return interfaces
    
    def start(self, config: CaptureConfig) -> str:
        with self._lock:
            session_id = f"scapy_{int(time.time())}_{hash(config.interface)}"
            
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
            
            def packet_callback(packet):
                """Callback for each captured packet."""
                nonlocal stats
                
                try:
                    # Convert Scapy packet to our format
                    packet_data = {
                        'ts': packet.time,
                        'data': bytes(packet),
                        'wirelen': len(packet),
                        'scapy_packet': packet,  # Keep for debugging
                    }
                    
                    try:
                        packet_queue.put_nowait(packet_data)
                        stats['packets_since_update'] += 1
                        stats['bytes_since_update'] += len(packet)
                    except queue.Full:
                        stats['drops_total'] += 1
                    
                    # Update rate stats every second
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
                        
                except Exception as e:
                    print(f"Error in packet callback: {e}")
            
            # Start Scapy AsyncSniffer
            sniffer = AsyncSniffer(
                iface=config.interface,
                prn=packet_callback,
                filter=config.filter,
                store=False,  # Don't store in Scapy's memory
                promisc=config.promisc,
                monitor=config.monitor,
            )
            
            sniffer.start()
            
            # Store session
            self._sessions[session_id] = {
                'sniffer': sniffer,
                'queue': packet_queue,
                'stop_event': stop_event,
                'config': config,
                'stats': stats,
                'stats_lock': threading.Lock(),
            }
            
            # Start stats updater thread
            stats_thread = threading.Thread(
                target=self._stats_updater,
                args=(session_id, stop_event),
                daemon=True
            )
            stats_thread.start()
            
            return session_id
    
    def _stats_updater(self, session_id: str, stop_event: threading.Event):
        """Update stats periodically."""
        while not stop_event.is_set():
            time.sleep(1)
            with self._lock:
                if session_id in self._sessions:
                    session = self._sessions[session_id]
                    stats = session['stats']
                    queue = session['queue']
                    
                    with session['stats_lock']:
                        # Final update of rates
                        stats['packets_per_sec'] = stats['packets_since_update']
                        stats['bytes_per_sec'] = stats['bytes_since_update']
                        stats['packets_total'] += stats['packets_since_update']
                        stats['bytes_total'] += stats['bytes_since_update']
                        stats['queue_depth'] = queue.qsize()
                        stats['packets_since_update'] = 0
                        stats['bytes_since_update'] = 0
                        stats['last_update'] = time.time()
    
    def stop(self, session_id: str) -> Dict[str, Any]:
        with self._lock:
            if session_id not in self._sessions:
                raise ValueError(f"Session {session_id} not found")
            
            session = self._sessions[session_id]
            
            # Signal stop
            session['stop_event'].set()
            
            # Stop Scapy sniffer
            session['sniffer'].stop()
            
            # Wait for it to stop
            time.sleep(0.5)
            
            # Prepare metadata
            metadata = {
                'session_id': session_id,
                'backend': 'scapy',
                'interface': session['config'].interface,
                'start_ts': session['stats']['start_time'],
                'end_ts': time.time(),
                'config': {
                    'interface': session['config'].interface,
                    'snaplen': session['config'].snaplen,
                    'promisc': session['config'].promisc,
                    'filter': session['config'].filter,
                },
                'stats_summary': session['stats'].copy()
            }
            
            # Remove final queue items
            metadata['stats_summary']['final_queue_size'] = session['queue'].qsize()
            
            # Remove session
            del self._sessions[session_id]
            
            return metadata
    
    def get_stats(self, session_id: str) -> Dict[str, Any]:
        with self._lock:
            if session_id not in self._sessions:
                raise ValueError(f"Session {session_id} not found")
            
            session = self._sessions[session_id]
            with session['stats_lock']:
                return session['stats'].copy()
    
    def get_packets(self, session_id: str, count: int = 100) -> List[Dict]:
        """Get captured packets from the queue."""
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