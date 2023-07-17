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
        if not SCAPY_AVAILABLE:
            return []
        
        interfaces = []
        
        try:
            # Get raw interface GUIDs (what NpCap sees)
            iface_guids = get_if_list()
            
            # Get Windows interface details with human-readable names
            # Try to import Windows-specific function
            try:
                from scapy.arch.windows import get_windows_if_list
                win_ifaces = get_windows_if_list()
                
                # Create mapping from GUID to Windows interface info
                guid_to_wininfo = {}
                for win_iface in win_ifaces:
                    guid = win_iface.get('guid', '')
                    if guid:
                        guid_to_wininfo[guid] = win_iface
                
            except ImportError:
                win_ifaces = []
                guid_to_wininfo = {}
            
            # If Scapy returns no NPF interfaces, fall back to Windows list
            if not iface_guids and win_ifaces:
                for win_iface in win_ifaces:
                    guid = win_iface.get('guid', '')
                    if guid:
                        iface_guids.append(rf"\\Device\\NPF_{guid}")

            for iface_guid in iface_guids:
                try:
                    # Extract GUID from NpCap device name
                    # Format: \Device\NPF_{GUID} or \Device\NPF_Loopback
                    if iface_guid == r'\Device\NPF_Loopback':
                        guid = 'Loopback'
                        description = 'Loopback Interface'
                        is_up = True
                        ips = ['127.0.0.1', '::1']
                        mac = '00:00:00:00:00:00'
                    else:
                        # Extract GUID from \Device\NPF_{GUID}
                        guid_start = iface_guid.find('{')
                        guid_end = iface_guid.find('}')
                        if guid_start != -1 and guid_end != -1:
                            guid = iface_guid[guid_start:guid_end+1]  # Keep braces
                        else:
                            guid = iface_guid
