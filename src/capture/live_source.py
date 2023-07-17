"""
LiveCaptureSource using Scapy backend.
Simplified version without circular imports.
"""
import time
from typing import Iterator, Optional

# Don't import IPacketSource - define it locally
class IPacketSource:
    """Minimal interface for compatibility."""
    def open(self): pass
    def __iter__(self): pass  
    def close(self): pass

# Don't import RawPacket - define minimal version
