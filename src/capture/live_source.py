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
class RawPacket:
    """Minimal packet class."""
    def __init__(self, timestamp=0, data=b"", capture_length=0, wire_length=0, interface=""):
        self.timestamp = timestamp
        self.data = data
        self.capture_length = capture_length
        self.wire_length = wire_length
        self.interface = interface
