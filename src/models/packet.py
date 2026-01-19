# Packet data model
"""
Packet data models for Asphalt.

THESE MODELS ARE IMMUTABLE - This is critical for deterministic processing.
Once created, packet objects should not be modified. All transformations
create new objects.
"""

from dataclasses import dataclass, field
from typing import Optional, Tuple
import time

@dataclass(frozen=True)  # IMMUTABLE: Ensures deterministic processing
class RawPacket:
    """
    Raw packet as read directly from capture file.
    
    This is the lowest-level representation - just bytes + metadata.
    All timestamps are normalized to microseconds for consistency.
    
    IMPORTANT: packet_id must be monotonic starting at 1 for each session.
    This is enforced by the PacketSource implementation.
    """
    # CORE IDENTIFICATION
    packet_id: int  
    """Monotonic integer starting at 1 for this packet source"""
    
    timestamp_us: int  
    """Microseconds since Unix epoch (1970-01-01). 
    Use this consistently for all time calculations."""
    
    # SIZE INFORMATION
    captured_length: int  
    """Bytes actually captured (may be less than original due to snaplen)"""
    
    original_length: int  
    """Bytes on the wire (original packet size)"""
    
    # NETWORK CONTEXT
    link_type: int  
    """libpcap DLT_* constant (e.g., 1 = DLT_EN10MB for Ethernet)"""
    
    # RAW DATA
    data: bytes  
    """Raw packet bytes. DO NOT modify this - create new objects instead."""
    
    # STORAGE REFERENCE
    pcap_ref: str  
    """Format: 'file_id:start_offset:data_offset'
    Example: '0:128:144' means:
      - file_id 0 (first file in session)
      - Packet record starts at byte 128 in file
      - Packet data starts at byte 144 (after 16-byte pcap header)
    This allows random access to packet data without full file scan."""
    
    # OPTIONAL METADATA
    interface_id: Optional[int] = None  
    """For multi-interface captures (PCAPNG)"""
    
    comment: Optional[str] = None  
    """Optional annotation (not used in hash calculation)"""
    
    # COMPUTED PROPERTIES
    @property
    def timestamp_seconds(self) -> float:
        """Convert microseconds to seconds with fractional part."""
        return self.timestamp_us / 1_000_000.0
    
    @property
    def is_truncated(self) -> bool:
        """True if captured length < original length (snaplen limited)."""
        return self.captured_length < self.original_length
    
    @property
    def data_hash(self) -> str:
        """Quick hash for equality checks (not cryptographic)."""
        # Use built-in hash for performance in dictionaries/sets
        return str(hash(self.data))

@dataclass(frozen=True)  # Also immutable
class DecodedPacket:
    """
    Packet after protocol decoding (FUTURE SPRINT - define interface now).
    
    This will be extended in future sprints with protocol-specific fields.
    The raw_packet reference ensures we can always go back to original data.
    """
    raw_packet: RawPacket  
    """Reference to original raw packet - NEVER modify"""
    
    protocol_stack: Tuple[str, ...] = field(default_factory=tuple)
    """Stack of protocol names, e.g., ('eth', 'ipv4', 'tcp', 'http')
    Tuple is immutable and hashable for use in dictionaries."""
    
    # FUTURE FIELDS (commented out for now):
    # src_mac: Optional[str] = None
    # dst_mac: Optional[str] = None
    # src_ip: Optional[str] = None
    # dst_ip: Optional[str] = None
    # src_port: Optional[int] = None
    # dst_port: Optional[int] = None
    # flags: Optional[int] = None
    # ttl: Optional[int] = None
    
    def __post_init__(self):
        """Validate after initialization."""
        # Ensure protocol_stack is a tuple (immutable)
        if not isinstance(self.protocol_stack, tuple):
            # Convert list to tuple to ensure immutability
            object.__setattr__(self, 'protocol_stack', tuple(self.protocol_stack))
    
    @property
    def stack_summary(self) -> str:
        """String representation of protocol stack."""
        return ":".join(self.protocol_stack) if self.protocol_stack else "unknown"

# Helper function for timestamp conversion
def datetime_to_microseconds(year: int, month: int, day: int, 
                            hour: int = 0, minute: int = 0, 
                            second: int = 0, microsecond: int = 0) -> int:
    """
    Convert datetime components to microseconds since epoch.
    
    Useful for testing and timestamp normalization.
    """
    # Implementation uses time module for consistency
    # You might want to use datetime in production
    pass