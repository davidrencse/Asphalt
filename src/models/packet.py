# Packet data model
"""
Packet data models for Asphalt.

THESE MODELS ARE IMMUTABLE - This is critical for deterministic processing.
Once created, packet objects should not be modified. All transformations
create new objects.
"""

from dataclasses import dataclass, field
from typing import Optional, Tuple, Dict, Any
import json
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
    Packet after protocol decoding (L2/L3/L4 MVP).
    
    This model is immutable and safe for deterministic processing.
    The raw_packet reference ensures we can always access original bytes.
    """
    raw_packet: RawPacket
    """Reference to original raw packet - NEVER modify"""
    
    # Protocol stack
    protocol_stack: Tuple[str, ...] = field(default_factory=tuple)
    """Stack of protocol names, e.g., ('ETH', 'IP4', 'TCP')"""

    # L2 metadata
    eth_type: Optional[int] = None
    """EtherType for Ethernet-derived frames (None if not applicable)."""

    src_mac: Optional[str] = None
    """Source MAC address (lowercase colon-separated)."""
    dst_mac: Optional[str] = None
    """Destination MAC address (lowercase colon-separated)."""

    is_vlan: bool = False
    """True if one or more VLAN tags were present."""
    is_arp: bool = False
    """True if packet was identified as ARP."""
    is_multicast: bool = False
    """True if destination was multicast (L2 or L3)."""
    is_broadcast: bool = False
    """True if destination was broadcast (L2 or L3)."""
    is_ipv4_fragment: bool = False
    """True if IPv4 fragmentation flags/offset indicate a fragment."""
    is_ipv6_fragment: bool = False
    """True if IPv6 fragment header was detected."""
    
    # L3/L4 summary fields
    ip_version: int = 0
    """IP version (4 or 6). 0 means unknown/not IP."""
    
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    
    l4_protocol: Optional[str] = None
    """L4 protocol name: TCP, UDP, ICMP, ICMP6 (None if unknown)."""
    
    ip_protocol: int = 0
    """IP protocol number (e.g., 6=TCP, 17=UDP). 0 if unknown."""
    
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    tcp_flags: Optional[int] = None
    """TCP flags bitmask (FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, 
    ACK=0x10, URG=0x20, ECE=0x40, CWR=0x80)."""

    tcp_seq: Optional[int] = None
    """TCP sequence number."""
    tcp_ack: Optional[int] = None
    """TCP acknowledgment number."""
    tcp_window: Optional[int] = None
    """Advertised TCP receive window (unscaled)."""
    tcp_mss: Optional[int] = None
    """TCP MSS option value if present."""

    arp_sender_ip: Optional[str] = None
    """ARP sender protocol address (SPA)."""
    arp_sender_mac: Optional[str] = None
    """ARP sender hardware address (SHA)."""

    dns_qname: Optional[str] = None
    """DNS query name if decoded."""
    dns_is_query: Optional[bool] = None
    """True if DNS packet is a query."""
    dns_is_response: Optional[bool] = None
    """True if DNS packet is a response."""
    dns_rcode: Optional[int] = None
    """DNS response code if available."""
    ttl: Optional[int] = None
    """IPv4 TTL or IPv6 Hop Limit."""

    # Decode quality
    quality_flags: int = 0
    """Bitmask of decode quality flags (see capture.packet_decoder)."""
    
    def __post_init__(self):
        """Validate after initialization."""
        # Ensure protocol_stack is a tuple (immutable)
        if not isinstance(self.protocol_stack, tuple):
            object.__setattr__(self, 'protocol_stack', tuple(self.protocol_stack))
    
    @property
    def stack_summary(self) -> str:
        """String representation of protocol stack."""
        return "/".join(self.protocol_stack) if self.protocol_stack else "UNKNOWN"
    
    @property
    def tcp_flag_names(self) -> Tuple[str, ...]:
        """Return tuple of TCP flag names in canonical order."""
        if self.tcp_flags is None:
            return tuple()
        flags = []
        flag_map = [
            (0x80, "CWR"),
            (0x40, "ECE"),
            (0x20, "URG"),
            (0x10, "ACK"),
            (0x08, "PSH"),
            (0x04, "RST"),
            (0x02, "SYN"),
            (0x01, "FIN"),
        ]
        for mask, name in flag_map:
            if self.tcp_flags & mask:
                flags.append(name)
        return tuple(flags)
