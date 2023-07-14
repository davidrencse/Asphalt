# index record model
"""
Packet index record model for Asphalt.

These records are written to persistent storage and MUST be:
1. Deterministic - same input always produces same output
2. Backward compatible - schema changes must be handled
3. Queryable - optimized for common lookup patterns
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any
import json

@dataclass
class PacketIndexRecord:
    """
    Index record for fast packet lookup and metadata storage.
    
    This record exists in the analytics database (Tier 3) and enables:
    - Fast timestamp-based lookups
    - Flow reassembly queries
    - Protocol filtering
    - Statistical analysis
    
    SCHEMA VERSIONING: Always include schema_version field.
    When adding fields, ensure they have sensible defaults.
    """
    
    # ========== PRIMARY IDENTIFICATION ==========
    packet_id: int  
    """Monotonic integer, starting at 1 for this session.
    This is the primary key for intra-session lookups."""
    
    session_id: str  
    """Links to SessionManifest. Format: blake2b_hexdigest.
    Used for cross-session queries and data partitioning."""
    
    timestamp_us: int  
    """Microseconds since epoch. MUST match RawPacket.timestamp_us."""
    
    
    # ========== SIZE INFORMATION ==========
    captured_length: int  
    """Bytes captured (for statistics and filtering)"""
    
    original_length: int  
    """Original packet size (for bandwidth calculations)"""
    
    
    # ========== STORAGE REFERENCE ==========
    pcap_ref: str  
    """Format: 'file_id:start_offset:data_offset'
    Used to retrieve raw packet data from PCAP store."""
    
    packet_hash: str  
    """Blake2b-128 hash of (timestamp + data + lengths).
    Used for duplicate detection and data integrity."""
    
    
    # ========== NETWORK ADDRESSING ==========
    # NOTE: These are PLACEHOLDERS in Sprint 0.2
    # Will be populated by decoder in future sprints
    src_ip: str = "0.0.0.0"  
    """Source IP address. Default indicates not yet decoded."""
    
    dst_ip: str = "0.0.0.0"  
    """Destination IP address."""
    
    src_port: int = 0  
    """Source port (0 for non-TCP/UDP)."""
    
    dst_port: int = 0  
    """Destination port."""
    
    protocol: int = 0  
    """IP protocol number (e.g., 6=TCP, 17=UDP)."""
