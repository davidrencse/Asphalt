"""
Packet index builder for deterministic index record creation.

CRITICAL: Must produce identical output for identical input.
No randomness, no system-specific values.
"""

import hashlib
from typing import Optional
try:
    from ..models.packet import RawPacket, DecodedPacket
    from ..models.index_record import PacketIndexRecord
except ImportError:
    from models.packet import RawPacket, DecodedPacket
    from models.index_record import PacketIndexRecord

class PacketIndexBuilder:
    """
    Creates deterministic PacketIndexRecords from RawPackets.
    
    Think of this as a "library catalog card creator":
    - Takes a book (RawPacket)
    - Creates a catalog card (PacketIndexRecord)
    - Same book → same catalog card, every time
    """
    
    def __init__(self, session_id: str, schema_version: str = "0.2.0"):
        """
        Initialize index builder.
        
        Args:
            session_id: From SessionManifest, used in all records
            schema_version: Version string for schema evolution
            
        TODO: 
        1. Store session_id and schema_version as instance variables
        2. Initialize packet counter to 0 (will increment to 1 for first packet)
        """
        # TODO: Your code here
