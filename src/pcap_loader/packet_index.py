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

        self.session_id = session_id
        self.schema_version = schema_version
        self._packet_counter = 0
        
    def create_index_record(self, packet: RawPacket,
                           decoded: Optional[DecodedPacket] = None,
                           stack_summary: Optional[str] = None) -> PacketIndexRecord:
        """
        Create index record for a packet.
        
        Steps:
        1. Increment packet counter
        2. Validate packet_id matches expected order
        3. Calculate packet hash (fingerprint)
        4. Use stack_summary or default to "raw"
        5. Create and return PacketIndexRecord
        
        TODO: Implement all 5 steps
        """
        # TODO: Step 1 - Increment packet counter
        self._packet_counter += 1

        # TODO: Step 2 - Validate packet.packet_id matches _packet_counter 
        # in case of out-of-order or duplicate packet processing
        if packet.packet_id != self._packet_counter:
            raise ValueError(
                f"Packet ID mismatch: expected {self._packet_counter}, "
                f"got {packet.packet_id}. Packet sources must maintain "
                f"monotonic packet_id starting at 1."
            )
