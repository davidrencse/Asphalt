"""
Packet index builder for deterministic index record creation.

CRITICAL: Must produce identical output for identical input.
No randomness, no system-specific values.
"""

import hashlib
from typing import Optional
from ..models.packet import RawPacket
from ..models.index_record import PacketIndexRecord

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
        
        # TODO: Step 3 - Calculate hash using _calculate_packet_hash(packet)
        # Every packet is given a hash, calculate this hash for fingerprint
        hash_value = self._calculate_packet_hash(packet)

        # TODO: Step 4 - If stack_summary is None, set to "raw"
        if (stack_summary == None):
            stack_summary = "raw"

        # TODO: Step 5 - Create and return PacketIndexRecord with all fields
        return PacketIndexRecord(
            packet_id=self._packet_counter,
            session_id=self.session_id,
            timestamp_us=packet.timestamp_us,
            captured_length=packet.captured_length,  
            original_length=packet.original_length,
            pcap_ref=packet.pcap_ref,
            packet_hash=hash_value,
            src_ip="0.0.0.0",  # Placeholder for Sprint 0.2
            dst_ip="0.0.0.0",  # Placeholder for Sprint 0.2
            src_port=0,  # Placeholder for Sprint 0.2
            dst_port=0,  # Placeholder for Sprint 0.2
            protocol=0,  # Placeholder for Sprint 0.2
            stack_summary=stack_summary,
            schema_version=self.schema_version
        )
        # Remember: src_ip, dst_ip, etc. are placeholders ("0.0.0.0", 0)
    
    def _calculate_packet_hash(self, packet: RawPacket) -> str:
        """
        Calculate deterministic hash for packet based on packet info:
        
        1. Timestamp (8 bytes, big-endian)
        2. Captured length (4 bytes, big-endian)
        3. Original length (4 bytes, big-endian)
        4. Link type (4 bytes, big-endian)
        5. Packet data (variable length)
        """
        # TODO:
        # 1. Create hashlib.blake2b(digest_size=16)
        h = hashlib.blake2b(digest_size=16)

        # 2. Add timestamp (packet.timestamp_us.to_bytes(8, 'big'))
        h.update(packet.timestamp_us.to_bytes(8, 'big'))

        # 3. Add captured length (4 bytes, big-endian)
        h.update(packet.captured_length.to_bytes(4, 'big'))

        # 4. Add original length (4 bytes, big-endian)
        h.update(packet.original_length.to_bytes(4, 'big'))

        # 5. Add link type (4 bytes, big-endian)
        h.update(packet.link_type.to_bytes(4, 'big'))

        # 6. Add packet.data
        h.update(packet.data)

        # 7. Return hexdigest()
        return h.hexdigest()
    
    def reset(self):
        """
        Reset the packet counter.
        
        TODO: Set _packet_counter back to 0
        """
        # TODO:
        self._packet_counter = 0
    
    @property
    def current_packet_id(self) -> int:
        """
        Get the current packet_id (next one to be assigned).
        
        TODO: Return _packet_counter
        """
        # TODO: Your code here
        return self._packet_counter
    
    @property
    def total_packets_processed(self) -> int:
        """
        Get total packets processed so far.
        
        TODO: Return _packet_counter (same as current_packet_id)
        """
        # TODO:
        return self._packet_counter