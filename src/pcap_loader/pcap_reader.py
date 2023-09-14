"""
PCAP file format reader (legacy .pcap).

Reference: https://wiki.wireshark.org/Development/LibpcapFileFormat

File structure:
- 24-byte global header
- Repeated packet records:
  - 16-byte packet header
  - Packet data (variable length, padded to 32-bit boundary)
"""

import struct
import mmap
from typing import BinaryIO, Iterator, Tuple, Dict, Any, Optional
import os
from .packet_source import IPacketSource
from .exceptions import PcapFormatError, PcapEOFError
try:
    from ..models.packet import RawPacket
except ImportError:
    from models.packet import RawPacket
from .packet_index import PacketIndexRecord, PacketIndexBuilder

class PcapReader(IPacketSource):
    """
    Reads legacy PCAP format files.
    
    This class MUST implement ALL abstract methods from IPacketSource.
    """
    
    # Magic numbers for format detection
    MAGIC_NUMBER_BIG_ENDIAN = 0xA1B2C3D4        # Standard microsecond
    MAGIC_NUMBER_LITTLE_ENDIAN = 0xD4C3B2A1     # Swapped microsecond
    MAGIC_NUMBER_BIG_ENDIAN_NANO = 0xA1B23C4D   # Nanosecond resolution
    MAGIC_NUMBER_LITTLE_ENDIAN_NANO = 0x4D3CB2A1 # Swapped nanosecond
    
    # Link type constants (from pcap/bpf.h)
    DLT_NULL = 0          # BSD loopback
    DLT_EN10MB = 1        # Ethernet
    DLT_RAW = 12          # Raw IP
    DLT_LINUX_SLL = 113   # Linux cooked socket
    
    def __init__(self, filepath: str):
        """
        Initialize PCAP reader.
        
        Args:
            filepath: Path to .pcap file
        """
        # TODO: Store filepath and initialize instance variables:
        # 1. file_handle: None (will be set in open())
        self.filepath = filepath
        self.file_handle = None
    
        # 2. mmap: None (memory mapping for fast access)
        self.mmap = None

        # 3. byte_order: '>' or '<' (detected in open())
        self.byte_order = '>'

        # 4. is_nanosecond: bool (detected in open())
        self.is_nanosecond = False

        # 5. link_type: int (detected in open())
        self.link_type = self.DLT_EN10MB # Default ethernet

        # 6. _packet_count: 0 (count packets as we read)
        self._packet_count = 0
