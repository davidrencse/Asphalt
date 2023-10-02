"""
PCAPNG file format reader (next generation .pcapng).

Reference: https://github.com/pcapng/pcapng

File structure:
- Block-based format (Type-Length-Value blocks)
- Each block has: Block Type (4B) + Block Length (4B) + Block Body + Block Length (repeat)
- Must be 32-bit aligned

Key blocks:
1. Section Header Block (SHB) - Defines a section (like PCAP header)
2. Interface Description Block (IDB) - Defines network interface
3. Enhanced Packet Block (EPB) - Contains packet data (most common)
4. Simple Packet Block (SPB) - Simplified packet
5. Name Resolution Block (NRB) - DNS-like name resolution
"""

import struct
import mmap
from typing import BinaryIO, Iterator, Dict, Any, Optional, List, Tuple
import os
from .packet_source import IPacketSource
from .exceptions import PcapngFormatError, PcapEOFError
try:
    from ..models.packet import RawPacket
except ImportError:
    from models.packet import RawPacket
from .packet_index import PacketIndexRecord, PacketIndexBuilder

class PcapngReader(IPacketSource):
    """
    Reads PCAPNG format files.
    
    Key differences from PCAP:
    1. Block-based instead of linear packet records
    2. Supports multiple interfaces in one file
    3. Extensible with custom block types
    4. More metadata (interface descriptions, comments, etc.)
    5. 64-bit timestamps (nanosecond resolution)
    """
    
    # Block type constants
    BLOCK_TYPE_SECTION_HEADER = 0x0A0D0D0A
    BLOCK_TYPE_INTERFACE_DESCRIPTION = 0x00000001
    BLOCK_TYPE_ENHANCED_PACKET = 0x00000006
    BLOCK_TYPE_SIMPLE_PACKET = 0x00000003
    BLOCK_TYPE_NAME_RESOLUTION = 0x00000004
    BLOCK_TYPE_INTERFACE_STATS = 0x00000005
    
    def __init__(self, filepath: str):
        """
        Initialize PCAPNG reader.
        
        Args:
            filepath: Path to .pcapng file
        """
        self.filepath = filepath
        
        self.file_handle: Optional[BinaryIO] = None
        self.mmap: Optional[mmap.mmap] = None
        
        # Interface info: {if_id: {'link_type': int, 'snaplen': int, 'name': str or None, 'tsresol': int or None, ...}}
        self.interfaces: Dict[int, Dict[str, Any]] = {}
        
        # Current section metadata (updated on each SHB)
        self.current_section: Dict[str, Any] = {
            'byte_order': 'little',  
            'version_major': 1,
            'version_minor': 0,
            'section_length': -1,       
            'start_offset': 0,
        }
        
        self._packet_count: int = 0
        self._time_range: Optional[Tuple[int, int]] = None 
        self._file_size: int = 0
        self._current_offset: int = 0
        
        # For building index / random access later: packet_id → byte offset of its block
        self.block_offsets: Dict[int, int] = {} 
        
    def open(self):
        """
        Open and validate PCAPNG file.
        
        Implementation of abstract method from IPacketSource.
        """
        # 1. Check file exists
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"PCAPNG file not found: {self.filepath}")
        
        # 2. Open file
        self.file_handle = open(self.filepath, 'rb')
