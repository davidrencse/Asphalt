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
        
        # 3. Get file size
        self._file_size = os.path.getsize(self.filepath)
        
        # 4. Create memory map
        try:
            self.mmap = mmap.mmap(
                self.file_handle.fileno(),
                0,  # Map entire file
                access=mmap.ACCESS_READ
            )
        except Exception as e:
            self.file_handle.close()
            self.file_handle = None
            raise PcapngFormatError(f"Failed to memory map file: {e}")
        
        # 5. Parse initial blocks to find SHB and IDBs
        self._parse_initial_blocks()
        
        # 6. Set starting offset
        self._current_offset = 0
    
    def _read_block_header(self, offset: int) -> Tuple[int, int]:
        """
        Read block type and length at given offset.
        
        PCAPNG block format:
        - Bytes 0-3: Block Type (e.g., 0x0A0D0D0A = Section Header)
        - Bytes 4-7: Block Total Length (includes header and footer)
        
        Args:
            offset: Position in file to read from
            
        Returns:
            Tuple of (block_type, block_total_length)
            
        Raises:
            PcapEOFError: If not enough bytes for header
        """
        # 1. Check we have enough bytes
        if offset + 8 > len(self.mmap):
            raise PcapEOFError(f"Not enough bytes for block header at offset {offset}")
        
        # 2. Read 8 bytes from memory map
        header_bytes = self.mmap[offset:offset + 8]
        
        # 3. Unpack as two 32-bit unsigned integers (little-endian)
        block_type, block_length = struct.unpack('<II', header_bytes)
        
        # 4. Validate block_length makes sense
        if block_length < 12:
            raise PcapngFormatError(
                f"Invalid block length {block_length} at offset {offset} - "
                f"must be at least 12 bytes"
            )
        
        if offset + block_length > len(self.mmap):
            raise PcapEOFError(
                f"Block extends past end of file: "
                f"offset={offset}, length={block_length}, "
                f"file size={len(self.mmap)}"
            )
        
        return block_type, block_length
    
    def _parse_section_header_block(self, offset: int):
        """
        Parse Section Header Block (SHB).
        """
        if self.mmap is None:
            raise PcapngFormatError("File not memory-mapped")
        
        # Read block type and length
        block_type, block_length = struct.unpack_from("<II", self.mmap, offset)
        if block_type != self.BLOCK_TYPE_SECTION_HEADER:
            raise PcapngFormatError(f"Expected SHB at offset {offset}, got type {hex(block_type)}")
        
        # Byte-order magic (4B)
        bom = struct.unpack_from("<I", self.mmap, offset + 8)[0]
        if bom != 0x1A2B3C4D:
            raise PcapngFormatError(f"Invalid byte-order magic: {hex(bom)} (expected 0x1A2B3C4D)")
        
        # Version major/minor (2B each)
        version_major, version_minor = struct.unpack_from("<HH", self.mmap, offset + 12)
        
        # Section length (8B signed int, -1 = unknown)
        section_length = struct.unpack_from("<q", self.mmap, offset + 16)[0]
        
        # Validate trailing block length matches
        trailing_length = struct.unpack_from("<I", self.mmap, offset + block_length - 4)[0]
        if trailing_length != block_length:
            raise PcapngFormatError("Mismatched block lengths in SHB")
        
        # Update current_section
        self.current_section.update({
            'byte_order': 'little',
            'version_major': version_major,
            'version_minor': version_minor,
            'section_length': section_length,
            'start_offset': offset,
        })
    
    def _parse_interface_description_block(self, offset: int):
        """
        Parse Interface Description Block (IDB).
        """
        if self.mmap is None:
            raise PcapngFormatError("File not memory-mapped")
