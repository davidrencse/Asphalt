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

        # 7. _time_range: None (track (start_us, end_us))
        self._time_range = None

        # 8. _file_size: 0 (set in open())
        self._file_size = 0

        # 9. _current_offset: 0 (track position in file)
        self._current_offset = 0 
        
    def open(self):
        """
        Open and validate PCAP file.
        
        Implementation of abstract method from IPacketSource.
        """
        # TODO:
        # 1. Check file exists with os.path.exists()
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"PCAP file not found: {self.filepath}")
        
        # 2. Open file: self.file_handle = open(self.filepath, 'rb')
        self.file_handle = open(self.filepath, 'rb')

        # 3. Get file size: self._file_size = os.path.getsize(self.filepath)
        self._file_size = os.path.getsize(self.filepath)

        # 4. Call self._read_global_header() to validate and set format
        self._read_global_header()

        # 5. Create memory map
        try:
            self.mmap = mmap.mmap(
                self.file_handle.fileno(), 
                0,  # Map entire file
                access=mmap.ACCESS_READ
            )
        except Exception as e:
            # Close file if mmap fails
            self.file_handle.close()
            self.file_handle = None
            raise PcapFormatError(f"Failed to memory map file: {e}")

        # 6. Set self._current_offset = 24 (skip global header)
        self._current_offset = 24

    
    def _read_global_header(self):
        
        # Read and validate PCAP global header (24 bytes).
        
        # TODO:
        # 1. Read first 24 bytes from file_handle
        self.file_handle.seek(0)
        header_data = self.file_handle.read(24)
        # 2. Check length >= 24 bytes
        if len(header_data) < 24:
            raise PcapFormatError("File too small for PCAP header")
        
        # 3. Read magic number (first 4 bytes) to determine:
        #    - byte_order ('>' or '<')
        #    - is_nanosecond (True for nanosecond formats)
        magic_number, = struct.unpack('>I', header_data[0:4])

        # 4. Parse rest of header to get link_type
        if magic_number == self.MAGIC_NUMBER_BIG_ENDIAN:
            self.byte_order = '>'
            self.is_nanosecond = False
        elif magic_number == self.MAGIC_NUMBER_LITTLE_ENDIAN:
            self.byte_order = '<'
            self.is_nanosecond = False
        elif magic_number == self.MAGIC_NUMBER_BIG_ENDIAN_NANO:
            self.byte_order = '>'
            self.is_nanosecond = True
        elif magic_number == self.MAGIC_NUMBER_LITTLE_ENDIAN_NANO:
            self.byte_order = '<'
            self.is_nanosecond = True
        else:
            # Try little-endian interpretation for better error message
            magic_le, = struct.unpack('<I', header_data[0:4])
            raise PcapFormatError(
                f"Invalid PCAP magic number: 0x{magic_number:08x} (big) / "
                f"0x{magic_le:08x} (little). Expected one of the valid magic numbers."
            )
        # Step 5: Parse rest of header (bytes 4-24)
        # Format string: 'HHIIII' means:
        # H = unsigned short (2 bytes) - version_major
        # H = unsigned short (2 bytes) - version_minor  
        # I = unsigned int (4 bytes) - timezone offset (ignore)
        # I = unsigned int (4 bytes) - timestamp accuracy (ignore)
        # I = unsigned int (4 bytes) - snaplen (max packet size)
        # I = unsigned int (4 bytes) - link_type
        fmt = self.byte_order + 'HHIIII'
        version_major, version_minor, _, _, snaplen, self.link_type = \
            struct.unpack(fmt, header_data[4:24])
        
    
    def __iter__(self) -> Iterator[RawPacket]:
        """
        Read packets from file and yield them.
        """
        # 1. Check self.mmap exists (raise error if not opened)
        if self.mmap is None:
            raise RuntimeError("PCAP file not opened. Call open() or use 'with' statement.")
