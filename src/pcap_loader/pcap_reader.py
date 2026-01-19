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
from ..models.packet import RawPacket

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
        self._time.range = None

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
        """
        Read and validate PCAP global header (24 bytes).
        
        TODO:
        1. Read first 24 bytes from file_handle
        2. Check length >= 24 bytes
        3. Read magic number (first 4 bytes) to determine:
           - byte_order ('>' or '<')
           - is_nanosecond (True for nanosecond formats)
        4. Parse rest of header to get link_type
        5. Validate magic number is one of the 4 valid values
        
        Sets:
            self.byte_order: '>' or '<'
            self.is_nanosecond: True for nanosecond timestamps
            self.link_type: DLT_* constant
            
        Raises:
            PcapFormatError: If header is invalid
        """
        # TODO: Your code here


        pass
    
    def __iter__(self) -> Iterator[RawPacket]:
        """
        Read packets from file and yield them.
        
        Implementation of abstract method from IPacketSource.
        
        TODO:
        1. Check self.mmap exists (raise error if not opened)
        2. Start at offset = 24 (after global header)
        3. packet_id = 1 (MUST start at 1!)
        4. While there's enough bytes for a packet header (16 bytes):
           a. Read packet header (16 bytes from mmap[offset:offset+16])
           b. Parse header with struct.unpack(self.byte_order + 'IIII')
           c. Calculate timestamp_us (convert seconds + microseconds/nanoseconds)
           d. Validate packet data fits in file
           e. Get packet data slice from mmap
           f. Create pcap_ref = f"0:{packet_start}:{data_start}"
           g. Create RawPacket with all fields
           h. Yield the RawPacket
           i. Update packet_id, _packet_count, _time_range
           j. Move offset to next packet (add caplen + padding)
        
        Raises:
            RuntimeError: If file not opened
            PcapFormatError: If packet header corrupt
            PcapEOFError: If file ends unexpectedly
        """
        # TODO: Your code here
        pass
    
    def close(self):
        """
        Close the packet source and release resources.
        
        Implementation of abstract method from IPacketSource.
        
        TODO:
        1. If self.mmap exists: self.mmap.close()
        2. If self.file_handle exists: self.file_handle.close()
        3. Set self.mmap = None, self.file_handle = None
        4. Reset tracking variables isf needed
        """
        # TODO: Your code here
        pass
    
    def get_index_record(self, packet: RawPacket, packet_id: int) -> PacketIndexRecord:
        """
        Create index record for a packet.
        
        Implementation of abstract method from IPacketSource.
        
        TODO:
        1. Import PacketIndexRecord and PacketIndexBuilder at top of file
        2. Create PacketIndexBuilder instance (need session_id - use placeholder)
        3. Call builder.create_index_record(packet, packet_id)
        4. Return the result
        
        Note: We'll fix session_id later when we have SessionManifest
        """
        # TODO: Your code here
        pass
    
    def get_session_info(self) -> Dict[str, Any]:
        """
        Return session metadata.
        
        Implementation of abstract method from IPacketSource.
        
        TODO:
        Return dictionary with these REQUIRED keys:
        {
            'packet_count': self._packet_count,
            'time_range': self._time_range or (0, 0),
            'link_types': [self.link_type],  # List of link types found
            'file_size': self._file_size,
            'format': 'pcap',
            'byte_order': self.byte_order,
            'is_nanosecond': self.is_nanosecond,
            'link_type': self.link_type,
        }
        """
        # TODO: Your code here
        pass