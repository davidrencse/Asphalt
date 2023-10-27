"""
IPacketSource Interface

This is the CONTRACT that all packet sources must follow.
Think of this as a "job description" for PCAP file readers.

All packet source classes (PcapReader, PcapngReader, etc.) must:
1. Implement ALL the methods marked @abstractmethod
2. Follow the rules defined in each method's docstring
3. Handle errors consistently
4. Clean up resources properly
"""

from abc import ABC, abstractmethod
from typing import Iterator, Optional, Dict, Any
try:
    from ..models.packet import RawPacket
    from ..models.index_record import PacketIndexRecord
except ImportError:
    from models.packet import RawPacket
    from models.index_record import PacketIndexRecord

class IPacketSource(ABC):
    """
    Abstract base class for all packet data sources.
    
    This is like a "job description" for file readers.
    Any class that wants to read packets MUST implement these methods.
    
    Example implementations:
    - PcapReader (reads .pcap files)
    - PcapngReader (reads .pcapng files) 
    - LiveCapture (future: reads from network interface)
    
    Rules for implementers:
    1. Deterministic iteration order
    2. Proper resource cleanup (close files!)
    3. Accurate packet metadata
    4. Consistent error handling
    """
    
    # =========================================================================
    # TODO: MUST IMPLEMENT - PACKET ITERATION
    # =========================================================================
    @abstractmethod
    def __iter__(self) -> Iterator[RawPacket]:
        """
        Iterate through packets in capture order.
