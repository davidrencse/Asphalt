# Custom exceptions

"""
Custom exceptions for Asphalt PCAP processing.
"""

class PcapError(Exception):
    """Base exception for all PCAP-related errors."""
    pass

class PcapFormatError(PcapError):
    """Raised when PCAP file format is invalid or corrupt."""
    pass
