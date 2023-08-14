"""
Decoder integration layer.

This module connects raw capture packets to decoded models and
provides helpers to enrich index records without UI coupling.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Iterable, Iterator, Optional

try:
    from ..models.packet import RawPacket, DecodedPacket
    from ..models.index_record import PacketIndexRecord
    from ..pcap_loader.packet_index import PacketIndexBuilder
    from .packet_decoder import decode_packet
except ImportError:
    from models.packet import RawPacket, DecodedPacket
    from models.index_record import PacketIndexRecord
    from pcap_loader.packet_index import PacketIndexBuilder
    from capture.packet_decoder import decode_packet
