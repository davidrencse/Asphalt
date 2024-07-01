"""CLI command for packet analysis."""
import click
from typing import Optional

from capture.decoder import PacketDecoder
from pcap_loader.pcap_reader import PcapReader
from pcap_loader.pcapng_reader import PcapngReader
from analysis.engine import AnalysisEngine
from analysis.registry import create_analyzer, list_analyzers

_PCAP_MAGIC = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def _select_reader(filepath: str):
    lower = filepath.lower()
    if lower.endswith(".pcapng"):
        return PcapngReader
    if lower.endswith(".pcap"):
        return PcapReader

    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
    except OSError as e:
        raise click.ClickException(f"Failed to open file: {e}")

    if magic == _PCAPNG_MAGIC:
        return PcapngReader
    if magic in _PCAP_MAGIC:
        return PcapReader

    raise click.ClickException("Unsupported capture file format")
