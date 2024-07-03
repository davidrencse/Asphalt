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


def _parse_analyzers(value: str):
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


@click.command()
@click.argument("filepath", type=click.Path(exists=True, dir_okay=False))
@click.option("--limit", "limit", type=int, default=0, show_default=True,
              help="Max packets to analyze (0 = no limit)")
@click.option(
    "--analyzers",
    "analyzers",
    default="capture_health,global_stats,protocol_mix,flow_summary,flow_analytics,tcp_handshakes,tcp_reliability,tcp_performance,abnormal_activity,scan_signals,arp_lan_signals,dns_anomalies,packet_chunks,time_series,throughput_peaks,packet_size_stats,l2_l3_breakdown,top_entities",
    show_default=True,
    help="Comma-separated analyzer list",
)
