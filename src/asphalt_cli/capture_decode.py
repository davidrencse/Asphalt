"""
CLI command for live capture + decode (non-intrusive to existing capture).
"""
import time
import sys
import json
from typing import Optional

import click

from models.packet import RawPacket
from capture.decoder import PacketDecoder
from capture.packet_decoder import quality_flag_names


@click.command(name="capture-decode")
@click.option("--interface", "-i", required=True, help="Interface to capture from")
@click.option("--duration", "-d", type=int, help="Duration in seconds (default: run until limit)")
@click.option("--filter", "-f", help="BPF filter (e.g., \"tcp port 80\")")
@click.option("--packet-filter", "--filter-expr", "filter_expr",
              help="Filter expression for decoded packets")
@click.option("--limit", type=int, default=50, show_default=True,
              help="Max packets to decode (0 = no limit)")
@click.option("--show-quality", is_flag=True, help="Show decode quality flags")
@click.option("--format", "format", type=click.Choice(["table", "json", "jsonl"]),
              default="table", show_default=True, help="Output format")
@click.option("--output", "output", type=click.Path(dir_okay=False),
              help="Write JSON/JSONL output to file")
def capture_decode(interface: str,
                   duration: Optional[int],
                   filter: Optional[str],
                   limit: int,
                   show_quality: bool,
                   format: str,
                   output: Optional[str],
                   filter_expr: Optional[str]):
    """
    Live capture and decode packets, printing a compact summary.
    """
    try:
        from capture.scapy_backend import ScapyBackend
        from capture.icapture_backend import CaptureConfig
    except ImportError as e:
        click.echo(f"Error importing capture modules: {e}", err=True)
        sys.exit(1)
