"""
CLI commands for packet capture.
"""
import click
import time
import sys
from typing import Optional

@click.command()
@click.option('--interface', '-i', required=True, help='Interface to capture from')
@click.option('--duration', '-d', type=int, help='Duration in seconds (default: run until Ctrl+C)')
@click.option('--filter', '-f', help='BPF filter (e.g., "tcp port 80")')
def capture(interface: str, duration: Optional[int], filter: Optional[str]):
    """
    Start packet capture.
    
    Examples:
      asphalt capture -i "Ethernet" -d 60 -f "tcp port 80"
    """
    # Import from capture module (in same src directory)
    try:
        # These should work since src is in sys.path
        from capture.scapy_backend import ScapyBackend
        from capture.icapture_backend import CaptureConfig
    except ImportError as e:
        click.echo(f"Error importing capture modules: {e}", err=True)
        sys.exit(1)
