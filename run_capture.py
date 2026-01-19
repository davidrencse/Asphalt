#!/usr/bin/env python
"""
Asphalt CLI - Use this as your main command.
"""
import sys
import os

# Add src to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

import click

@click.group()
def cli():
    """Asphalt - Wireshark-grade packet capture and analysis."""
    pass

# Import and add commands
from cli.capture import capture
cli.add_command(capture)

if __name__ == "__main__":
    cli()
"""

Available interfaces:
  dummy0               UP    Dummy Ethernet Interface
  dummy1               UP    Dummy Wi-Fi Interface

Capture started on 'dummy0' (session: dummy_1768828199)
Duration: 3 seconds
Press Ctrl+C to stop

Time   Pkts/s   Total      Drops
----------------------------------------
  2.8s       63        126        0
Duration reached (3s), stopping...

==================================================
CAPTURE SUMMARY
==================================================
Session ID:    dummy_1768828199
Interface:     dummy0
Duration:      3.02s
Total Packets: 126
Total Bytes:   15,184
Packet Drops:  0

"""