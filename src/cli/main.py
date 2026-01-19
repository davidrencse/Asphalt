"""
Asphalt CLI - main entry point.
"""
import sys
import os

# Ensure src is in path when running directly
if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_root = os.path.dirname(os.path.dirname(current_dir))
    if src_root not in sys.path:
        sys.path.insert(0, src_root)

import click
from .capture import capture

@click.group()
def cli():
    """Asphalt - Wireshark-grade packet capture and analysis."""
    pass

cli.add_command(capture)

if __name__ == "__main__":
    cli()