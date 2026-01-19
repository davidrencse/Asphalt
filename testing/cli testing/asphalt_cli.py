#!/usr/bin/env python
"""
Standalone Asphalt CLI runner.
"""
import sys
import os

# Add src to path BEFORE any imports
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Now import
import click

# Import capture command directly
try:
    from asphalt_cli.capture import capture
except ImportError as e:
    click.echo(f"Error importing CLI: {e}", err=True)
    sys.exit(1)

@click.group()
def cli():
    """Asphalt - Wireshark-grade packet capture and analysis."""
    pass

cli.add_command(capture)

if __name__ == "__main__":
    cli()