"""
Asphalt CLI - main entry point.
"""
import click
from .capture import capture
from .decode import decode
from .capture_decode import capture_decode
from .analyze import analyze

@click.group()
def cli():
    """Asphalt - Wireshark-grade packet capture and analysis."""
    pass
