"""
Asphalt CLI - main entry point.
"""
import click
from .capture import capture

@click.group()
def cli():
    """Asphalt - Wireshark-grade packet capture and analysis."""
    pass

cli.add_command(capture)

if __name__ == "__main__":
    cli()