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
    
    # Create capture backend
    try:
        capture_backend = ScapyBackend()
    except Exception as e:
        click.echo(f"Error initializing scapy backend: {e}", err=True)
        click.echo("\nFor packet capture on Windows:", err=True)
        click.echo("1. Install NpCap from https://npcap.com/", err=True)
        click.echo("2. Choose 'WinPcap API-compatible mode'", err=True)
        click.echo("3. Reboot if prompted", err=True)
        sys.exit(1)
    
    # List interfaces if requested
    if interface == 'list':
        click.echo("Available interfaces:")
        interfaces = capture_backend.list_interfaces()

        if interfaces:
            click.echo("\n=== Network Interfaces ===")
            for iface in interfaces:
                display_name = iface.get('display_name', iface['name'])
                desc = iface.get('description', '')

                # Truncate long GUIDs for display
                if len(display_name) > 30 and 'NPF_' in display_name:
                    display_name = desc if desc and desc != iface['name'] else f"...{display_name[-20:]}"

                status = "UP" if iface.get('is_up', True) else "DOWN"

                click.echo(f"  {status} {display_name:30}")
                if iface.get('ips'):
                    click.echo(f"      IPs: {', '.join(iface['ips'])}")
                click.echo(f"      Use: asphalt capture --interface \"{iface['name']}\"")

        if not interfaces:
            click.echo("\nNo real interfaces found.")
            click.echo("Note: Interface names are GUIDs like \\Device\\NPF_{...}")
            click.echo("      Use the exact name shown above for capture.")

        return

    # Create config
    config = CaptureConfig(
        interface=interface,
        filter=filter,
        buffer_size=10000
    )
