"""ASCII art banner for FalconEYE CLI."""

from rich.console import Console
from rich.text import Text

from ... import __version__

_SHORT_VERSION = ".".join(__version__.split(".")[:2])


def print_banner(console: Console):
    """Print FalconEYE ASCII art banner."""
    
    banner = r"""
    ███████╗ █████╗ ██╗      ██████╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗███████╗
    ██╔════╝██╔══██╗██║     ██╔════╝██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔════╝
    █████╗  ███████║██║     ██║     ██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ █████╗  
    ██╔══╝  ██╔══██║██║     ██║     ██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔══╝  
    ██║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████╗   ██║   ███████╗
    ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝
    """
    
    # Create styled text
    banner_text = Text(banner, style="bold cyan")
    subtitle = Text("Security Code Review", style="bold bright_cyan", justify="center")
    version = Text(f"v{_SHORT_VERSION} - AI-Powered Analysis", style="dim cyan", justify="center")
    authors = Text("FalconEYE-NG by NoAuthZone · based on FalconEYE by hardw00t & h4ckologic", style="italic dim cyan", justify="center")
    
    # Print banner
    console.print()
    console.print(banner_text)
    console.print(subtitle)
    console.print(version)
    console.print(authors)
    console.print()
    console.print("─" * 88, style="cyan")
    console.print()


def print_compact_banner(console: Console):
    """Print a compact version of the banner for less verbose output."""
    
    banner = r"""
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║  ███████╗ █████╗ ██╗      ██████╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗███████╗  ║
    ║  ██╔════╝██╔══██╗██║     ██╔════╝██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔════╝  ║
    ║  █████╗  ███████║██║     ██║     ██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ █████╗    ║
    ║  ██╔══╝  ██╔══██║██║     ██║     ██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔══╝    ║
    ║  ██║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████╗   ██║   ███████╗  ║
    ║  ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝  ║
    ║                      Security Code Review - v3.0                          ║
    ╚═══════════════════════════════════════════════════════════════════════════╗
    """
    
    console.print(banner, style="cyan")
    console.print()
