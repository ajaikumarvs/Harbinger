"""
Command Line Interface Module for Net-Sentinel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module handles command-line argument parsing and
user interaction for the Net-Sentinel tool.
"""

import logging
import sys
import argparse
from typing import Optional, List, Dict, Any
from pathlib import Path
import textwrap
from enum import Enum
from datetime import datetime

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import print as rprint

logger = logging.getLogger(__name__)
console = Console()

class OutputFormat(str, Enum):
    """Output format options."""
    TEXT = "text"
    JSON = "json"
    HTML = "html"
    XML = "xml"

class CLI:
    """
    Handles command-line interface operations.
    """
    
    def __init__(self):
        """Initialize CLI parser."""
        self.parser = self._create_parser()
        self.console = Console()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command-line argument parser."""
        parser = argparse.ArgumentParser(
            description=textwrap.dedent("""
                Net-Sentinel - Network Security Assessment Tool with AI Guidance
                
                A comprehensive network security assessment tool that combines
                traditional scanning techniques with AI-powered guidance.
            """),
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        # Target specification
        parser.add_argument(
            "target",
            help="Target network (CIDR) or host"
        )
        
        # Scanning options
        scan_group = parser.add_argument_group("Scanning Options")
        scan_group.add_argument(
            "-p", "--ports",
            help="Port specification (e.g., 80,443 or 1-1000)",
            default="1-1000"
        )
        scan_group.add_argument(
            "-sT", "--tcp-scan",
            action="store_true",
            help="Perform TCP connect scan"
        )
        scan_group.add_argument(
            "-sS", "--syn-scan",
            action="store_true",
            help="Perform TCP SYN scan (requires root)"
        )
        scan_group.add_argument(
            "-sU", "--udp-scan",
            action="store_true",
            help="Perform UDP scan"
        )
        scan_group.add_argument(
            "--speed",
            choices=["sneaky", "quiet", "normal", "aggressive", "insane"],
            default="normal",
            help="Scan speed (default: normal)"
        )
        
        # AI options
        ai_group = parser.add_argument_group("AI Options")
        ai_group.add_argument(
            "--ai-guidance",
            action="store_true",
            help="Enable AI-powered guidance"
        )
        ai_group.add_argument(
            "--local-model",
            help="Path to local AI model"
        )
        ai_group.add_argument(
            "--model-type",
            choices=["local", "endpoint", "hybrid"],
            default="local",
            help="AI model deployment type"
        )
        
        # Output options
        output_group = parser.add_argument_group("Output Options")
        output_group.add_argument(
            "-o", "--output",
            help="Output file path"
        )
        output_group.add_argument(
            "-f", "--format",
            choices=[f.value for f in OutputFormat],
            default=OutputFormat.TEXT.value,
            help="Output format"
        )
        output_group.add_argument(
            "--debug",
            action="store_true",
            help="Enable debug output"
        )
        output_group.add_argument(
            "-q", "--quiet",
            action="store_true",
            help="Minimal output"
        )
        
        # Advanced options
        adv_group = parser.add_argument_group("Advanced Options")
        adv_group.add_argument(
            "--timeout",
            type=float,
            default=3.0,
            help="Timeout for network operations (seconds)"
        )
        adv_group.add_argument(
            "--max-retries",
            type=int,
            default=2,
            help="Maximum number of retries"
        )
        adv_group.add_argument(
            "--threads",
            type=int,
            default=10,
            help="Number of concurrent threads"
        )
        adv_group.add_argument(
            "--no-service-detection",
            action="store_true",
            help="Disable service version detection"
        )
        
        return parser
    
    def parse_args(self) -> argparse.Namespace:
        """
        Parse command-line arguments.
        
        Returns:
            Parsed arguments namespace
        """
        return self.parser.parse_args()
    
    def print_banner(self) -> None:
        """Print tool banner."""
        banner = """
███    ██ ███████ ████████       ███████ ███████ ███    ██ ████████ ██ ███    ██ ███████ ██     
████   ██ ██         ██          ██      ██      ████   ██    ██    ██ ████   ██ ██      ██     
██ ██  ██ █████      ██    █████ ███████ █████   ██ ██  ██    ██    ██ ██ ██  ██ █████   ██     
██  ██ ██ ██         ██               ██ ██      ██  ██ ██    ██    ██ ██  ██ ██ ██      ██     
██   ████ ███████    ██          ███████ ███████ ██   ████    ██    ██ ██   ████ ███████ ███████
        """
        self.console.print(banner, style="blue bold")
        self.console.print(
            "\nNetwork Security Assessment Tool with AI Guidance",
            style="yellow"
        )
        self.console.print("=" * 80 + "\n")
    
    def start_scan(self, args: argparse.Namespace) -> None:
        """
        Start scan with progress indication.
        
        Args:
            args: Parsed command-line arguments
        """
        with Progress(
            SpinnerColumn(),
            *Progress.get_default_columns(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task(
                "[cyan]Scanning...",
                total=100
            )
            
            # Simulate scan progress (replace with actual scan)
            import time
            for i in range(100):
                time.sleep(0.1)
                progress.update(task, advance=1)
    
    def display_results(
        self,
        results: Dict[str, Any],
        format: OutputFormat = OutputFormat.TEXT
    ) -> None:
        """
        Display scan results.
        
        Args:
            results: Scan results to display
            format: Output format
        """
        if format == OutputFormat.TEXT:
            self._display_text_results(results)
        elif format == OutputFormat.JSON:
            self.console.print_json(data=results)
        else:
            logger.info(f"Results saved in {format} format")
    
    def _display_text_results(self, results: Dict[str, Any]) -> None:
        """Display results in text format."""
        # Create hosts table
        hosts_table = Table(title="Discovered Hosts")
        hosts_table.add_column("IP Address", style="cyan")
        hosts_table.add_column("Hostname", style="green")
        hosts_table.add_column("Open Ports", style="magenta")
        hosts_table.add_column("Services", style="yellow")
        
        for host in results.get('hosts', []):
            hosts_table.add_row(
                host['ip'],
                host.get('hostname', 'N/A'),
                str(len(host.get('ports', []))),
                ', '.join(
                    p.get('service', 'unknown')
                    for p in host.get('ports', [])
                )
            )
        
        self.console.print(hosts_table)
        
        # Create vulnerabilities table
        vuln_table = Table(title="Findings")
        vuln_table.add_column("Severity", style="red")
        vuln_table.add_column("Title", style="cyan")
        vuln_table.add_column("Description", style="white")
        
        for finding in results.get('findings', []):
            vuln_table.add_row(
                finding['severity'],
                finding['title'],
                textwrap.shorten(
                    finding['description'],
                    width=60,
                    placeholder="..."
                )
            )
        
        self.console.print("\n", vuln_table)
    
    def prompt_for_action(self, message: str) -> bool:
        """
        Prompt user for action.
        
        Args:
            message: Prompt message
            
        Returns:
            User's response
        """
        return Confirm.ask(message)
    
    def get_input(
        self,
        prompt: str,
        default: Optional[str] = None,
        password: bool = False
    ) -> str:
        """
        Get user input.
        
        Args:
            prompt: Input prompt
            default: Default value
            password: Whether input is a password
            
        Returns:
            User input
        """
        return Prompt.ask(
            prompt,
            default=default,
            password=password
        )
    
    def show_error(self, message: str) -> None:
        """
        Display error message.
        
        Args:
            message: Error message
        """
        self.console.print(f"[red]Error:[/red] {message}")
    
    def show_warning(self, message: str) -> None:
        """
        Display warning message.
        
        Args:
            message: Warning message
        """
        self.console.print(f"[yellow]Warning:[/yellow] {message}")
    
    def show_info(self, message: str) -> None:
        """
        Display info message.
        
        Args:
            message: Info message
        """
        self.console.print(f"[blue]Info:[/blue] {message}")
    
    def show_success(self, message: str) -> None:
        """
        Display success message.
        
        Args:
            message: Success message
        """
        self.console.print(f"[green]Success:[/green] {message}")