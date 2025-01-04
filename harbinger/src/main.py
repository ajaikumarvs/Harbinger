# src/main.py
import typer
from cli.command_handler import handle_scan_command

app = typer.Typer()

@app.command()
def scan(
    scanner_type: str = typer.Option(..., help="Scanner type: malware, network, or web"),
    target: str = typer.Option(..., help="File or directory to scan"),
    mode: str = typer.Option("normal", help="Scan mode: quick, normal, or deep"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Scan directory recursively")
):
    """Execute a security scan using the specified scanner"""
    handle_scan_command(scanner_type, target, mode, recursive)

if __name__ == "__main__":
    app()