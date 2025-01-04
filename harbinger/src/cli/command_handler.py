# src/cli/command_handler.py
from core.module_loader import load_scanner
from utils.logger import setup_logger

logger = setup_logger(__name__)

def handle_scan_command(scanner_type: str, target: str, mode: str, recursive: bool) -> None:
    """Handle scan command by loading and executing appropriate scanner"""
    try:
        # Load the requested scanner
        scanner = load_scanner(scanner_type)
        if not scanner:
            raise ValueError(f"Scanner '{scanner_type}' not found")

        # Initialize scanner
        if not scanner.initialize():
            raise RuntimeError(f"Failed to initialize {scanner_type} scanner")

        # Prepare scan options
        options = {
            "mode": mode,
            "recursive": recursive
        }

        # Execute scan
        try:
            results = scanner.scan(target, options)
            print(f"\nScan Results:\n{results}")
        finally:
            scanner.cleanup()

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        raise