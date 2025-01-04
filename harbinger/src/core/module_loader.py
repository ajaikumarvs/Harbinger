# src/core/module_loader.py
import importlib
from typing import Optional
from modules.common.base_scanner import BaseScanner
from utils.logger import setup_logger

logger = setup_logger(__name__)

SCANNER_MODULES = {
    "malware": "modules.malware_scanner.scanner",
    "network": "modules.network_scanner.scanner",
    "web": "modules.web_scanner.scanner"
}

def load_scanner(scanner_type: str) -> Optional[BaseScanner]:
    """
    Dynamically load and instantiate a scanner module
    """
    try:
        if scanner_type not in SCANNER_MODULES:
            raise ValueError(f"Unknown scanner type: {scanner_type}")

        # Import the module
        module_path = SCANNER_MODULES[scanner_type]
        module = importlib.import_module(module_path)

        # Get the scanner class (assuming it's named 'Scanner')
        scanner_class = getattr(module, "Scanner")

        # Create and return an instance
        return scanner_class()

    except Exception as e:
        logger.error(f"Failed to load scanner {scanner_type}: {str(e)}")
        return None