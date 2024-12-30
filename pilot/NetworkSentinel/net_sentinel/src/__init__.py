"""
Net-Sentinel - Network Security Assessment Tool with AI Guidance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A comprehensive network security assessment tool that combines traditional
network scanning with AI-powered guidance and analysis.

Basic usage:
    >>> from net_sentinel import NetworkDiscovery
    >>> scanner = NetworkDiscovery()
    >>> results = scanner.scan_network("192.168.1.0/24")

For CLI usage:
    $ net-sentinel --help

:copyright: (c) 2024
:license: MIT, see LICENSE for more details.
"""

from typing import List, Tuple, Dict, Any
import logging

# Version information
__version__ = '1.0.0'
__author__ = 'Your Name'
__license__ = 'MIT'
__copyright__ = 'Copyright 2024'

# Set default logging handler to avoid "No handler found" warnings.
logging.getLogger(__name__).addHandler(logging.NullHandler())

# Import main components for easier access
from .network.discovery import NetworkDiscovery
from .vulnerability.scanner import VulnerabilityScanner
from .vulnerability.analyzer import VulnerabilityAnalyzer
from .ai.llm_manager import LLMManager
from .ai.guidance import AIGuidance
from .exploit.executor import ExploitExecutor
from .exploit.validator import ExploitValidator
from .reporting.html_generator import HTMLReporter
from .reporting.xml_generator import XMLReporter
from .utils.cli import CLI
from .utils.logger import setup_logging

# Define exported symbols
__all__ = [
    'NetworkDiscovery',
    'VulnerabilityScanner',
    'VulnerabilityAnalyzer',
    'LLMManager',
    'AIGuidance',
    'ExploitExecutor',
    'ExploitValidator',
    'HTMLReporter',
    'XMLReporter',
    'CLI',
    'setup_logging',
    '__version__',
    '__author__',
    '__license__',
    'get_version_info',
    'configure_logging'
]

def get_version_info() -> Tuple[str, str, str]:
    """
    Returns version information for the package.
    
    Returns:
        Tuple containing (version, author, license)
    """
    return __version__, __author__, __license__

def configure_logging(
    level: int = logging.INFO,
    log_file: str = None,
    format_string: str = None
) -> None:
    """
    Configure logging for the package.
    
    Args:
        level: Logging level (default: logging.INFO)
        log_file: Optional file path for logging output
        format_string: Optional custom format string for log messages
    """
    logger = logging.getLogger(__name__)
    
    if format_string is None:
        format_string = '[%(asctime)s] %(levelname)s - %(name)s - %(message)s'
    
    formatter = logging.Formatter(format_string)
    
    # Configure console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Configure file handler if log_file is specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    logger.setLevel(level)

# Runtime initialization
logger = logging.getLogger(__name__)

# Package metadata
metadata: Dict[str, Any] = {
    'name': 'net-sentinel',
    'version': __version__,
    'author': __author__,
    'license': __license__,
    'description': 'Network Security Assessment Tool with AI Guidance',
    'requires': [
        'scapy>=2.5.0',
        'python-nmap>=0.7.1',
        'requests>=2.28.0',
        'cryptography>=41.0.0',
        'torch>=2.0.0',
        'transformers>=4.30.0',
        'pyyaml>=6.0',
        'jinja2>=3.1.2',
        'lxml>=4.9.0',
        'rich>=13.0.0',
        'python-dotenv>=1.0.0'
    ]
}