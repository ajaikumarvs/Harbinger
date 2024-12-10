"""
Net-Sentinel Network Module
~~~~~~~~~~~~~~~~~~~~~~~

This module provides network discovery, service detection, and port scanning
capabilities with efficient and non-intrusive scanning techniques.

Basic usage:
    >>> from net_sentinel.network import NetworkDiscovery, ScanOptions
    >>> scanner = NetworkDiscovery()
    >>> results = scanner.scan_network("192.168.1.0/24")
"""

import logging
from typing import List, Dict, Any, Optional, Union
from enum import Enum, auto
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv4Address
import socket

# Configure module logger
logger = logging.getLogger(__name__)

class ScanType(Enum):
    """Types of network scans."""
    PING = auto()         # Simple ping sweep
    TCP_CONNECT = auto()  # TCP connect scan
    TCP_SYN = auto()      # TCP SYN scan (stealth)
    UDP = auto()          # UDP scan
    SERVICE = auto()      # Service detection
    COMPREHENSIVE = auto() # All scan types

class ScanSpeed(Enum):
    """Scan speed presets."""
    SNEAKY = 1    # Very slow, harder to detect
    QUIET = 2     # Slower than normal
    NORMAL = 3    # Default speed
    AGGRESSIVE = 4 # Faster, more parallel
    INSANE = 5    # Fastest, very noisy

@dataclass
class ScanOptions:
    """Configuration options for network scanning."""
    scan_type: ScanType = ScanType.TCP_CONNECT
    speed: ScanSpeed = ScanSpeed.NORMAL
    ports: Union[str, List[int]] = "1-1000"
    timeout: float = 3.0
    retries: int = 2
    concurrent_hosts: int = 10
    concurrent_ports: int = 25
    service_detection: bool = True
    skip_ping: bool = False
    interface: Optional[str] = None

    def validate(self) -> None:
        """
        Validate scan options.
        
        Raises:
            ValueError: If options are invalid
        """
        if isinstance(self.ports, str):
            if not self._validate_port_range(self.ports):
                raise ValueError("Invalid port range format")
        elif isinstance(self.ports, list):
            if not all(isinstance(p, int) and 1 <= p <= 65535 for p in self.ports):
                raise ValueError("Invalid port numbers")
        else:
            raise ValueError("Ports must be string range or list of integers")

        if self.timeout <= 0:
            raise ValueError("Timeout must be positive")

        if self.retries < 0:
            raise ValueError("Retries cannot be negative")

        if self.concurrent_hosts < 1:
            raise ValueError("Concurrent hosts must be positive")

        if self.concurrent_ports < 1:
            raise ValueError("Concurrent ports must be positive")

    def _validate_port_range(self, port_range: str) -> bool:
        """Validate port range string format."""
        try:
            parts = port_range.split(",")
            for part in parts:
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    if not (1 <= start <= end <= 65535):
                        return False
                else:
                    port = int(part)
                    if not (1 <= port <= 65535):
                        return False
            return True
        except ValueError:
            return False

@dataclass
class Host:
    """Represents a discovered network host."""
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    status: str = "up"
    ports: List[Dict[str, Any]] = None
    os_match: Optional[str] = None
    distance: Optional[int] = None
    last_seen: Optional[float] = None

    def __post_init__(self):
        """Initialize default values."""
        if self.ports is None:
            self.ports = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert host to dictionary format."""
        return {
            'ip': self.ip,
            'hostname': self.hostname,
            'mac': self.mac,
            'vendor': self.vendor,
            'status': self.status,
            'ports': self.ports,
            'os_match': self.os_match,
            'distance': self.distance,
            'last_seen': self.last_seen
        }

@dataclass
class Service:
    """Represents a detected network service."""
    port: int
    protocol: str
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    tunnel: Optional[str] = None
    confidence: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert service to dictionary format."""
        return {
            'port': self.port,
            'protocol': self.protocol,
            'state': self.state,
            'service': self.service,
            'version': self.version,
            'banner': self.banner,
            'tunnel': self.tunnel,
            'confidence': self.confidence
        }

class NetworkError(Exception):
    """Base exception for network operations."""
    pass

class ScanError(NetworkError):
    """Exception raised for scanning errors."""
    pass

class ServiceDetectionError(NetworkError):
    """Exception raised for service detection errors."""
    pass

# Import main components
from .discovery import NetworkDiscovery
from .services import ServiceDetector

__all__ = [
    'NetworkDiscovery',
    'ServiceDetector',
    'ScanOptions',
    'ScanType',
    'ScanSpeed',
    'Host',
    'Service',
    'NetworkError',
    'ScanError',
    'ServiceDetectionError'
]

def get_default_scan_options() -> ScanOptions:
    """
    Get default scan options.
    
    Returns:
        ScanOptions with default settings
    """
    return ScanOptions()

def is_valid_target(target: str) -> bool:
    """
    Check if target specification is valid.
    
    Args:
        target: Target specification (IP, hostname, or CIDR)
        
    Returns:
        bool indicating if target is valid
    """
    try:
        # Try as IP network (CIDR)
        IPv4Network(target)
        return True
    except ValueError:
        try:
            # Try as single IP
            IPv4Address(target)
            return True
        except ValueError:
            try:
                # Try as hostname
                socket.gethostbyname(target)
                return True
            except socket.error:
                return False