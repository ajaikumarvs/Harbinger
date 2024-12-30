"""
Net-Sentinel Utilities Module
~~~~~~~~~~~~~~~~~~~~~~~~

This module provides common utility functions and helpers used
across the Net-Sentinel application.

Basic usage:
    >>> from net_sentinel.utils import validate_ip, get_logger
    >>> logger = get_logger("my_module")
    >>> is_valid = validate_ip("192.168.1.1")
"""

import logging
import sys
import os
from typing import Union, Optional, Dict, Any, List
from pathlib import Path
import ipaddress
import json
from datetime import datetime
import hashlib
import re
from functools import wraps
import time

# Configure base logger
logger = logging.getLogger(__name__)

class NetworkUtilsError(Exception):
    """Base exception for network utility errors."""
    pass

class ValidationError(NetworkUtilsError):
    """Exception raised for validation errors."""
    pass

class ConfigError(NetworkUtilsError):
    """Exception raised for configuration errors."""
    pass

def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    log_format: Optional[str] = None
) -> logging.Logger:
    """
    Configure logging with specified settings.
    
    Args:
        level: Logging level
        log_file: Optional file path for logging
        log_format: Optional custom log format
        
    Returns:
        Configured logger instance
    """
    if log_format is None:
        log_format = "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    
    formatter = logging.Formatter(log_format)
    
    # Configure console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.addHandler(console_handler)
    
    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    return root_logger

def validate_ip(ip: str) -> bool:
    """
    Validate IP address format.
    
    Args:
        ip: IP address to validate
        
    Returns:
        bool indicating if IP is valid
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_port(port: Union[str, int]) -> bool:
    """
    Validate port number.
    
    Args:
        port: Port number to validate
        
    Returns:
        bool indicating if port is valid
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def validate_port_range(port_range: str) -> bool:
    """
    Validate port range format.
    
    Args:
        port_range: Port range string (e.g., "80-443")
        
    Returns:
        bool indicating if range is valid
    """
    try:
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            return 1 <= start <= end <= 65535
        return validate_port(port_range)
    except (ValueError, TypeError):
        return False

def is_valid_hostname(hostname: str) -> bool:
    """
    Validate hostname format.
    
    Args:
        hostname: Hostname to validate
        
    Returns:
        bool indicating if hostname is valid
    """
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def sanitize_input(value: str) -> str:
    """
    Sanitize input string for safe usage.
    
    Args:
        value: String to sanitize
        
    Returns:
        Sanitized string
    """
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[;&|`$]', '', value)
    return sanitized.strip()

def generate_file_hash(file_path: Union[str, Path]) -> str:
    """
    Generate SHA-256 hash of file.
    
    Args:
        file_path: Path to file
        
    Returns:
        Hex digest of file hash
    """
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

def load_json_config(config_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Load JSON configuration file.
    
    Args:
        config_path: Path to config file
        
    Returns:
        Configuration dictionary
        
    Raises:
        ConfigError: If config loading fails
    """
    try:
        with open(config_path) as f:
            return json.load(f)
    except Exception as e:
        raise ConfigError(f"Failed to load config: {str(e)}")

def save_json_config(
    config: Dict[str, Any],
    config_path: Union[str, Path]
) -> None:
    """
    Save configuration to JSON file.
    
    Args:
        config: Configuration to save
        config_path: Path to save config
        
    Raises:
        ConfigError: If config saving fails
    """
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        raise ConfigError(f"Failed to save config: {str(e)}")

def rate_limit(calls: int, period: float):
    """
    Rate limiting decorator.
    
    Args:
        calls: Number of calls allowed
        period: Time period in seconds
    """
    def decorator(func):
        timestamps = []
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            
            # Remove old timestamps
            while timestamps and now - timestamps[0] > period:
                timestamps.pop(0)
            
            if len(timestamps) >= calls:
                sleep_time = timestamps[0] + period - now
                if sleep_time > 0:
                    time.sleep(sleep_time)
            
            timestamps.append(now)
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

def format_duration(seconds: float) -> str:
    """
    Format duration in human-readable format.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f}m"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f}h"
    days = hours / 24
    return f"{days:.1f}d"

def ensure_dir(path: Union[str, Path]) -> Path:
    """
    Ensure directory exists, create if necessary.
    
    Args:
        path: Directory path
        
    Returns:
        Path object for directory
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path

def get_timestamp() -> str:
    """
    Get current timestamp string.
    
    Returns:
        Formatted timestamp
    """
    return datetime.now().strftime("%Y%m%d_%H%M%S")

# Import utility components
from .cli import CLI
from .logger import setup_logging

__all__ = [
    'CLI',
    'setup_logging',
    'validate_ip',
    'validate_port',
    'validate_port_range',
    'is_valid_hostname',
    'sanitize_input',
    'generate_file_hash',
    'load_json_config',
    'save_json_config',
    'rate_limit',
    'format_duration',
    'ensure_dir',
    'get_timestamp',
    'NetworkUtilsError',
    'ValidationError',
    'ConfigError'
]