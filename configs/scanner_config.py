from dataclasses import dataclass
from typing import Dict, List, Optional
from pathlib import Path
import os

@dataclass
class RequestConfig:
    """Configuration for HTTP requests"""
    timeout: int = 30
    max_retries: int = 3
    verify_ssl: bool = True
    follow_redirects: bool = True
    max_redirects: int = 10
    user_agent: str = "CustomScanner/1.0"
    default_headers: Dict[str, str] = None
    cookies: Dict[str, str] = None
    proxy: Dict[str, str] = None

    def __post_init__(self):
        if self.default_headers is None:
            self.default_headers = {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",
            }
        if self.cookies is None:
            self.cookies = {}
        if self.proxy is None:
            self.proxy = {}

@dataclass
class CrawlerConfig:
    """Configuration for web crawler"""
    max_depth: int = 3
    max_pages_per_domain: int = 100
    respect_robots_txt: bool = True
    allowed_domains: List[str] = None
    excluded_paths: List[str] = None
    included_paths: List[str] = None
    parse_javascript: bool = True
    parse_forms: bool = True
    allowed_schemes: List[str] = None

    def __post_init__(self):
        if self.allowed_domains is None:
            self.allowed_domains = []
        if self.excluded_paths is None:
            self.excluded_paths = [
                '/logout',
                '/delete',
                '/remove',
                '/admin'
            ]
        if self.included_paths is None:
            self.included_paths = []
        if self.allowed_schemes is None:
            self.allowed_schemes = ['http', 'https']

@dataclass
class ScannerConfig:
    """Main scanner configuration"""
    max_threads: int = 10
    rate_limit: int = 50  # requests per second
    scan_timeout: int = 3600  # 1 hour
    output_dir: Path = Path("reports")
    temp_dir: Path = Path("temp")
    debug: bool = False
    verbose: bool = False
    
    # Vulnerability scan settings
    enable_active_scan: bool = True
    enable_passive_scan: bool = True
    risk_level: str = "medium"  # low, medium, high
    
    # Authentication settings
    auth_method: Optional[str] = None  # basic, digest, oauth, jwt
    auth_credentials: Dict[str, str] = None
    
    def __post_init__(self):
        if self.auth_credentials is None:
            self.auth_credentials = {}
        
        # Create necessary directories
        self.output_dir.mkdir(exist_ok=True)
        self.temp_dir.mkdir(exist_ok=True)

class VulnerabilityScanConfig:
    """Configuration for different vulnerability scanners"""
    
    XSS = {
        "enabled": True,
        "payloads_file": "configs/payloads/xss_payloads.txt",
        "check_reflected": True,
        "check_stored": True,
        "check_dom": True
    }
    
    SQL_INJECTION = {
        "enabled": True,
        "payloads_file": "configs/payloads/sqli_payloads.txt",
        "check_error_based": True,
        "check_blind": True,
        "check_time_based": True
    }
    
    SSRF = {
        "enabled": True,
        "payloads_file": "configs/payloads/ssrf_payloads.txt",
        "callback_url": "http://localhost:8000",
        "check_internal_services": False
    }
    
    FILE_INCLUSION = {
        "enabled": True,
        "payloads_file": "configs/payloads/lfi_payloads.txt",
        "check_null_byte": True,
        "check_path_traversal": True
    }

def load_config(config_file: str = None) -> tuple[RequestConfig, CrawlerConfig, ScannerConfig]:
    """
    Load configuration from file or return default configuration
    
    Args:
        config_file: Path to configuration file (yaml/json)
        
    Returns:
        Tuple of configuration objects
    """
    if config_file and os.path.exists(config_file):
        # TODO: Implement configuration file loading
        # This could use yaml or json format
        pass
    
    # Return default configuration
    return (
        RequestConfig(),
        CrawlerConfig(),
        ScannerConfig()
    )

def get_vulnerability_config(vuln_type: str) -> dict:
    """
    Get configuration for specific vulnerability type
    
    Args:
        vuln_type: Type of vulnerability (xss, sql_injection, etc.)
        
    Returns:
        Configuration dictionary for the vulnerability type
    """
    config_map = {
        "xss": VulnerabilityScanConfig.XSS,
        "sql_injection": VulnerabilityScanConfig.SQL_INJECTION,
        "ssrf": VulnerabilityScanConfig.SSRF,
        "file_inclusion": VulnerabilityScanConfig.FILE_INCLUSION
    }
    
    return config_map.get(vuln_type.lower(), {})

# Environment-specific configurations
DEVELOPMENT = {
    "debug": True,
    "verbose": True,
    "risk_level": "low",
    "max_threads": 2
}

PRODUCTION = {
    "debug": False,
    "verbose": False,
    "risk_level": "medium",
    "max_threads": 10
}

# Default configuration based on environment
CURRENT_ENV = os.getenv("SCANNER_ENV", "development")
DEFAULT_CONFIG = DEVELOPMENT if CURRENT_ENV.lower() == "development" else PRODUCTION