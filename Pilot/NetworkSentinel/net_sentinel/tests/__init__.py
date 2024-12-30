"""
Net-Sentinel Test Suite
~~~~~~~~~~~~~~~~~~

This module provides common utilities and fixtures for testing
the Net-Sentinel security assessment tool.
"""

import os
import sys
import logging
import pytest
import tempfile
from typing import Generator, Any, Dict
from pathlib import Path
import json
import asyncio
from unittest.mock import MagicMock
from contextlib import contextmanager

# Add src directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

# Configure test logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class TestConfig:
    """Test configuration settings."""
    # Test data paths
    TEST_DATA_DIR = Path(__file__).parent / "data"
    MOCK_DATA_DIR = TEST_DATA_DIR / "mocks"
    SAMPLE_SCANS_DIR = TEST_DATA_DIR / "sample_scans"
    
    # Test timeouts
    DEFAULT_TIMEOUT = 5.0
    NETWORK_TIMEOUT = 10.0
    
    # Test targets
    SAFE_TEST_TARGETS = [
        "127.0.0.1",
        "localhost",
        "test.local"
    ]

@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)

@pytest.fixture
def mock_config() -> Dict[str, Any]:
    """Provide mock configuration."""
    return {
        'max_depth': 2,
        'timeout': 3.0,
        'concurrent_scans': 5,
        'scan_types': ['network', 'service'],
        'user_agent': 'Net-Sentinel-Test',
        'follow_redirects': True
    }

@pytest.fixture
def sample_scan_data() -> Dict[str, Any]:
    """Load sample scan data."""
    data_file = TestConfig.SAMPLE_SCANS_DIR / "sample_scan.json"
    with open(data_file) as f:
        return json.load(f)

@pytest.fixture
async def mock_network_discovery() -> MagicMock:
    """Provide mock network discovery."""
    mock = MagicMock()
    mock.scan_network.return_value = [
        {'ip': '192.168.1.1', 'ports': [80, 443]},
        {'ip': '192.168.1.2', 'ports': [22, 80]}
    ]
    return mock

@pytest.fixture
async def mock_service_detector() -> MagicMock:
    """Provide mock service detector."""
    mock = MagicMock()
    mock.detect_service.return_value = {
        'service': 'http',
        'version': '2.4.29',
        'banner': 'Apache/2.4.29'
    }
    return mock

@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@contextmanager
def mock_file_system():
    """Mock file system operations."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        old_cwd = os.getcwd()
        os.chdir(tmp_dir)
        try:
            yield Path(tmp_dir)
        finally:
            os.chdir(old_cwd)

def load_test_data(filename: str) -> Dict[str, Any]:
    """
    Load test data from file.
    
    Args:
        filename: Test data filename
        
    Returns:
        Loaded test data
        
    Raises:
        FileNotFoundError: If test data file not found
    """
    file_path = TestConfig.TEST_DATA_DIR / filename
    with open(file_path) as f:
        return json.load(f)

def async_test(coro):
    """Decorator for running async tests."""
    def wrapper(*args, **kwargs):
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(coro(*args, **kwargs))
    return wrapper

class AsyncMock(MagicMock):
    """Mock for async functions."""
    async def __call__(self, *args, **kwargs):
        return super(AsyncMock, self).__call__(*args, **kwargs)

class BaseTestCase:
    """Base class for test cases."""
    
    @classmethod
    def setup_class(cls):
        """Set up test class."""
        cls.mock_data = {}
        cls.test_dir = TestConfig.TEST_DATA_DIR
        cls.logger = logging.getLogger(cls.__name__)
    
    def setup_method(self, method):
        """Set up test method."""
        self.logger.info(f"Running test: {method.__name__}")
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self, method):
        """Clean up after test method."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @staticmethod
    def load_mock_data(filename: str) -> Dict[str, Any]:
        """Load mock data for tests."""
        file_path = TestConfig.MOCK_DATA_DIR / filename
        with open(file_path) as f:
            return json.load(f)
    
    @staticmethod
    async def async_context():
        """Provide async context for tests."""
        loop = asyncio.get_event_loop()
        return loop

# Create test data directories if they don't exist
TestConfig.TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)
TestConfig.MOCK_DATA_DIR.mkdir(exist_ok=True)
TestConfig.SAMPLE_SCANS_DIR.mkdir(exist_ok=True)

# Create sample test data if it doesn't exist
if not (TestConfig.SAMPLE_SCANS_DIR / "sample_scan.json").exists():
    sample_data = {
        "scan_time": "2024-12-10T12:00:00",
        "target": "192.168.1.0/24",
        "hosts": [
            {
                "ip": "192.168.1.1",
                "ports": [80, 443],
                "services": ["http", "https"]
            },
            {
                "ip": "192.168.1.2",
                "ports": [22, 80],
                "services": ["ssh", "http"]
            }
        ],
        "vulnerabilities": [
            {
                "title": "Open HTTP Port",
                "severity": "medium",
                "description": "HTTP service is exposed"
            }
        ]
    }
    
    with open(TestConfig.SAMPLE_SCANS_DIR / "sample_scan.json", 'w') as f:
        json.dump(sample_data, f, indent=2)