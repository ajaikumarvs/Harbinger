"""
Tests for Net-Sentinel Network Components
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module provides test cases for network discovery and
service detection functionality.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
import socket
from typing import List, Dict, Any
import ipaddress

from net_sentinel.network import (
    NetworkDiscovery,
    ServiceDetector,
    ScanType,
    ScanSpeed,
    ScanOptions,
    Host,
    Service,
    NetworkError
)
from tests import BaseTestCase, async_test, TestConfig

class TestNetworkDiscovery(BaseTestCase):
    """Test cases for network discovery functionality."""
    
    def setup_method(self, method):
        """Set up test method."""
        super().setup_method(method)
        self.discovery = NetworkDiscovery()
        self.options = ScanOptions(
            scan_type=ScanType.TCP_CONNECT,
            speed=ScanSpeed.NORMAL,
            ports="80,443,22",
            timeout=1.0
        )
    
    @pytest.mark.asyncio
    async def test_scan_network(self, mock_network_responses):
        """Test network range scanning."""
        target = "192.168.1.0/24"
        
        # Setup mock responses
        mock_network_responses.add_host("192.168.1.1", [80, 443])
        mock_network_responses.add_host("192.168.1.2", [22, 80])
        
        results = await self.discovery.scan_network(target, self.options)
        
        assert isinstance(results, list)
        assert len(results) == 2
        assert all(isinstance(host, Host) for host in results)
        
        # Verify discovered hosts
        assert any(h.ip == "192.168.1.1" for h in results)
        assert any(h.ip == "192.168.1.2" for h in results)
    
    @pytest.mark.asyncio
    async def test_scan_single_host(self):
        """Test single host scanning."""
        target = "192.168.1.100"
        
        with patch('socket.socket') as mock_socket:
            # Mock successful connection to port 80
            mock_socket.return_value.connect_ex.return_value = 0
            
            result = await self.discovery.scan_host(
                target,
                self.options
            )
            
            assert isinstance(result, Host)
            assert result.ip == target
            assert 80 in [p['port'] for p in result.ports]
    
    @pytest.mark.asyncio
    async def test_scan_speed_control(self):
        """Test scan speed controls."""
        target = "192.168.1.0/24"
        
        # Test with different speeds
        speeds = [
            (ScanSpeed.SNEAKY, 30),    # Slower
            (ScanSpeed.NORMAL, 10),     # Normal
            (ScanSpeed.AGGRESSIVE, 5)   # Faster
        ]
        
        for speed, expected_batch_size in speeds:
            options = ScanOptions(
                scan_type=ScanType.TCP_CONNECT,
                speed=speed,
                ports="80"
            )
            
            with patch('net_sentinel.network.discovery.NetworkDiscovery._tcp_connect_scan') as mock_scan:
                await self.discovery.scan_network(target, options)
                
                # Verify batch size matches speed
                called_batch_sizes = [
                    len(call.args[0])
                    for call in mock_scan.call_args_list
                ]
                assert max(called_batch_sizes) <= expected_batch_size
    
    def test_port_parsing(self):
        """Test port specification parsing."""
        test_cases = [
            ("80", [80]),
            ("80,443", [80, 443]),
            ("80-85", [80, 81, 82, 83, 84, 85]),
            ("80,443,8000-8002", [80, 443, 8000, 8001, 8002])
        ]
        
        for port_spec, expected in test_cases:
            options = ScanOptions(ports=port_spec)
            assert self.discovery._parse_ports(options.ports) == expected
    
    def test_invalid_targets(self):
        """Test handling of invalid targets."""
        invalid_targets = [
            "256.256.256.256",  # Invalid IP
            "invalid.host!name",  # Invalid hostname
            "192.168.1.0/40"     # Invalid CIDR
        ]
        
        for target in invalid_targets:
            with pytest.raises(NetworkError):
                asyncio.run(self.discovery.scan_network(target))

class TestServiceDetector(BaseTestCase):
    """Test cases for service detection functionality."""
    
    def setup_method(self, method):
        """Set up test method."""
        super().setup_method(method)
        self.detector = ServiceDetector()
    
    @pytest.mark.asyncio
    async def test_detect_service(self):
        """Test service detection."""
        host = "192.168.1.100"
        port = 80
        
        with patch('asyncio.open_connection') as mock_conn:
            # Mock HTTP response
            mock_conn.return_value = (
                AsyncMock(read=AsyncMock(return_value=b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.29\r\n")),
                AsyncMock(close=AsyncMock(), wait_closed=AsyncMock())
            )
            
            service = await self.detector.detect_service(
                host,
                port,
                protocol="tcp"
            )
            
            assert isinstance(service, Service)
            assert service.service == "http"
            assert service.version == "2.4.29"
            assert service.port == port
    
    @pytest.mark.asyncio
    async def test_detect_multiple(self):
        """Test detection of multiple services."""
        host = "192.168.1.100"
        ports = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
            {"port": 22, "protocol": "tcp"}
        ]
        
        with patch('net_sentinel.network.services.ServiceDetector.detect_service') as mock_detect:
            mock_detect.side_effect = [
                Service(port=80, protocol="tcp", service="http", version="2.4.29"),
                Service(port=443, protocol="tcp", service="https"),
                Service(port=22, protocol="tcp", service="ssh", version="OpenSSH_8.2p1")
            ]
            
            services = await self.detector.detect_multiple(
                host,
                ports
            )
            
            assert len(services) == 3
            assert all(isinstance(s, Service) for s in services)
            assert any(s.service == "http" for s in services)
            assert any(s.service == "https" for s in services)
            assert any(s.service == "ssh" for s in services)
    
    @pytest.mark.asyncio
    async def test_ssl_detection(self):
        """Test SSL/TLS service detection."""
        host = "192.168.1.100"
        port = 443
        
        with patch('ssl.create_default_context') as mock_ssl:
            mock_ssl.return_value.wrap_socket.return_value = Mock(
                getpeercert=Mock(return_value={
                    "subject": ((("commonName", "example.com"),),),
                    "version": 3
                })
            )
            
            service = await self.detector.detect_service(
                host,
                port,
                protocol="tcp"
            )
            
            assert service.service == "https"
            assert service.tunnel == "ssl"
            assert "certificate" in service.banner.lower()
    
    def test_service_matching(self):
        """Test service matching patterns."""
        test_cases = [
            (b"SSH-2.0-OpenSSH_8.2p1", "ssh", "8.2p1"),
            (b"220 ProFTPD 1.3.5e Server", "ftp", "1.3.5e"),
            (b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0", "http", "1.18.0")
        ]
        
        for banner, expected_service, expected_version in test_cases:
            service_info = self.detector._match_service_banner(banner)
            assert service_info['service'] == expected_service
            assert service_info['version'] == expected_version

@pytest.fixture
def mock_network_responses():
    """Provide mock network response handler."""
    class MockNetworkResponses:
        def __init__(self):
            self.hosts = {}
            
        def add_host(self, ip: str, ports: List[int]):
            self.hosts[ip] = ports
            
        async def mock_connect(self, ip: str, port: int) -> bool:
            return port in self.hosts.get(ip, [])
    
    return MockNetworkResponses()

@pytest.fixture
def sample_host():
    """Provide sample host data."""
    return Host(
        ip="192.168.1.100",
        hostname="test-host",
        mac="00:11:22:33:44:55",
        status="up",
        ports=[
            {"port": 80, "protocol": "tcp", "state": "open"},
            {"port": 443, "protocol": "tcp", "state": "open"}
        ]
    )

@pytest.fixture
def mock_socket_responses():
    """Provide mock socket response handler."""
    class MockSocketResponse:
        def __init__(self):
            self.responses = {}
            
        def add_response(self, port: int, response: bytes):
            self.responses[port] = response
            
        def get_response(self, port: int) -> bytes:
            return self.responses.get(port, b"")