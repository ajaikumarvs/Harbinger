"""
Network Services Module for Net-Sentinel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module handles service detection, version identification,
and protocol analysis for discovered network services.
"""

import logging
import asyncio
from typing import Dict, List, Any, Optional, Tuple
import socket
import ssl
import re
from dataclasses import dataclass
from datetime import datetime
import struct
import json
import aiohttp
import async_timeout

# src/net_sentinel/network/services.py
from typing import Dict, List, Any, Optional
from net_sentinel.utils.logger import setup_logging

from . import Service, ServiceDetectionError, ScanOptions
from ..utils.logger import setup_logging

logger = logging.getLogger(__name__)

@dataclass
class ServiceProbe:
    """Definition for a service probe."""
    name: str
    ports: List[int]
    protocol: str
    probe_string: bytes
    pattern: str
    ssl: bool = False
    timeout: float = 3.0

class ServiceDetector:
    """
    Handles detection and identification of network services.
    """
    
    def __init__(self):
        """Initialize the service detector."""
        self._load_probes()
        self._load_patterns()
    
    def _load_probes(self) -> None:
        """Load service probes from configuration."""
        self.probes = {
            'http': ServiceProbe(
                name='http',
                ports=[80, 8080, 8000],
                protocol='tcp',
                probe_string=b'GET / HTTP/1.0\r\n\r\n',
                pattern=r'HTTP/[\d.]+\s+(\d+)\s+'
            ),
            'https': ServiceProbe(
                name='https',
                ports=[443, 8443],
                protocol='tcp',
                probe_string=b'',  # SSL handshake only
                pattern=r'',
                ssl=True
            ),
            'ssh': ServiceProbe(
                name='ssh',
                ports=[22],
                protocol='tcp',
                probe_string=b'',  # Banner only
                pattern=r'SSH-([\d.]+)-([^\r\n]+)'
            ),
            'ftp': ServiceProbe(
                name='ftp',
                ports=[21],
                protocol='tcp',
                probe_string=b'',  # Banner only
                pattern=r'^220[ -]([^\r\n]+)'
            ),
            'smtp': ServiceProbe(
                name='smtp',
                ports=[25, 587],
                protocol='tcp',
                probe_string=b'HELO net-sentinel\r\n',
                pattern=r'^220[ -]([^\r\n]+)'
            ),
            'dns': ServiceProbe(
                name='dns',
                ports=[53],
                protocol='udp',
                probe_string=self._create_dns_probe(),
                pattern=r''  # DNS response parsing is handled separately
            )
        }
    
    def _load_patterns(self) -> None:
        """Load version detection patterns."""
        self.patterns = {
            'http_server': re.compile(r'Server:\s*([^\r\n]+)', re.I),
            'http_powered': re.compile(r'X-Powered-By:\s*([^\r\n]+)', re.I),
            'ssh_version': re.compile(r'SSH-([\d.]+)-([^\r\n]+)'),
            'ftp_version': re.compile(r'^220[- ]([^\r\n]+)', re.I),
            'smtp_version': re.compile(r'^220[- ]([^\r\n]+)', re.I)
        }
    
    async def detect_service(
        self,
        host: str,
        port: int,
        protocol: str = 'tcp',
        options: Optional[ScanOptions] = None
    ) -> Optional[Service]:
        """
        Detect service on specified port.
        
        Args:
            host: Target host
            port: Target port
            protocol: Protocol (tcp/udp)
            options: Scan options
            
        Returns:
            Service object if detected, None otherwise
        """
        try:
            # Find appropriate probe
            probe = self._get_probe_for_port(port, protocol)
            if not probe:
                return None
            
            # Attempt service detection
            service_info = await self._probe_service(
                host,
                port,
                probe,
                options
            )
            
            if service_info:
                return Service(
                    port=port,
                    protocol=protocol,
                    **service_info
                )
            
            return None
            
        except Exception as e:
            logger.debug(f"Service detection failed for {host}:{port}: {str(e)}")
            return None
    
    async def detect_multiple(
        self,
        host: str,
        ports: List[Dict[str, Any]],
        options: Optional[ScanOptions] = None
    ) -> List[Service]:
        """
        Detect services on multiple ports.
        
        Args:
            host: Target host
            ports: List of port dictionaries
            options: Scan options
            
        Returns:
            List of detected services
        """
        services = []
        
        # Create detection tasks
        tasks = [
            self.detect_service(
                host,
                port['port'],
                port.get('protocol', 'tcp'),
                options
            )
            for port in ports
        ]
        
        # Run detections concurrently in batches
        batch_size = 10  # Adjust based on options if needed
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Service):
                    services.append(result)
            
            # Small delay between batches
            await asyncio.sleep(0.1)
        
        return services
    
    def _get_probe_for_port(
        self,
        port: int,
        protocol: str
    ) -> Optional[ServiceProbe]:
        """Get appropriate probe for port number."""
        for probe in self.probes.values():
            if port in probe.ports and probe.protocol == protocol:
                return probe
        return None
    
    async def _probe_service(
        self,
        host: str,
        port: int,
        probe: ServiceProbe,
        options: Optional[ScanOptions]
    ) -> Optional[Dict[str, Any]]:
        """
        Probe service with appropriate detection method.
        
        Args:
            host: Target host
            port: Target port
            probe: Service probe to use
            options: Scan options
            
        Returns:
            Dictionary with service information if detected
        """
        timeout = options.timeout if options else probe.timeout
        
        try:
            if probe.ssl:
                return await self._probe_ssl_service(host, port, timeout)
            
            if probe.protocol == 'tcp':
                return await self._probe_tcp_service(
                    host,
                    port,
                    probe,
                    timeout
                )
            elif probe.protocol == 'udp':
                return await self._probe_udp_service(
                    host,
                    port,
                    probe,
                    timeout
                )
                
        except Exception as e:
            logger.debug(f"Probe failed for {host}:{port}: {str(e)}")
            return None
    
    async def _probe_tcp_service(
        self,
        host: str,
        port: int,
        probe: ServiceProbe,
        timeout: float
    ) -> Optional[Dict[str, Any]]:
        """Probe TCP service."""
        try:
            # Create connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            service_info = {
                'state': 'open',
                'service': probe.name
            }
            
            try:
                # Send probe if specified
                if probe.probe_string:
                    writer.write(probe.probe_string)
                    await writer.drain()
                
                # Read response
                with async_timeout.timeout(timeout):
                    response = await reader.read(4096)
                
                # Parse banner
                if response:
                    service_info['banner'] = response.decode('utf-8', 'ignore')
                    
                    # Extract version information
                    version_info = self._extract_version_info(
                        probe.name,
                        service_info['banner']
                    )
                    if version_info:
                        service_info.update(version_info)
                
            finally:
                writer.close()
                await writer.wait_closed()
            
            return service_info
            
        except Exception as e:
            logger.debug(f"TCP probe failed: {str(e)}")
            return None
    
    async def _probe_udp_service(
        self,
        host: str,
        port: int,
        probe: ServiceProbe,
        timeout: float
    ) -> Optional[Dict[str, Any]]:
        """Probe UDP service."""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            # Send probe
            sock.sendto(probe.probe_string, (host, port))
            
            # Read response
            try:
                data, _ = sock.recvfrom(4096)
                if data:
                    if probe.name == 'dns':
                        return self._parse_dns_response(data)
                    return {
                        'state': 'open',
                        'service': probe.name,
                        'banner': data.hex()
                    }
            finally:
                sock.close()
            
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"UDP probe failed: {str(e)}")
            return None
    
    async def _probe_ssl_service(
        self,
        host: str,
        port: int,
        timeout: float
    ) -> Optional[Dict[str, Any]]:
        """Probe SSL/TLS service."""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect with SSL
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                    ssl=context
                ),
                timeout=timeout
            )
            
            try:
                # Get SSL certificate information
                ssl_object = writer.get_extra_info('ssl_object')
                if ssl_object:
                    cert = ssl_object.getpeercert(binary_form=True)
                    if cert:
                        return {
                            'state': 'open',
                            'service': 'https',
                            'tunnel': 'ssl',
                            'version': ssl_object.version(),
                            'cert_info': self._parse_ssl_cert(cert)
                        }
            finally:
                writer.close()
                await writer.wait_closed()
            
        except Exception as e:
            logger.debug(f"SSL probe failed: {str(e)}")
            return None
    
    def _extract_version_info(
        self,
        service_name: str,
        banner: str
    ) -> Optional[Dict[str, str]]:
        """Extract version information from banner."""
        pattern_key = f"{service_name}_version"
        if pattern_key in self.patterns:
            match = self.patterns[pattern_key].search(banner)
            if match:
                return {'version': match.group(1)}
        return None
    
    def _create_dns_probe(self) -> bytes:
        """Create DNS query probe."""
        # Create DNS query for version.bind TXT record
        return struct.pack(
            '!HHHHHH',
            0x1234,  # Transaction ID
            0x0100,  # Flags (standard query)
            0x0001,  # Questions
            0x0000,  # Answer RRs
            0x0000,  # Authority RRs
            0x0000   # Additional RRs
        ) + b'\x07version\x04bind\x00\x00\x10\x00\x03'
    
    def _parse_dns_response(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse DNS response."""
        try:
            # Basic DNS response validation
            if len(data) < 12:
                return None
            
            return {
                'state': 'open',
                'service': 'dns',
                'protocol': 'udp',
                'response_size': len(data)
            }
        except Exception:
            return None
    
    def _parse_ssl_cert(self, cert_data: bytes) -> Dict[str, Any]:
        """Parse SSL certificate information."""
        try:
            return {
                'cert_size': len(cert_data),
                'cert_fingerprint': self._get_cert_fingerprint(cert_data)
            }
        except Exception:
            return {}