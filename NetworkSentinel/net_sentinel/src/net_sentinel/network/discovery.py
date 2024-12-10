"""
Network Discovery Module for Net-Sentinel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module handles network discovery and host scanning with
multiple techniques and efficient parallelization.
"""

import logging
import asyncio
from typing import List, Dict, Any, Optional, Set
import ipaddress
import socket
from datetime import datetime
import random
from concurrent.futures import ThreadPoolExecutor
import struct
import time

# additional imports
from net_sentinel.network.services import ServiceDetector
from net_sentinel.utils.logger import setup_logging

import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, TCP, UDP
import nmap

from . import (
    ScanOptions,
    ScanType,
    ScanSpeed,
    Host,
    Service,
    ScanError,
    ServiceDetectionError
)
from .services import ServiceDetector

logger = logging.getLogger(__name__)

class NetworkDiscovery:
    """
    Handles network discovery and host scanning operations.
    """
    
    def __init__(self):
        """Initialize the network discovery module."""
        self.service_detector = ServiceDetector()
        self.nm = nmap.PortScanner()
        self._executor = ThreadPoolExecutor(max_workers=5)
        
    async def scan_network(
        self,
        target: str,
        options: Optional[ScanOptions] = None
    ) -> List[Host]:
        """
        Scan network for hosts and services.
        
        Args:
            target: Target network or host
            options: Scan options
            
        Returns:
            List of discovered hosts
            
        Raises:
            ScanError: If scan fails
        """
        options = options or ScanOptions()
        options.validate()
        
        try:
            # Expand target to IP list
            ip_list = self._expand_target(target)
            
            # Adjust concurrency based on scan speed
            self._adjust_concurrency(options, len(ip_list))
            
            # Initial host discovery
            if not options.skip_ping:
                alive_hosts = await self._discover_hosts(ip_list, options)
            else:
                alive_hosts = [Host(ip=str(ip)) for ip in ip_list]
            
            # Perform port scanning
            if options.scan_type != ScanType.PING:
                await self._scan_ports(alive_hosts, options)
            
            # Service detection if enabled
            if options.service_detection:
                await self._detect_services(alive_hosts, options)
            
            return alive_hosts
            
        except Exception as e:
            logger.error(f"Network scan failed: {str(e)}")
            raise ScanError(f"Network scan failed: {str(e)}")
        
    async def scan_host(
        self,
        target: str,
        options: Optional[ScanOptions] = None
    ) -> Host:
        """
        Scan a single host.
        
        Args:
            target: Target host
            options: Scan options
            
        Returns:
            Host object with scan results
            
        Raises:
            ScanError: If scan fails
        """
        options = options or ScanOptions()
        options.validate()
        
        try:
            # Create host object
            host = Host(ip=target)
            
            # Check if host is up
            if not options.skip_ping:
                if not await self._is_host_alive(target, options):
                    host.status = "down"
                    return host
            
            # Scan ports
            if options.scan_type != ScanType.PING:
                await self._scan_host_ports(host, options)
            
            # Detect services
            if options.service_detection:
                await self._detect_host_services(host, options)
            
            return host
            
        except Exception as e:
            logger.error(f"Host scan failed: {str(e)}")
            raise ScanError(f"Host scan failed: {str(e)}")
    
    def _expand_target(self, target: str) -> List[ipaddress.IPv4Address]:
        """Expand target into list of IP addresses."""
        try:
            # Try as network
            network = ipaddress.ip_network(target, strict=False)
            return list(network.hosts())
        except ValueError:
            try:
                # Try as hostname
                ip = socket.gethostbyname(target)
                return [ipaddress.ip_address(ip)]
            except socket.error as e:
                raise ScanError(f"Invalid target: {str(e)}")
    
    def _adjust_concurrency(self, options: ScanOptions, target_count: int) -> None:
        """Adjust concurrency based on scan speed and target count."""
        speed_multipliers = {
            ScanSpeed.SNEAKY: 0.2,
            ScanSpeed.QUIET: 0.5,
            ScanSpeed.NORMAL: 1.0,
            ScanSpeed.AGGRESSIVE: 2.0,
            ScanSpeed.INSANE: 4.0
        }
        
        multiplier = speed_multipliers[options.speed]
        options.concurrent_hosts = min(
            int(options.concurrent_hosts * multiplier),
            target_count
        )
        options.concurrent_ports = int(options.concurrent_ports * multiplier)
    
    async def _discover_hosts(
        self,
        ip_list: List[ipaddress.IPv4Address],
        options: ScanOptions
    ) -> List[Host]:
        """Discover active hosts using multiple techniques."""
        alive_hosts: Set[str] = set()
        
        # ARP scan for local network
        if self._is_local_network(ip_list[0]):
            arp_results = await self._arp_scan(ip_list)
            alive_hosts.update(arp_results)
        
        # ICMP scan
        icmp_results = await self._icmp_scan(ip_list, options)
        alive_hosts.update(icmp_results)
        
        # TCP scan on common ports for hosts that didn't respond
        remaining_ips = [
            ip for ip in ip_list
            if str(ip) not in alive_hosts
        ]
        if remaining_ips:
            tcp_results = await self._tcp_discovery_scan(
                remaining_ips,
                options
            )
            alive_hosts.update(tcp_results)
        
        return [
            Host(ip=str(ip))
            for ip in ip_list
            if str(ip) in alive_hosts
        ]
    
    async def _arp_scan(
        self,
        ip_list: List[ipaddress.IPv4Address]
    ) -> Set[str]:
        """Perform ARP scan for local network."""
        alive_hosts: Set[str] = set()
        
        # Create ARP requests
        requests = [
            scapy.Ether(dst="ff:ff:ff:ff:ff:ff") /
            scapy.ARP(pdst=str(ip))
            for ip in ip_list
        ]
        
        try:
            # Send requests in chunks to avoid flooding
            chunk_size = 50
            for i in range(0, len(requests), chunk_size):
                chunk = requests[i:i + chunk_size]
                responses, _ = scapy.srp(
                    chunk,
                    timeout=2,
                    verbose=False
                )
                
                for _, rcv in responses:
                    alive_hosts.add(rcv.psrc)
                
                # Small delay between chunks
                await asyncio.sleep(0.1)
                
        except Exception as e:
            logger.warning(f"ARP scan error: {str(e)}")
        
        return alive_hosts
    
    async def _icmp_scan(
        self,
        ip_list: List[ipaddress.IPv4Address],
        options: ScanOptions
    ) -> Set[str]:
        """Perform ICMP echo scan."""
        alive_hosts: Set[str] = set()
        
        async def _ping_host(ip: ipaddress.IPv4Address) -> Optional[str]:
            try:
                reply = await asyncio.get_event_loop().run_in_executor(
                    self._executor,
                    lambda: scapy.sr1(
                        IP(dst=str(ip))/ICMP(),
                        timeout=options.timeout,
                        verbose=False
                    )
                )
                if reply and reply.haslayer(ICMP):
                    return str(ip)
            except Exception as e:
                logger.debug(f"ICMP scan error for {ip}: {str(e)}")
            return None
        
        # Create tasks for concurrent scanning
        tasks = [
            _ping_host(ip)
            for ip in ip_list
        ]
        
        # Run tasks in batches
        batch_size = options.concurrent_hosts
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch)
            alive_hosts.update(host for host in results if host)
            
            # Add delay based on scan speed
            if i + batch_size < len(tasks):
                delay = self._get_speed_delay(options.speed)
                await asyncio.sleep(delay)
        
        return alive_hosts
    
    async def _tcp_discovery_scan(
        self,
        ip_list: List[ipaddress.IPv4Address],
        options: ScanOptions
    ) -> Set[str]:
        """Perform TCP discovery scan on common ports."""
        alive_hosts: Set[str] = set()
        common_ports = [80, 443, 22, 445]  # Common ports for host discovery
        
        async def _tcp_probe(
            ip: ipaddress.IPv4Address,
            port: int
        ) -> Optional[str]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(options.timeout)
                result = await asyncio.get_event_loop().run_in_executor(
                    self._executor,
                    lambda: sock.connect_ex((str(ip), port))
                )
                sock.close()
                
                if result == 0:
                    return str(ip)
            except Exception as e:
                logger.debug(f"TCP probe error for {ip}:{port}: {str(e)}")
            return None
        
        # Create tasks for concurrent scanning
        tasks = [
            _tcp_probe(ip, port)
            for ip in ip_list
            for port in common_ports
        ]
        
        # Run tasks in batches
        batch_size = options.concurrent_hosts * len(common_ports)
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch)
            alive_hosts.update(host for host in results if host)
            
            # Add delay based on scan speed
            if i + batch_size < len(tasks):
                delay = self._get_speed_delay(options.speed)
                await asyncio.sleep(delay)
        
        return alive_hosts
    
    async def _scan_host_ports(
        self,
        host: Host,
        options: ScanOptions
    ) -> None:
        """Scan ports on a single host."""
        try:
            ports_to_scan = self._parse_ports(options.ports)
            scan_tasks = []
            
            if options.scan_type == ScanType.TCP_CONNECT:
                scan_tasks = [
                    self._tcp_connect_scan(host.ip, port, options)
                    for port in ports_to_scan
                ]
            elif options.scan_type == ScanType.TCP_SYN:
                scan_tasks = [
                    self._tcp_syn_scan(host.ip, port, options)
                    for port in ports_to_scan
                ]
            elif options.scan_type == ScanType.UDP:
                scan_tasks = [
                    self._udp_scan(host.ip, port, options)
                    for port in ports_to_scan
                ]
            
            # Run scans in batches
            batch_size = options.concurrent_ports
            for i in range(0, len(scan_tasks), batch_size):
                batch = scan_tasks[i:i + batch_size]
                results = await asyncio.gather(*batch)
                
                # Add open ports to host
                for port_info in results:
                    if port_info and port_info.get('state') == 'open':
                        host.ports.append(port_info)
                
                # Add delay between batches
                if i + batch_size < len(scan_tasks):
                    delay = self._get_speed_delay(options.speed)
                    await asyncio.sleep(delay)
                    
        except Exception as e:
            logger.error(f"Port scan failed for {host.ip}: {str(e)}")
            raise ScanError(f"Port scan failed: {str(e)}")
    
    def _parse_ports(self, ports: Union[str, List[int]]) -> List[int]:
        """Parse port specification into list of ports."""
        if isinstance(ports, list):
            return sorted(ports)
        
        result = []
        for part in ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                result.extend(range(start, end + 1))
            else:
                result.append(int(part))
        return sorted(result)
    
    def _get_speed_delay(self, speed: ScanSpeed) -> float:
        """Get delay between operations based on scan speed."""
        delays = {
            ScanSpeed.SNEAKY: 1.0,
            ScanSpeed.QUIET: 0.5,
            ScanSpeed.NORMAL: 0.1,
            ScanSpeed.AGGRESSIVE: 0.05,
            ScanSpeed.INSANE: 0.01
        }
        return delays[speed]
    
    def _is_local_network(self, ip: ipaddress.IPv4Address) -> bool:
        """Check if IP is in local network."""
        return ip.is_private or ip.is_link_local
    
    def __del__(self):
        """Cleanup resources."""
        if self._executor:
            self._executor.shutdown(wait=True)