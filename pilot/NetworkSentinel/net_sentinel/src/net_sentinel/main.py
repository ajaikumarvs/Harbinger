# src/main.py
#!/usr/bin/env python3

import argparse
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pathlib import Path
from typing import Optional, List

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from net_sentinel.network.discovery import NetworkDiscovery
from net_sentinel.utils.cli import CLI

from utils.cli import CLI
from utils.logger import setup_logging
from network.discovery import NetworkDiscovery
from vulnerability.scanner import VulnerabilityScanner
from ai.llm_manager import LLMManager
from exploit.executor import ExploitExecutor
from reporting.html_generator import HTMLReporter
from reporting.xml_generator import XMLReporter

class VAPTTool:
    def __init__(self):
        self.logger = setup_logging()
        self.llm = LLMManager()
        self.discovery = NetworkDiscovery()
        self.scanner = VulnerabilityScanner()
        self.exploit_executor = ExploitExecutor()
        
    def run(self, args: argparse.Namespace) -> int:
        try:
            # Network Discovery Phase
            self.logger.info("Starting network discovery...")
            discovered_hosts = self.discovery.scan_network(
                target=args.target,
                ports=args.ports,
                timeout=args.timeout
            )
            
            # Vulnerability Assessment Phase
            self.logger.info("Beginning vulnerability assessment...")
            vulnerabilities = self.scanner.scan_hosts(
                hosts=discovered_hosts,
                intensity=args.scan_intensity
            )
            
            # AI Guidance Integration
            if args.ai_guidance:
                guidance = self.llm.analyze_vulnerabilities(vulnerabilities)
                self.logger.info("AI Recommendations: %s", guidance)
            
            # Exploitation Phase (if requested)
            if args.exploit:
                self.exploit_executor.run_exploits(
                    targets=vulnerabilities,
                    safe_mode=args.safe_mode
                )
            
            # Report Generation
            if args.output_html:
                HTMLReporter().generate_report(
                    path=args.output_html,
                    data={
                        'hosts': discovered_hosts,
                        'vulnerabilities': vulnerabilities
                    }
                )
            
            if args.output_xml:
                XMLReporter().generate_report(
                    path=args.output_xml,
                    data={
                        'hosts': discovered_hosts,
                        'vulnerabilities': vulnerabilities
                    }
                )
            
            return 0
            
        except Exception as e:
            self.logger.error("Fatal error: %s", str(e))
            return 1

def main():
    cli = CLI()
    args = cli.parse_args()
    
    tool = VAPTTool()
    sys.exit(tool.run(args))

if __name__ == "__main__":
    main()

# src/utils/cli.py
import argparse
from typing import Optional

class CLI:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="Net-Sentinel - Network Security Assessment Tool with AI Guidance"
        )
        self._setup_arguments()
    
    def _setup_arguments(self):
        self.parser.add_argument(
            'target',
            help="Target network range (CIDR notation) or host"
        )
        
        self.parser.add_argument(
            '-p', '--ports',
            help="Port range to scan (default: top 1000)",
            default="1-1000"
        )
        
        self.parser.add_argument(
            '-t', '--timeout',
            help="Timeout for network operations (seconds)",
            type=int,
            default=30
        )
        
        self.parser.add_argument(
            '--scan-intensity',
            choices=['light', 'moderate', 'aggressive'],
            default='moderate',
            help="Vulnerability scan intensity"
        )
        
        self.parser.add_argument(
            '--ai-guidance',
            action='store_true',
            help="Enable AI-powered guidance during scan"
        )
        
        self.parser.add_argument(
            '--exploit',
            action='store_true',
            help="Enable exploitation capabilities"
        )
        
        self.parser.add_argument(
            '--safe-mode',
            action='store_true',
            help="Run exploits in safe mode (no actual exploitation)"
        )
        
        self.parser.add_argument(
            '--output-html',
            type=str,
            help="Path for HTML report output"
        )
        
        self.parser.add_argument(
            '--output-xml',
            type=str,
            help="Path for XML report output"
        )
    
    def parse_args(self) -> argparse.Namespace:
        return self.parser.parse_args()

# src/network/discovery.py
from typing import List, Dict
import socket
import ipaddress
import concurrent.futures
from scapy.all import ARP, Ether, srp
import nmap

class NetworkDiscovery:
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def scan_network(
        self,
        target: str,
        ports: str = "1-1000",
        timeout: int = 30
    ) -> List[Dict]:
        """
        Perform network discovery using a combination of ARP and
        TCP scanning techniques.
        
        Args:
            target: Target network range in CIDR notation or single host
            ports: Port range to scan
            timeout: Scan timeout in seconds
            
        Returns:
            List of discovered hosts with their details
        """
        discovered_hosts = []
        
        try:
            # First, perform ARP scan for local network
            if ipaddress.ip_network(target).num_addresses <= 256:
                discovered_hosts.extend(self._arp_scan(target))
            
            # Then perform TCP scan
            self.nm.scan(
                hosts=target,
                ports=ports,
                arguments=f'-sS -T4 --max-retries 2 --host-timeout {timeout}s'
            )
            
            for host in self.nm.all_hosts():
                host_info = {
                    'ip': host,
                    'hostname': self._get_hostname(host),
                    'status': self.nm[host].state(),
                    'ports': []
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        host_info['ports'].append({
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'version': port_info.get('version', '')
                        })
                
                discovered_hosts.append(host_info)
            
            return discovered_hosts
            
        except Exception as e:
            raise RuntimeError(f"Network discovery failed: {str(e)}")
    
    def _arp_scan(self, target: str) -> List[Dict]:
        """Perform ARP scan for local network discovery."""
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target),
                timeout=2,
                verbose=False
            )
            
            return [
                {
                    'ip': rcv.psrc,
                    'mac': rcv.hwsrc,
                    'status': 'up'
                }
                for snd, rcv in ans
            ]
        except Exception:
            return []
    
    def _get_hostname(self, ip: str) -> str:
        """Resolve hostname for an IP address."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return ""