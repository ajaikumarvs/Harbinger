import os
import hashlib
import math
import magic
import yara
import re
import logging
from logging.handlers import RotatingFileHandler
import zipfile
import time
import ssdeep
import pefile
import requests
import tempfile
import json
import threading
import queue
import signal
import mmap
import importlib
import subprocess
import struct
import platform
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from termcolor import colored


# Suppress ssdeep warnings
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='ssdeep')
warnings.filterwarnings("ignore", message=r"reimporting '_ssdeep_cffi_\w+' might overwrite older definitions")

@dataclass
class FileMetadata:
    filepath: str
    file_type: str
    file_size: int
    creation_time: float
    modification_time: float
    access_time: float
    owner: str
    permissions: str
    sha256: str
    md5: str
    ssdeep_hash: str
    entropy: float
    magic_signature: str

@dataclass
class ScanResult:
    metadata: FileMetadata
    threats_found: List[Dict[str, Any]]
    scan_time: float
    is_suspicious: bool
    risk_level: str  # 'low', 'medium', 'high', 'critical'
    detection_methods: List[str]
    scan_errors: List[str]

class ThreatIntelligence:
    def __init__(self):
        self.known_malware_hashes = set()
        self.known_malicious_domains = set()
        self.known_malicious_ips = set()
        self.known_ransomware_extensions = set()
        self.update_interval = 86400  # 24 hours
        self.last_update = 0

    def update_threat_intelligence(self):
        """Update threat intelligence from various sources."""
        if time.time() - self.last_update < self.update_interval:
            return

        try:
            # Update from local signature files
            self._update_from_local_signatures()
            
            # Update from custom threat feeds (implement as needed)
            self._update_from_threat_feeds()
            
            self.last_update = time.time()
        except Exception as e:
            logging.error(f"Error updating threat intelligence: {e}")

    def _update_from_local_signatures(self):
        """Update from local signature files."""
        # Implementation for updating from local files
        pass

    def _update_from_threat_feeds(self):
        """Update from online threat feeds."""
        # Implementation for updating from threat feeds
        pass

class HeuristicEngine:
    def __init__(self):
        self.suspicious_patterns = self._compile_patterns()
        self.api_blacklist = self._load_api_blacklist()
        self.entropy_threshold = 7.0

    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile advanced regex patterns for different threat categories."""
        patterns = {
            'shellcode': [
                r'\x55\x8B\xEC',  # Common x86 prologue
                r'\x48\x89\x5C',  # Common x64 prologue
            ],
            'encryption': [
                r'(?i)(aes|rc4|blowfish|des)_(en|de)crypt',
                r'(?i)(rsa|ecc)_(en|de)crypt',
            ],
            'network': [
                r'(?i)(socket|connect|bind|listen|accept)',
                r'(?i)(http[s]?|ftp|smtp|dns)',
            ],
            'process_injection': [
                r'(?i)(createremotethread|virtualallocex|writeprocessmemory)',
                r'(?i)(ntmapviewofsection|ntunmapviewofsection)',
            ],
            'persistence': [
                r'(?i)(run|runonce|userinit|winlogon)',
                r'(?i)(startup|schedule|task|service)',
            ],
            'evasion': [
                r'(?i)(isdebuggerpresent|checkremovedebugger)',
                r'(?i)(sleep|delay|timeout)',
            ]
        }
        
        return {
            category: [re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
                      for pattern in category_patterns]
            for category, category_patterns in patterns.items()
        }

    def _load_api_blacklist(self) -> Dict[str, List[str]]:
        """Load blacklisted API calls by category."""
        return {
            'process': [
                'CreateProcess', 'ShellExecute', 'WinExec',
                'CreateRemoteThread', 'CreateThread'
            ],
            'memory': [
                'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
                'ReadProcessMemory', 'HeapCreate'
            ],
            'registry': [
                'RegCreateKey', 'RegSetValue', 'RegOpenKey',
                'RegDeleteKey', 'RegEnumKey'
            ],
            'network': [
                'socket', 'connect', 'bind', 'send', 'recv',
                'WSAStartup', 'gethostbyname'
            ],
            'file': [
                'CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile',
                'CopyFile', 'MoveFile'
            ]
        }

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
            
        entropy = 0.0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def check_pe_anomalies(self, filepath: str) -> List[Dict[str, Any]]:
        """Check for anomalies in PE files."""
        anomalies = []
        try:
            pe = pefile.PE(filepath)
            
            # Check for packed/encrypted sections
            for section in pe.sections:
                section_entropy = self.calculate_entropy(section.get_data())
                if section_entropy > self.entropy_threshold:
                    anomalies.append({
                        'type': 'high_entropy_section',
                        'details': f"Section {section.Name.decode().strip()} has high entropy: {section_entropy:.2f}"
                    })

            # Check for suspicious section names
            suspicious_sections = {'.text', '.data', '.rdata', '.idata', '.edata', '.pdata', '.rsrc'}
            for section in pe.sections:
                if section.Name.decode().strip() not in suspicious_sections:
                    anomalies.append({
                        'type': 'suspicious_section',
                        'details': f"Suspicious section name: {section.Name.decode().strip()}"
                    })

            # Check for suspicious imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        for category, apis in self.api_blacklist.items():
                            if imp.name and any(api.lower() in imp.name.decode().lower() for api in apis):
                                anomalies.append({
                                    'type': 'suspicious_import',
                                    'details': f"Suspicious {category} API: {imp.name.decode()}"
                                })

            # Check for resource anomalies
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.id == pefile.RESOURCE_TYPE['RT_VERSION']:
                        continue
                    for resource_id in resource_type.directory.entries:
                        for resource_lang in resource_id.directory.entries:
                            data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                            resource_entropy = self.calculate_entropy(data)
                            if resource_entropy > self.entropy_threshold:
                                anomalies.append({
                                    'type': 'suspicious_resource',
                                    'details': f"High entropy resource: Type {resource_type.id}, ID {resource_id.id}"
                                })

        except Exception as e:
            anomalies.append({
                'type': 'pe_analysis_error',
                'details': f"Error analyzing PE file: {str(e)}"
            })

        return anomalies

class MemoryScanner:
    def __init__(self):
        self.page_size = mmap.PAGESIZE
        self.suspicious_patterns = self._compile_memory_patterns()

    def _compile_memory_patterns(self) -> List[re.Pattern]:
        """Compile patterns for memory scanning."""
        patterns = [
            # Shellcode patterns
            rb'\x55\x8B\xEC',  # Common x86 prologue
            rb'\x48\x89\x5C',  # Common x64 prologue
            # Add more patterns as needed
        ]
        return [re.compile(pattern) for pattern in patterns]

    def scan_process_memory(self, pid: int) -> List[Dict[str, Any]]:
        """Scan process memory for suspicious patterns."""
        findings = []
        try:
            with open(f"/proc/{pid}/maps", 'r') as maps, open(f"/proc/{pid}/mem", 'rb', 0) as mem:
                for line in maps:
                    region = line.split()
                    start, end = map(lambda x: int(x, 16), region[0].split('-'))
                    
                    if 'r' in region[1]:  # Only scan readable regions
                        try:
                            mem.seek(start)
                            chunk = mem.read(end - start)
                            
                            # Scan for patterns
                            for pattern in self.suspicious_patterns:
                                for match in pattern.finditer(chunk):
                                    findings.append({
                                        'type': 'suspicious_memory_pattern',
                                        'address': hex(start + match.start()),
                                        'pattern': pattern.pattern,
                                        'region': region[0]
                                    })
                                    
                        except Exception as e:
                            continue  # Skip inaccessible regions
                            
        except Exception as e:
            findings.append({
                'type': 'memory_scan_error',
                'details': str(e)
            })
            
        return findings

class BehaviorMonitor:
    def __init__(self):
        self.suspicious_behaviors = defaultdict(list)
        self.monitoring = False
        self.monitor_thread = None

    def start_monitoring(self):
        """Start monitoring system behavior."""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop monitoring system behavior."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()

    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.monitoring:
            try:
                # Monitor file system changes
                self._monitor_filesystem()
                
                # Monitor network connections
                self._monitor_network()
                
                # Monitor process creation
                self._monitor_processes()
                
                # Monitor registry changes (Windows only)
                if platform.system() == 'Windows':
                    self._monitor_registry()
                    
                time.sleep(1)  # Adjust polling interval as needed
                
            except Exception as e:
                logging.error(f"Error in behavior monitoring: {e}")

    def _monitor_filesystem(self):
        """Monitor file system changes."""
        pass  # Implement file system monitoring

    def _monitor_network(self):
        """Monitor network connections."""
        pass  # Implement network monitoring

    def _monitor_processes(self):
        """Monitor process creation and termination."""
        pass  # Implement process monitoring

    def _monitor_registry(self):
        """Monitor registry changes (Windows only)."""
        pass  # Implement registry monitoring

import xml.etree.ElementTree as ET  # Place at top level

class AdvancedVirusScanner:
    def __init__(self, signature_dir: str = "signatures"):
        self.logger = self._setup_logging()
        self.signature_dir = signature_dir
        self.yara_rules = self._load_yara_rules()
        self.heuristic_engine = HeuristicEngine()
        self.threat_intelligence = ThreatIntelligence()
        self.memory_scanner = MemoryScanner()
        self.behavior_monitor = BehaviorMonitor()
        self.mime_magic = magic.Magic(mime=True)
        self.max_file_size = 500 * 1024 * 1024  # 500MB limit
        self.scanned_files = 0
        self.threats_found = 0
        self.scan_queue = queue.Queue()
        self.results_queue = queue.Queue()
        self.worker_threads = []
        self.scanning = False

    def _setup_logging(self) -> logging.Logger:
        """Configure advanced logging system."""
        logger = logging.getLogger("AdvancedAntivirusScanner")
        logger.setLevel(logging.DEBUG)
        
        # Create handlers with rotation
        console_handler = logging.StreamHandler()
        file_handler = RotatingFileHandler(
            "antivirus_scan.log",
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s'
        )
        console_formatter = logging.Formatter(
            '%(levelname)s - %(message)s'
        )
        
        # Set formatters and levels
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(logging.INFO)
        file_handler.setFormatter(detailed_formatter)
        file_handler.setLevel(logging.DEBUG)
        
        # Add handlers
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        
        return logger

    def start_workers(self, num_workers: int = 4):
        """Start worker threads for parallel scanning."""
        self.scanning = True
        for _ in range(num_workers):
            worker = threading.Thread(target=self._worker_loop)
            worker.daemon = True
            worker.start()
            self.worker_threads.append(worker)

    def stop_workers(self):
        """Stop all worker threads."""
        self.scanning = False
        for _ in self.worker_threads:
            self.scan_queue.put(None)
        for worker in self.worker_threads:
            worker.join()
        self.worker_threads.clear()

    def _worker_loop(self):
        """Worker thread loop for processing files."""
        while self.scanning:
            try:
                task = self.scan_queue.get()
                if task is None:
                    break
                
                filepath = task
                result = self.scan_file(filepath)
                self.results_queue.put(result)
                self.scan_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Worker error: {e}")
                self.scan_queue.task_done()

    def _load_yara_rules(self) -> Optional[yara.Rules]:
        """Load YARA rules from signature directory."""
        try:
            rules_files = {}
            for file in os.listdir(self.signature_dir):
                if file.endswith('.yar'):
                    rule_path = os.path.join(self.signature_dir, file)
                    rules_files[file] = rule_path
            
            if not rules_files:
                self.logger.warning("No YARA rule files found")
                return None
                
            return yara.compile(filepaths=rules_files)
        except Exception as e:
            self.logger.error(f"Error loading YARA rules: {e}")
            return None

    def analyze_file_metadata(self, filepath: str) -> FileMetadata:
        """Gather comprehensive file metadata."""
        try:
            stat = os.stat(filepath)
            file_size = stat.st_size
            
            # Calculate hashes
            with open(filepath, 'rb') as f:
                data = f.read()
                sha256 = hashlib.sha256(data).hexdigest()
                md5 = hashlib.md5(data).hexdigest()
                ssdeep_hash = ssdeep.hash(data)
                entropy = self.heuristic_engine.calculate_entropy(data)

            return FileMetadata(
                filepath=filepath,
                file_type=self.mime_magic.from_file(filepath),
                file_size=file_size,
                creation_time=stat.st_ctime,
                modification_time=stat.st_mtime,
                access_time=stat.st_atime,
                owner=str(stat.st_uid),
                permissions=oct(stat.st_mode),
                sha256=sha256,
                md5=md5,
                ssdeep_hash=ssdeep_hash,
                entropy=entropy,
                magic_signature=magic.Magic().from_file(filepath)
            )
        except Exception as e:
            self.logger.error(f"Error analyzing file metadata for {filepath}: {e}")
            raise

    def scan_file(self, filepath: str) -> ScanResult:
        """Perform comprehensive file scanning."""
        start_time = time.time()
        threats = []
        scan_errors = []
        detection_methods = []

        try:
            # Get file metadata
            metadata = self.analyze_file_metadata(filepath)
            
            # Skip if file is too large
            if metadata.file_size > self.max_file_size:
                scan_errors.append("File exceeds maximum size limit")
                return ScanResult(
                    metadata=metadata,
                    threats_found=[{"type": "size_limit_exceeded", "details": "File too large"}],
                    scan_time=time.time() - start_time,
                    is_suspicious=True,
                    risk_level="medium",
                    detection_methods=[],
                    scan_errors=scan_errors
                )

            # Hash-based detection
            if metadata.sha256 in self.threat_intelligence.known_malware_hashes:
                threats.append({
                    "type": "known_malware",
                    "details": "File hash matches known malware"
                })
                detection_methods.append("hash_detection")

            # YARA scanning
            if self.yara_rules:
                try:
                    matches = self.yara_rules.match(filepath)
                    if matches:
                        threats.extend([{
                            "type": "yara_match",
                            "details": f"Matched rule: {match.rule}"
                        } for match in matches])
                        detection_methods.append("yara_rules")
                except Exception as e:
                    scan_errors.append(f"YARA scan error: {str(e)}")

            # PE file analysis
            if metadata.file_type.startswith('application/x-dosexec'):
                pe_threats = self.heuristic_engine.check_pe_anomalies(filepath)
                if pe_threats:
                    threats.extend(pe_threats)
                    detection_methods.append("pe_analysis")

            # Archive scanning
            if any(metadata.file_type.startswith(ft) for ft in ['application/zip', 'application/x-rar', 'application/x-7z']):
                archive_threats = self.scan_archive(filepath)
                if archive_threats:
                    threats.extend(archive_threats)
                    detection_methods.append("archive_scan")

            # Heuristic analysis
            with open(filepath, 'rb') as f:
                content = f.read()
                for category, patterns in self.heuristic_engine.suspicious_patterns.items():
                    for pattern in patterns:
                        try:
                            text_content = content.decode('utf-8', errors='ignore')
                            matches = pattern.findall(text_content)
                            if matches:
                                threats.append({
                                    "type": "heuristic_detection",
                                    "category": category,
                                    "details": f"Suspicious pattern found: {matches[0]}"
                                })
                                if "heuristic_analysis" not in detection_methods:
                                    detection_methods.append("heuristic_analysis")
                        except Exception as e:
                            scan_errors.append(f"Pattern matching error: {str(e)}")

            # Determine risk level
            risk_level = self._calculate_risk_level(threats)

            return ScanResult(
                metadata=metadata,
                threats_found=threats,
                scan_time=time.time() - start_time,
                is_suspicious=len(threats) > 0,
                risk_level=risk_level,
                detection_methods=detection_methods,
                scan_errors=scan_errors
            )

        except Exception as e:
            self.logger.error(f"Error scanning {filepath}: {e}")
            # Create a default metadata object if metadata collection failed
            default_metadata = FileMetadata(
                filepath=filepath,
                file_type="unknown",
                file_size=0,
                creation_time=0,
                modification_time=0,
                access_time=0,
                owner="unknown",
                permissions="unknown",
                sha256="",
                md5="",
                ssdeep_hash="",
                entropy=0.0,
                magic_signature="unknown"
            )
            
            return ScanResult(
                metadata=metadata if 'metadata' in locals() else default_metadata,
                threats_found=[{"type": "scan_error", "details": str(e)}],
                scan_time=time.time() - start_time,
                is_suspicious=True,
                risk_level="unknown",
                detection_methods=[],
                scan_errors=[str(e)]
            )

    def _calculate_risk_level(self, threats: List[Dict[str, Any]]) -> str:
        """Calculate risk level based on threats found."""
        if not threats:
            return "clean"
            
        # Define threat severity scores
        severity_scores = {
            "known_malware": 10,
            "yara_match": 8,
            "heuristic_detection": 6,
            "suspicious_import": 5,
            "high_entropy_section": 4,
            "suspicious_section": 3,
            "suspicious_resource": 3
        }
        
        # Calculate total severity score
        total_score = sum(severity_scores.get(threat["type"], 1) for threat in threats)
        
        # Determine risk level based on total score
        if total_score >= 10:
            return "critical"
        elif total_score >= 7:
            return "high"
        elif total_score >= 4:
            return "medium"
        else:
            return "low"

    def scan_archive(self, filepath: str) -> List[Dict[str, Any]]:
        """Enhanced archive scanning with support for multiple formats."""
        threats = []
        
        try:
            # Handle ZIP files
            if zipfile.is_zipfile(filepath):
                with zipfile.ZipFile(filepath, 'r') as archive:
                    for file_info in archive.infolist():
                        # Skip directories
                        if file_info.filename.endswith('/'):
                            continue
                            
                        # Check file size
                        if file_info.file_size > self.max_file_size:
                            threats.append({
                                "type": "suspicious_archive",
                                "details": f"Oversized file in archive: {file_info.filename}"
                            })
                            continue

                        # Extract and scan file
                        try:
                            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                                temp_file.write(archive.read(file_info.filename))
                                temp_file.flush()
                                
                                # Scan extracted file
                                result = self.scan_file(temp_file.name)
                                if result.threats_found:
                                    threats.extend([{
                                        "type": "archive_threat",
                                        "filename": file_info.filename,
                                        "details": threat
                                    } for threat in result.threats_found])
                                    
                        except Exception as e:
                            threats.append({
                                "type": "archive_scan_error",
                                "details": f"Error scanning {file_info.filename}: {str(e)}"
                            })
                        finally:
                            if os.path.exists(temp_file.name):
                                os.unlink(temp_file.name)

        except Exception as e:
            threats.append({
                "type": "archive_error",
                "details": f"Error processing archive: {str(e)}"
            })

        return threats

    def scan_directory(self, directory: str, num_workers: int = 4) -> List[ScanResult]:
        """Scan directory using multiple worker threads."""
        results = []
        
        try:
            # Start worker threads
            self.start_workers(num_workers)
            
            # Walk directory and add files to scan queue
            for root, _, files in os.walk(directory):
                for file in files:
                    filepath = os.path.join(root, file)
                    self.scan_queue.put(filepath)

            # Wait for all files to be processed
            self.scan_queue.join()
            
            # Collect results
            while not self.results_queue.empty():
                results.append(self.results_queue.get())
                
        finally:
            # Stop workers
            self.stop_workers()

        return results

    def generate_report(self, results: List[ScanResult], output_prefix: str = "scan_report"):
        """Generate detailed HTML and XML reports with charts and statistics."""
        try:
            import xml.etree.ElementTree as ET  # Local import for ensure availability
            
            html_path = f"{output_prefix}.html"
            xml_path = f"{output_prefix}.xml"
            
            # Calculate statistics
            total_files = len(results)
            clean_files = sum(1 for r in results if not r.is_suspicious)
            suspicious_files = total_files - clean_files
            risk_levels = {
                "critical": sum(1 for r in results if r.risk_level == "critical"),
                "high": sum(1 for r in results if r.risk_level == "high"),
                "medium": sum(1 for r in results if r.risk_level == "medium"),
                "low": sum(1 for r in results if r.risk_level == "low")
            }
            
            # Generate HTML Report
            with open(html_path, 'w') as f:
                f.write("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Antivirus Scan Report</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            line-height: 1.6;
                            margin: 20px;
                            background-color: #f5f5f5;
                        }
                        .container {
                            max-width: 1200px;
                            margin: 0 auto;
                            background-color: white;
                            padding: 20px;
                            border-radius: 8px;
                            box-shadow: 0 0 10px rgba(0,0,0,0.1);
                        }
                        h1, h2, h3 {
                            color: #2c3e50;
                        }
                        .summary-box {
                            background-color: #f8f9fa;
                            border: 1px solid #dee2e6;
                            border-radius: 4px;
                            padding: 15px;
                            margin-bottom: 20px;
                        }
                        .stats {
                            display: grid;
                            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                            gap: 15px;
                            margin-bottom: 20px;
                        }
                        .stat-card {
                            background-color: white;
                            padding: 15px;
                            border-radius: 4px;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                            text-align: center;
                        }
                        .threat-item {
                            background-color: white;
                            padding: 15px;
                            margin-bottom: 15px;
                            border-radius: 4px;
                            border-left: 4px solid;
                        }
                        .risk-critical {
                            border-left-color: #dc3545;
                            background-color: #fff5f5;
                        }
                        .risk-high {
                            border-left-color: #fd7e14;
                            background-color: #fff9f5;
                        }
                        .risk-medium {
                            border-left-color: #ffc107;
                            background-color: #fffdf5;
                        }
                        .risk-low {
                            border-left-color: #28a745;
                            background-color: #f5fff7;
                        }
                        .clean {
                            border-left-color: #20c997;
                            background-color: #f5fffd;
                        }
                        .badge {
                            display: inline-block;
                            padding: 3px 8px;
                            border-radius: 3px;
                            color: white;
                            font-size: 12px;
                            font-weight: bold;
                        }
                        .badge-critical { background-color: #dc3545; }
                        .badge-high { background-color: #fd7e14; }
                        .badge-medium { background-color: #ffc107; color: black; }
                        .badge-low { background-color: #28a745; }
                        .badge-clean { background-color: #20c997; }
                        .threat-details {
                            margin-top: 10px;
                            padding-left: 20px;
                        }
                        .file-info {
                            display: grid;
                            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                            gap: 10px;
                            margin-top: 10px;
                            font-size: 14px;
                        }
                        .detection-method {
                            background-color: #e9ecef;
                            padding: 2px 6px;
                            border-radius: 3px;
                            font-size: 12px;
                            margin-right: 5px;
                        }
                    </style>
                </head>
                <body>
                <div class="container">
                """)
                
                # Write header and summary
                f.write(f"""
                    <h1>Antivirus Scan Report</h1>
                    <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    
                    <div class="summary-box">
                        <h2>Scan Summary</h2>
                        <div class="stats">
                            <div class="stat-card">
                                <h3>Total Files</h3>
                                <p>{total_files}</p>
                            </div>
                            <div class="stat-card">
                                <h3>Clean Files</h3>
                                <p>{clean_files}</p>
                            </div>
                            <div class="stat-card">
                                <h3>Suspicious Files</h3>
                                <p>{suspicious_files}</p>
                            </div>
                        </div>
                        <div class="stats">
                            <div class="stat-card">
                                <h3>Critical Risk</h3>
                                <p>{risk_levels['critical']}</p>
                            </div>
                            <div class="stat-card">
                                <h3>High Risk</h3>
                                <p>{risk_levels['high']}</p>
                            </div>
                            <div class="stat-card">
                                <h3>Medium Risk</h3>
                                <p>{risk_levels['medium']}</p>
                            </div>
                            <div class="stat-card">
                                <h3>Low Risk</h3>
                                <p>{risk_levels['low']}</p>
                            </div>
                        </div>
                    </div>
                """)
                
                # Write detailed results
                f.write("<h2>Detailed Scan Results</h2>")
                for result in results:
                    filepath = result.metadata.filepath if result.metadata else "Unknown file"
                    risk_class = f"risk-{result.risk_level}" if result.is_suspicious else "clean"
                    risk_badge = f"badge-{result.risk_level}" if result.is_suspicious else "badge-clean"
                    
                    f.write(f"""
                    <div class="threat-item {risk_class}">
                        <h3>{os.path.basename(filepath)}</h3>
                        <span class="badge {risk_badge}">
                            {result.risk_level.upper() if result.is_suspicious else 'CLEAN'}
                        </span>
                        
                        <div class="file-info">
                            <div>Path: {filepath}</div>
                            <div>Size: {result.metadata.file_size:,} bytes</div>
                            <div>Type: {result.metadata.file_type}</div>
                            <div>Scan Time: {result.scan_time:.2f} seconds</div>
                        </div>
                    """)
                    
                    if result.detection_methods:
                        f.write("<div style='margin-top: 10px;'>Detection Methods: ")
                        for method in result.detection_methods:
                            f.write(f'<span class="detection-method">{method}</span>')
                        f.write("</div>")
                    
                    if result.threats_found:
                        f.write("""
                        <div class="threat-details">
                            <h4>Threats Found:</h4>
                            <ul>
                        """)
                        for threat in result.threats_found:
                            f.write(f"""
                            <li>
                                <strong>{threat['type']}</strong>: {threat.get('details', '')}
                            </li>
                            """)
                        f.write("</ul></div>")
                    
                    f.write("</div>")
                
                f.write("</div></body></html>")
            
            # Generate XML Report
            root = ET.Element("scan_report")
            ET.SubElement(root, "scan_date").text = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Add summary statistics
            summary = ET.SubElement(root, "summary")
            ET.SubElement(summary, "total_files").text = str(total_files)
            ET.SubElement(summary, "clean_files").text = str(clean_files)
            ET.SubElement(summary, "suspicious_files").text = str(suspicious_files)
            
            risk_stats = ET.SubElement(summary, "risk_levels")
            for level, count in risk_levels.items():
                ET.SubElement(risk_stats, level).text = str(count)
            
            # Add detailed results
            results_element = ET.SubElement(root, "scan_results")
            for result in results:
                result_element = ET.SubElement(results_element, "file")
                
                # Add file metadata
                metadata = ET.SubElement(result_element, "metadata")
                if result.metadata:
                    for field, value in result.metadata.__dict__.items():
                        ET.SubElement(metadata, field).text = str(value)
                
                # Add scan results
                ET.SubElement(result_element, "risk_level").text = result.risk_level
                ET.SubElement(result_element, "is_suspicious").text = str(result.is_suspicious)
                ET.SubElement(result_element, "scan_time").text = str(result.scan_time)
                
                # Add detection methods
                methods = ET.SubElement(result_element, "detection_methods")
                for method in result.detection_methods:
                    ET.SubElement(methods, "method").text = method
                
                # Add threats
                threats = ET.SubElement(result_element, "threats")
                for threat in result.threats_found:
                    threat_element = ET.SubElement(threats, "threat")
                    for key, value in threat.items():
                        ET.SubElement(threat_element, key).text = str(value)
            
            # Write XML to file
            tree = ET.ElementTree(root)
            tree.write(xml_path, encoding='utf-8', xml_declaration=True)
            
            self.logger.info(f"Reports generated: {html_path} and {xml_path}")
            
        except Exception as e:
            self.logger.error(f"Error generating reports: {e}")
            raise

def main():
    """Main function to run the advanced antivirus scanner."""
    scanner = AdvancedVirusScanner()
    
    print("-----Binary Hunter-----")
    print("")
    print("1. Scan file")
    print("2. Scan directory")
    choice = input("Enter choice (1-2): ")
    
    target = input("Enter path to scan: ")
    report_prefix = "scan_report"
    
    start_time = time.time()
    
    try:
        if choice == "1" and os.path.isfile(target):
            results = [scanner.scan_file(target)]
        elif choice == "2" and os.path.isdir(target):
            results = scanner.scan_directory(target)
        else:
            print("Invalid choice or path")
            return
            
        # Generate reports (both HTML and XML)
        scanner.generate_report(results, report_prefix)
        
        # Print summary
        total_time = time.time() - start_time
        print(f"\nScan completed in {total_time:.2f} seconds")
        print(f"Total files scanned: {len(results)}")
        print(f"Threats found: {sum(1 for r in results if r.is_suspicious)}")
        print(f"Reports have been generated:")
        print(f"- HTML Report: {report_prefix}.html")
        print(f"- XML Report: {report_prefix}.xml")
        
        # Print risk level summary with colored text
        risk_levels = {
            "critical": sum(1 for r in results if r.risk_level == "critical"),
            "high": sum(1 for r in results if r.risk_level == "high"),
            "medium": sum(1 for r in results if r.risk_level == "medium"),
            "low": sum(1 for r in results if r.risk_level == "low")
        }
        
        print("\nRisk Level Summary:")
        for level, count in risk_levels.items():
            if count > 0:
                color = {
                    "critical": "red",
                    "high": "magenta",
                    "medium": "yellow",
                    "low": "blue"
                }[level]
                print(colored(f"- {level.upper()}: {count} file(s)", color, attrs=["bold"]))
        
    except Exception as e:
        print(f"Error during scan: {e}")
        logging.error(f"Scan error: {str(e)}", exc_info=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"Fatal error: {e}")
        logging.error("Fatal error", exc_info=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"Fatal error: {e}")
        logging.error("Fatal error", exc_info=True)