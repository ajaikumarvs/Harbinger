import os
import time
import math
import queue
import mmap
import magic
import yara
import pefile
import tlsh  # Replace ssdeep with tlsh
import hashlib
import logging
import zipfile
import tempfile
import platform
import threading
import re
from typing import Any, Dict, List, Optional, Generator
from pathlib import Path
from dataclasses import dataclass
from collections import defaultdict
from datetime import datetime
from termcolor import colored
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler
import xml.etree.ElementTree as ET

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
    tlsh_hash: str  # Changed from ssdeep_hash to tlsh_hash
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
            logging.exception(f"Error updating threat intelligence: {e}")

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
        self.context_whitelist = self._load_context_whitelist()

    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile advanced regex patterns for different threat categories with context."""
        patterns = {
            'shellcode': [
                # Actual shellcode patterns with opcodes
                r'\x55\x8B\xEC[\x00-\xFF]{10,}',  # x86 prologue followed by at least 10 bytes
                r'\x48\x89\x5C[\x00-\xFF]{10,}',  # x64 prologue followed by at least 10 bytes
                # Common shellcode patterns
                r'(?i)\\x(?:[0-9a-f]{2}){8,}',  # Long hex sequences
            ],
            'encryption': [
                # Suspicious encryption patterns
                r'(?i)(aes|rc4|blowfish|des)_(en|de)crypt.*\(.*password',
                r'(?i)(rsa|ecc)_(en|de)crypt.*private_key',
                r'(?i)XOR\s*\([^)]*\)\s*{\s*[^}]*\}',  # XOR operations on data
                # Ransomware-like patterns
                r'(?i)encrypt.*\.(jpg|doc|pdf|txt)',
            ],
            'network': [
                # Suspicious network patterns
                r'(?i)(socket|connect)\s*\(\s*["\']\s*(?:\d{1,3}\.){3}\d{1,3}["\']\s*,\s*[0-9]+\s*\)',
                r'(?i)(bind|listen)\s*\(\s*[0-9]+\s*\)',
                r'(?i)download.*execute',
                r'(?i)(http[s]?|ftp).*\.(exe|dll|ps1|bat|sh|cmd)',
            ],
            'process_injection': [
                # Process manipulation
                r'(?i)virtualalloc.*execute',
                r'(?i)writeprocessmemory.*\([^)]*\)',
                r'(?i)(createremotethread|virtualallocex).*\([^)]*process',
                r'(?i)(ntmapviewofsection|ntunmapviewofsection).*\([^)]*\)',
            ],
            'persistence': [
                # Registry/startup manipulation
                r'(?i)(HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)',
                r'(?i)(HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce)',
                r'(?i)sc.*create.*auto',
                r'(?i)schtasks.*create.*/sc',
            ],
            'evasion': [
                # Anti-debug and evasion techniques
                r'(?i)isdebuggerpresent.*!=.*0',
                r'(?i)checkremovedebugger.*true',
                r'(?i)(sleep|delay)\s*\(\s*[1-9][0-9]{3,}\s*\)',  # Long delays
                r'(?i)virtualbox|vmware|qemu|xen',  # VM detection
            ]
        }
        
        return {
            category: [re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL) 
                      for pattern in category_patterns]
            for category, category_patterns in patterns.items()
        }
    
    def _load_context_whitelist(self) -> Dict[str, List[str]]:
        """Load whitelisted contexts to reduce false positives."""
        return {
            'network': [
                r'(?i)test',
                r'(?i)example',
                r'(?i)demo',
                r'(?i)sample',
                r'(?i)documentation',
                r'(?i)import\s+',
                r'(?i)class\s+\w+\s*[({]',  # Class definitions
            ],
            'encryption': [
                r'(?i)test',
                r'(?i)example',
                r'(?i)unittest',
                r'(?i)crypto_example',
            ],
            'persistence': [
                r'(?i)test',
                r'(?i)sample',
                r'(?i)configuration',
                r'(?i)settings',
            ]
        }
    
    def check_for_malicious_context(self, content: str, match: re.Match, category: str) -> bool:
        """Check if the pattern match is in a malicious context."""
        # Get surrounding context (100 chars before and after)
        start = max(0, match.start() - 100)
        end = min(len(content), match.end() + 100)
        context = content[start:end]

        # Check against whitelist patterns
        whitelist_patterns = self.context_whitelist.get(category, [])
        for whitelist_pattern in whitelist_patterns:
            if re.search(whitelist_pattern, context):
                return False

        # Additional context checks
        if category == 'network':
            # Check if it's in import statements or legitimate network code
            if re.search(r'(?i)(import|require|include|using)\s+.*' + re.escape(match.group(0)), context):
                return False
            
        elif category == 'encryption':
            # Check if it's in legitimate crypto implementation
            if re.search(r'(?i)(test|cipher|crypto|security)\s+class', context):
                return False

        elif category == 'persistence':
            # Check if it's in configuration or setup code
            if re.search(r'(?i)(config|setup|install|deployment)', context):
                return False

        # If no whitelist matches and no legitimate context found, consider it suspicious
        return True
    
    def analyze_patterns(self, filepath: str, content: bytes) -> List[Dict[str, Any]]:
        """Analyze content for suspicious patterns with improved context awareness."""
        findings = []
        try:
            # Convert bytes to string for pattern matching
            text_content = content.decode('utf-8', errors='ignore')
            
            for category, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    matches = pattern.finditer(text_content)
                    for match in matches:
                        if self.check_for_malicious_context(text_content, match, category):
                            findings.append({
                                "type": "heuristic_detection",
                                "category": category,
                                "details": f"Suspicious pattern in {category} context: {match.group(0)[:50]}..."
                            })
        except Exception as e:
            findings.append({
                "type": "heuristic_error",
                "details": f"Error in pattern analysis: {str(e)}"
            })
            
        return findings
    
    def check_file_anomalies(self, filepath: str, content: bytes) -> List[Dict[str, Any]]:
        """Check for file-level anomalies."""
        anomalies = []
        
        # Check file entropy
        entropy = self.calculate_entropy(content)
        if entropy > self.entropy_threshold:
            # Additional checks for high entropy
            if not self._is_legitimate_high_entropy(filepath, content):
                anomalies.append({
                    "type": "high_entropy",
                    "details": f"Suspicious high entropy content: {entropy:.2f}"
                })

        return anomalies
    
    def _is_legitimate_high_entropy(self, filepath: str, content: bytes) -> bool:
        """Check if high entropy is legitimate (e.g., compressed files, images)."""
        # Check file extension
        legitimate_extensions = {'.zip', '.gz', '.jpg', '.png', '.pdf'}
        if any(filepath.lower().endswith(ext) for ext in legitimate_extensions):
            return True

        # Check for known file headers
        headers = {
            b'PK\x03\x04': 'zip',  # ZIP
            b'\xFF\xD8\xFF': 'jpeg',  # JPEG
            b'\x89PNG': 'png',  # PNG
            b'%PDF': 'pdf'  # PDF
        }
        
        for header, _ in headers.items():
            if content.startswith(header):
                return True

        return False

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
        import re
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
                logging.exception(f"Error in behavior monitoring: {e}")

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
        self.min_file_size = 50  # TLSH requires minimum 50 bytes for hashing
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
                
                filepath, pbar = task

                try:
                    result = self.scan_file(filepath)
                    if result is not None:
                        self.results_queue.put(result)
                except Exception as e:
                    self.logger.exception(f"Error scanning file {filepath}")
                    # Create a minimal scan result for failed scans with corrected parameters
                    result = ScanResult(
                        metadata=FileMetadata(
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
                            tlsh_hash="",  # Fixed: Changed from ssdeep_hash
                            entropy=0.0,
                            magic_signature="unknown"
                        ),
                        threats_found=[{"type": "scan_error", "details": str(e)}],
                        scan_time=0.0,
                        is_suspicious=True,
                        risk_level="unknown",
                        detection_methods=[],
                        scan_errors=[str(e)]
                    )
                    self.results_queue.put(result)
                
                # Always update the progressbar, even if the scan fails
                pbar.update(1)
                pbar.set_postfix(file=os.path.basename(filepath))
                self.scan_queue.task_done()

            except Exception as e:
                self.logger.exception("Worker error")
                self.scan_queue.task_done()

            except Exception as e:
                self.logger.exception(f"Worker error")
                self.scan_queue.task_done()

    def _load_yara_rules(self) -> Optional[yara.Rules]:
        """Load YARA rules from signature directory."""
        try:
            if not os.path.exists(self.signature_dir):
                self.logger.warning(f"Signature directory not found: {self.signature_dir}")
                return None

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
            self.logger.exception(f"Error loading YARA rules: {str(e)}")
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
                
                # Replace ssdeep hash with TLSH hash
                tlsh_hash = ""
                if len(data) >= self.min_file_size:
                    try:
                        tlsh_hash = tlsh.hash(data)
                    except Exception as e:
                        self.logger.warning(f"TLSH hash generation failed for {filepath}: {str(e)}")
                
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
                tlsh_hash=tlsh_hash,  # Use TLSH hash instead of ssdeep
                entropy=entropy,
                magic_signature=magic.Magic().from_file(filepath)
            )
        except Exception as e:
            self.logger.exception(f"Error analyzing file metadata for {filepath}")
            raise

    def calculate_hash_similarity(self, hash1: str, hash2: str) -> int:
        """Calculate similarity between two TLSH hashes."""
        try:
            if not hash1 or not hash2:
                return -1  # Invalid hash(es)
            return tlsh.diff(hash1, hash2)  # Returns a distance score (lower is more similar)
        except Exception as e:
            self.logger.warning(f"Error calculating TLSH similarity: {str(e)}")
            return -1

    def scan_file(self, filepath: str) -> Optional[ScanResult]:
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

            # Add TLSH similarity checking for known malware
            if metadata.tlsh_hash:
                for known_hash in self.threat_intelligence.known_malware_hashes:
                    if known_hash.startswith('T'):  # Check if it's a TLSH hash
                        similarity = self.calculate_hash_similarity(metadata.tlsh_hash, known_hash)
                        if similarity != -1 and similarity < 100:  # Threshold for similarity
                            threats.append({
                                "type": "similar_to_known_malware",
                                "details": f"File similar to known malware (TLSH distance: {similarity})"
                            })
                            detection_methods.append("fuzzy_hash_detection")
                            break

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
                risk_level=self._calculate_risk_level(threats),
                detection_methods=detection_methods,
                scan_errors=scan_errors
            )

        except Exception as e:
            self.logger.exception(f"Error scanning {filepath}")
            return None

    def _calculate_risk_level(self, threats: List[Dict[str, Any]]) -> str:
        """Calculate risk level based on threats found."""
        if not threats:
            return "clean"
            
        # Define threat severity scores
        severity_scores = {
            "known_malware": 10,
            "yara_match": 8,
            "heuristic_detection": 6,
            "suspicious_import": 4,
            "high_entropy_section": 3,
            "suspicious_section": 2,
            "suspicious_resource": 2
        }
        
        # Calculate total severity score
        total_score = sum(severity_scores.get(threat["type"], 0) for threat in threats)
        
        # Determine risk level based on total score
        if total_score >= 15:
            return "critical"
        elif total_score >= 10:
            return "high"
        elif total_score >= 6:
            return "medium"
        else:
            return "low"

    def scan_archive(self, filepath: str) -> List[Dict[str, Any]]:
        """Enhanced archive scanning with support for multiple formats and better error handling."""
        threats = []
    
        try:
            # Handle ZIP files
            if zipfile.is_zipfile(filepath):
                try:
                    with zipfile.ZipFile(filepath, 'r') as archive:
                        try:
                            # Test if archive is encrypted
                            archive.testzip()
                        except RuntimeError as e:
                            if "encrypted" in str(e).lower() or "password required" in str(e).lower():
                                threats.append({
                                    "type": "archive_scan_error",
                                    "category": "encryption",
                                    "details": "Password-protected archive detected. Unable to scan contents."
                                })
                                return threats
                        
                        for file_info in archive.infolist():
                            # Skip directories
                            if file_info.filename.endswith('/'):
                                continue
                            
                            # Check file size
                            if file_info.file_size > self.max_file_size:
                                threats.append({
                                    "type": "suspicious_archive",
                                    "category": "size",
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
                                    if result and result.threats_found:
                                        threats.extend([{
                                            "type": "archive_threat",
                                            "category": "malware",
                                            "filename": file_info.filename,
                                            "details": threat
                                        } for threat in result.threats_found])
                                    
                            except zipfile.BadZipFile as e:
                                threats.append({
                                    "type": "archive_scan_error",
                                    "category": "corruption",
                                    "details": f"Corrupted file in archive: {file_info.filename}"
                                })
                            except Exception as e:
                                threats.append({
                                    "type": "archive_scan_error",
                                    "category": "error",
                                    "details": f"Error scanning {file_info.filename}: {str(e)}"
                                })
                            finally:
                                if os.path.exists(temp_file.name):
                                    os.unlink(temp_file.name)

                except zipfile.BadZipFile:
                    threats.append({
                        "type": "archive_scan_error",
                        "category": "corruption",
                        "details": "Corrupted or invalid ZIP archive"
                    })
                except Exception as e:
                    threats.append({
                        "type": "archive_scan_error",
                        "category": "error",
                        "details": f"Error processing archive: {str(e)}"
                })

        except Exception as e:
            threats.append({
                "type": "archive_error",
                "category": "error",
                "details": f"Error accessing archive: {str(e)}"
            })

        return threats
    
    def scan_directory(self, directory: str, num_workers: int = 4) -> List[ScanResult]:
        """Scan a directory with improved progress tracking."""
        results = []
        total_files = sum(1 for _ in self._walk_files(directory))
    
        if total_files == 0:
            self.logger.warning(f"No files found in directory: {directory}")
            return results

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = []
            
            # Initialize progress bars
            overall_pbar = tqdm(
                total=total_files,
                desc="Overall Progress",
                unit="files",
                position=0,
                leave=True,
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
            )
            
            stats_pbar = tqdm(
                total=0,
                desc="Scan Statistics",
                position=1,
                bar_format="{desc}",
                leave=True
            )
            
            current_file_pbar = tqdm(
                total=1,
                desc="Current File",
                position=2,
                leave=False,
                bar_format="{desc}"
            )

            # Initialize statistics
            stats = {
                "clean": 0,
                "low": 0,
                "medium": 0,
                "high": 0,
                "critical": 0,
                "errors": 0
            }

            def update_progress(future):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        # Update statistics
                        if result.is_suspicious:
                            stats[result.risk_level] += 1
                        else:
                            stats["clean"] += 1
                        
                        # Update statistics display
                        stats_str = (
                            f"Statistics: Clean: {stats['clean']} | "
                            f"Low: {stats['low']} | "
                            f"Medium: {stats['medium']} | "
                            f"High: {stats['high']} | "
                            f"Critical: {stats['critical']} | "
                            f"Errors: {stats['errors']}"
                        )
                        stats_pbar.set_description_str(stats_str)
                    else:
                        stats["errors"] += 1
                except Exception as e:
                    self.logger.exception("Error processing scan result")
                    stats["errors"] += 1
                finally:
                    overall_pbar.update(1)

            try:
                # Submit all files for scanning
                for filepath in self._walk_files(directory):
                    current_file_pbar.set_description_str(f"Scanning: {os.path.basename(filepath)}")
                    future = executor.submit(self.scan_file, filepath)
                    future.add_done_callback(update_progress)
                    futures.append(future)

                # Wait for all scans to complete
                for future in futures:
                    future.result()

            finally:
                overall_pbar.close()
                stats_pbar.close()
                current_file_pbar.close()

            return results
        
    def display_scan_results(self, results: List[ScanResult]) -> None:
        """Display scan results in a well-formatted manner."""
        if not results:
            print(colored("\nNo scan results to display.", "yellow"))
            return

        # Calculate summary statistics
        total_files = len(results)
        stats = defaultdict(int)
        for result in results:
            stats[result.risk_level] += 1

        # Display summary
        print("\n" + "="*60)
        print(colored("SCAN SUMMARY", "cyan", attrs=["bold"]))
        print("="*60)
        print(f"Total files scanned: {total_files}")
        print(f"Clean files: {stats['clean']}")
        print(f"Suspicious files: {sum(stats[level] for level in ['low', 'medium', 'high', 'critical'])}")
        print("\nRisk Level Distribution:")
    
        # Define colors for risk levels
        risk_colors = {
            "critical": "red",
            "high": "magenta",
            "medium": "yellow",
            "low": "green",
            "clean": "blue"
        }

        # Display risk level distribution
        for level in ["critical", "high", "medium", "low"]:
            if stats[level] > 0:
                print(colored(
                    f"{level.upper():>8}: {stats[level]} files",
                    risk_colors[level],
                    attrs=["bold"]
            ))

        # Display detailed results for suspicious files
        suspicious_results = [r for r in results if r.is_suspicious]
        if suspicious_results:
            print("\n" + "="*60)
            print(colored("DETAILED FINDINGS", "cyan", attrs=["bold"]))
            print("="*60)
        
        for result in suspicious_results:
            color = risk_colors.get(result.risk_level, "white")
            
            # File header
            print(colored(
                f"\nFile: {os.path.basename(result.metadata.filepath)}",
                color,
                attrs=["bold"]
            ))
            
            # Basic info
            print(colored(f"Risk Level: {result.risk_level.upper()}", color))
            print(f"Type: {result.metadata.file_type}")
            
            # Group threats by category
            threats_by_category = defaultdict(list)
            for threat in result.threats_found:
                category = threat.get('category', 'unknown')
                if threat['type'] == "archive_scan_error":
                    # Handle archive scan errors specially
                    details = threat.get('details', '')
                    threats_by_category[category].append(f"{threat['type']}: {details}")
                elif threat['type'] == "heuristic_detection":
                    # Handle heuristic detections
                    details = threat.get('details', '')
                    if isinstance(details, str):
                        pattern = details.split(': ')[1] if ': ' in details else details
                        pattern = pattern[:30] + '...' if len(pattern) > 30 else pattern
                        threats_by_category[category].append(f"{threat['type']}: {pattern}")
                else:
                    # Handle other types of threats
                    threats_by_category[category].append(threat['type'])
            
            # Display threats by category
            if threats_by_category:
                print("\nThreats Found:")
                for category, threat_list in threats_by_category.items():
                    print(colored(f"  {category.title()}:", color))
                    for threat in threat_list:
                        print(f"    - {threat}")

            # Display detection methods compactly
            if result.detection_methods:
                print("\nDetection Methods:", ", ".join(result.detection_methods))

    print("\n" + "="*60)
            
    def _walk_files(self, directory: str) -> Generator[str, None, None]:
        try:
            for file_path in Path(directory).rglob("*"):
                if file_path.is_file():
                    yield str(file_path)
        except Exception as e:
            self.logger.exception(f"Error walking directory {directory}")    

    def generate_report(self, results: List[ScanResult], output_prefix: str = "scan_report"):
        """Generate detailed HTML and XML reports with charts and statistics."""
        try:
            # Filter out None results
            valid_results = [r for r in results if r is not None]

            if not valid_results:
                self.logger.warning("No valid results to generate report from")
                return
            
            html_path = f"{output_prefix}.html"
            xml_path = f"{output_prefix}.xml"
            
            # Calculate statistics from valid results only
            total_files = len(valid_results)
            clean_files = sum(1 for r in valid_results if not r.is_suspicious)
            suspicious_files = total_files - clean_files
            risk_levels = {
                "critical": sum(1 for r in valid_results if r.risk_level == "critical"),
                "high": sum(1 for r in valid_results if r.risk_level == "high"),
                "medium": sum(1 for r in valid_results if r.risk_level == "medium"),
                "low": sum(1 for r in valid_results if r.risk_level == "low")
            }
            
            # Generate HTML Report
            with open(html_path, 'w') as f:
                f.write("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Antivirus Scan Report</title>
                    <style>
                        ... 
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
                for result in valid_results:
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
            for result in valid_results:
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
            self.logger.exception(f"Error generating reports")

def main():
    """Main function to run the advanced antivirus scanner."""
    scanner = AdvancedVirusScanner()
    
    while True:
        print("\n" + "="*20 + " Binary Hunter " + "="*20)
        print(colored("1. Scan file", "cyan"))
        print(colored("2. Scan directory", "cyan"))
        print(colored("3. Exit", "red"))
        choice = input("\nEnter choice (1-3): ")
        
        if choice == "3":
            print(colored("\nExiting...", "yellow"))
            break
        
        target = input("Enter path to scan: ")
        if not os.path.exists(target):
            print(colored("Error: Path does not exist", "red"))
            continue
            
        report_prefix = "scan_report"
        start_time = time.time()
        
        try:
            if choice == "1" and os.path.isfile(target):
                print(colored("\nInitiating file scan...", "cyan"))
                result = scanner.scan_file(target)
                results = [result] if result is not None else []
            elif choice == "2" and os.path.isdir(target):
                print(colored("\nInitiating directory scan...", "cyan"))
                results = scanner.scan_directory(target)
            else:
                print(colored("Invalid choice or path", "red"))
                continue
            
            # Display results and generate reports
            total_time = time.time() - start_time
            print(colored(f"\nScan completed in {total_time:.2f} seconds", "green"))
            
            scanner.display_scan_results(results)  # Fixed: Call the method on the scanner instance
            
            if results:
                scanner.generate_report(results, report_prefix)
                print(colored(f"\nDetailed reports generated: {report_prefix}.html and {report_prefix}.xml", "green"))
            
        except KeyboardInterrupt:
            print(colored("\nScan interrupted by user.", "yellow"))
            scanner.stop_workers()
        except Exception as e:
            print(colored(f"Error during scan: {e}", "red"))
            scanner.logger.exception("Scan error")

if __name__ == "__main__":
    try:
        # Initialize scanner with default signatures directory
        scanner = AdvancedVirusScanner(signature_dir="signatures")
        
        # Start the behavior monitor
        scanner.behavior_monitor.start_monitoring()
        
        # Run the main scanning interface
        main()
        
    except KeyboardInterrupt:
        print(colored("\nProgram interrupted by user. Cleaning up...", "yellow"))
    except Exception as e:
        print(colored(f"Fatal error: {str(e)}", "red"))
        logging.exception("Fatal error occurred")
    finally:
        # Cleanup
        if 'scanner' in locals():
            scanner.behavior_monitor.stop_monitoring()
            scanner.stop_workers()