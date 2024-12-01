import os
import sys
import hashlib
import pefile
import magic
import ssdeep
import yara
import logging
from datetime import datetime
import virus_total_apis
import requests
from typing import Dict, List, Optional

class MalwareScanner:
    def __init__(self, yara_rules_path: str = 'malware_rules'):
        """
        Initialize the malware scanner with configuration and setup.
        
        :param yara_rules_path: Path to directory containing YARA rule files
        """
        # Logging configuration
        logging.basicConfig(
            level=logging.INFO, 
            format='%(asctime)s - %(levelname)s: %(message)s',
            filename='malware_scan.log'
        )
        self.logger = logging.getLogger(__name__)

        # VirusTotal API (replace with your actual API key)
        self.virustotal_api_key = 'YOUR_VIRUSTOTAL_API_KEY'
        self.virustotal_client = virus_total_apis.PublicApi(self.virustotal_api_key)

        # YARA rules loading
        try:
            self.yara_rules = yara.compile(yara_rules_path)
        except Exception as e:
            self.logger.error(f"Failed to load YARA rules: {e}")
            self.yara_rules = None

    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """
        Calculate multiple hash types for the file.
        
        :param file_path: Path to the executable file
        :return: Dictionary of hash values
        """
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'ssdeep': ssdeep.hash_file(file_path)
        }
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hashes['md5'].update(chunk)
                hashes['sha1'].update(chunk)
                hashes['sha256'].update(chunk)
        
        return {
            'md5': hashes['md5'].hexdigest(),
            'sha1': hashes['sha1'].hexdigest(),
            'sha256': hashes['sha256'].hexdigest(),
            'ssdeep': hashes['ssdeep']
        }

    def analyze_pe_headers(self, file_path: str) -> Dict:
        """
        Analyze PE (Portable Executable) file headers.
        
        :param file_path: Path to the executable file
        :return: Dictionary of PE header information
        """
        try:
            pe = pefile.PE(file_path)
            return {
                'sections': [section.Name.decode('utf-8').rstrip('\x00') for section in pe.sections],
                'imports': [entry.dll.decode('utf-8') for entry in pe.DIRECTORY_ENTRY_IMPORT] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else [],
                'exports': [entry.name.decode('utf-8') for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols] if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else [],
                'machine_type': hex(pe.FILE_HEADER.Machine),
                'timestamp': datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
            }
        except Exception as e:
            self.logger.error(f"PE Header analysis failed: {e}")
            return {}

    def check_virustotal(self, file_hash: str) -> Dict:
        """
        Check file against VirusTotal database.
        
        :param file_hash: SHA256 hash of the file
        :return: VirusTotal scan results
        """
        try:
            response = self.virustotal_client.get_file_report(file_hash)
            return {
                'positives': response.get('positives', 0),
                'total': response.get('total', 0),
                'scan_date': response.get('scan_date')
            }
        except Exception as e:
            self.logger.warning(f"VirusTotal lookup failed: {e}")
            return {}

    def yara_scan(self, file_path: str) -> List[str]:
        """
        Perform YARA rule matching.
        
        :param file_path: Path to the executable file
        :return: List of matched YARA rules
        """
        if not self.yara_rules:
            return []
        
        try:
            matches = self.yara_rules.match(file_path)
            return [match.rule for match in matches]
        except Exception as e:
            self.logger.error(f"YARA scan failed: {e}")
            return []

    def file_magic_detection(self, file_path: str) -> str:
        """
        Detect file type using libmagic.
        
        :param file_path: Path to the file
        :return: Detected file type
        """
        try:
            return magic.from_file(file_path)
        except Exception as e:
            self.logger.error(f"Magic detection failed: {e}")
            return "Unknown"

    def is_executable(self, file_path: str) -> bool:
        """
        Check if the file is an executable.
        
        :param file_path: Path to the file
        :return: Boolean indicating if file is executable
        """
        try:
            file_type = self.file_magic_detection(file_path)
            return 'executable' in file_type.lower()
        except Exception:
            return False

    def scan_file(self, file_path: str) -> Dict:
        """
        Comprehensive file scanning method.
        
        :param file_path: Path to the executable file
        :return: Detailed scan report
        """
        # Validate file exists and is executable
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Comprehensive scan
        scan_report = {
            'file_path': file_path,
            'file_type': self.file_magic_detection(file_path),
            'file_size': os.path.getsize(file_path),
            'hashes': self.calculate_hashes(file_path),
            'pe_analysis': self.analyze_pe_headers(file_path),
            'virustotal_results': self.check_virustotal(self.calculate_hashes(file_path)['sha256']),
            'yara_matches': self.yara_scan(file_path)
        }

        # Risk assessment
        scan_report['risk_level'] = self.assess_risk(scan_report)
        
        return scan_report

    def assess_risk(self, scan_report: Dict) -> str:
        """
        Assess overall risk level based on scan results.
        
        :param scan_report: Comprehensive scan report
        :return: Risk level (Low/Medium/High/Critical)
        """
        risk_score = 0

        # VirusTotal detection score
        vt_results = scan_report.get('virustotal_results', {})
        if vt_results:
            positives = vt_results.get('positives', 0)
            total = vt_results.get('total', 1)
            detection_rate = positives / total
            
            if detection_rate > 0.6:
                risk_score += 3
            elif detection_rate > 0.3:
                risk_score += 2

        # YARA rule matches
        if scan_report.get('yara_matches'):
            risk_score += 2

        # Suspicious PE header characteristics
        pe_analysis = scan_report.get('pe_analysis', {})
        suspicious_sections = ['UPX', '.rsrc', '.text']
        if any(section in str(pe_analysis.get('sections', [])) for section in suspicious_sections):
            risk_score += 1

        # Determine risk level
        if risk_score >= 4:
            return 'Critical'
        elif risk_score >= 3:
            return 'High'
        elif risk_score >= 2:
            return 'Medium'
        else:
            return 'Low'

    def generate_report(self, scan_report: Dict):
        """
        Generate a detailed human-readable report.
        
        :param scan_report: Comprehensive scan report
        """
        print("\n===== MALWARE SCAN REPORT =====")
        print(f"File: {scan_report['file_path']}")
        print(f"File Type: {scan_report['file_type']}")
        print(f"File Size: {scan_report['file_size']} bytes")
        print(f"Risk Level: {scan_report['risk_level']}\n")

        print("Hashes:")
        for hash_type, value in scan_report['hashes'].items():
            print(f"  {hash_type.upper()}: {value}")

        print("\nVirusTotal Detection:")
        vt_results = scan_report.get('virustotal_results', {})
        print(f"  Positives: {vt_results.get('positives', 0)}")
        print(f"  Total Scans: {vt_results.get('total', 0)}")

        print("\nYARA Matches:")
        for rule in scan_report.get('yara_matches', []):
            print(f"  - {rule}")

        print("\nPE Header Analysis:")
        pe_analysis = scan_report.get('pe_analysis', {})
        for key, value in pe_analysis.items():
            print(f"  {key.replace('_', ' ').title()}: {value}")

class MalwareScannerApp:
    def __init__(self):
        """
        Initialize the Malware Scanner Application.
        """
        self.scanner = MalwareScanner()
        self.scan_results = []

    def validate_directory(self, directory_path: str) -> bool:
        """
        Validate if the given path is a valid directory.
        
        :param directory_path: Path to scan
        :return: Boolean indicating directory validity
        """
        return os.path.isdir(directory_path) and os.path.exists(directory_path)

    def scan_directory(self, directory_path: str):
        """
        Scan all executable files in the given directory.
        
        :param directory_path: Path to scan
        """
        print(f"\nScanning directory: {directory_path}")
        self.scan_results = []

        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Check if file is executable
                if self.scanner.is_executable(file_path):
                    try:
                        scan_report = self.scanner.scan_file(file_path)
                        self.scan_results.append(scan_report)
                        
                        # Print quick status
                        print(f"Scanned: {file_path} - Risk: {scan_report['risk_level']}")
                    except Exception as e:
                        print(f"Error scanning {file_path}: {e}")

        self.generate_summary()

    def generate_summary(self):
        """
        Generate a summary of scan results.
        """
        print("\n===== SCAN SUMMARY =====")
        print(f"Total files scanned: {len(self.scan_results)}")
        
        risk_levels = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for result in self.scan_results:
            risk_levels[result['risk_level']] += 1
        
        print("Risk Level Breakdown:")
        for level, count in risk_levels.items():
            print(f"  {level}: {count}")
        
        # Option to generate detailed report
        detailed_report = input("\nGenerate detailed report for suspicious files? (y/n): ").lower()
        if detailed_report == 'y':
            self.generate_detailed_report()

    def generate_detailed_report(self):
        """
        Generate detailed report for high-risk files.
        """
        high_risk_files = [r for r in self.scan_results if r['risk_level'] in ['High', 'Critical']]
        
        if not high_risk_files:
            print("No high-risk files found.")
            return
        
        print("\n===== DETAILED HIGH-RISK FILES REPORT =====")
        for report in high_risk_files:
            self.scanner.generate_report(report)

def main():
    print("=== Advanced Malware Directory Scanner ===")
    
    while True:
        directory_path = input("\nEnter the full path of the directory to scan: ").strip()
        
        app = MalwareScannerApp()
        
        if app.validate_directory(directory_path):
            app.scan_directory(directory_path)
            
            # Ask if user wants to scan another directory
            another_scan = input("\nScan another directory? (y/n): ").lower()
            if another_scan != 'y':
                break
        else:
            print("Invalid directory path. Please try again.")

if __name__ == "__main__":
    main()