import os
import sys
import psutil
import torch
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Optional, Union, Tuple, Any
import re
import requests
from bs4 import BeautifulSoup
from contextlib import contextmanager
import gc
from transformers import AutoModelForCausalLM, AutoTokenizer
from llama_cpp import Llama
from termcolor import colored
import textwrap
from datetime import datetime
import html
from pathlib import Path
from typing import Tuple
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class RemediationAdvice:
    general_guidance: str
    specific_steps: List[str]
    priority: str
    difficulty: str
    resources: List[str]

@dataclass
class VulnerabilityCheck:
    name: str
    description: str
    severity: str
    subchecks: List[str]
    impact: str
    patterns: List[str]

@dataclass
class VulnerabilityLocation:
    element: str
    location: str
    detail: str

@dataclass
class VulnerabilityResult:
    name: str
    severity: str
    locations: List[VulnerabilityLocation]
    description: str
    impact: str
    remediation: Optional[RemediationAdvice] = None
    risk_score: float = 0.0

def shorten_url(url: str) -> str:
    """
    Simplifies the URL to just its domain.
    Example: https://www.example.com/long/path -> example.com
    """
    parsed_url = urlparse(url)
    return parsed_url.netloc.replace("www.", "")  # Keep only the domain and remove 'www.'

class SeverityLevel:
    CRITICAL = {"label": "CRITICAL", "color": "red", "score": 10.0}
    HIGH = {"label": "HIGH", "color": "red", "score": 8.0}
    MEDIUM = {"label": "MEDIUM", "color": "yellow", "score": 5.0}
    LOW = {"label": "LOW", "color": "green", "score": 2.0}
    INFO = {"label": "INFO", "color": "blue", "score": 0.5}

    @staticmethod
    def get_level(severity: str) -> dict:
        severity = severity.upper()
        levels = {
            'CRITICAL': SeverityLevel.CRITICAL,
            'HIGH': SeverityLevel.HIGH,
            'MEDIUM': SeverityLevel.MEDIUM,
            'LOW': SeverityLevel.LOW,
            'INFO': SeverityLevel.INFO
        }
        return levels.get(severity, SeverityLevel.INFO)

class ResourceManager:
    @staticmethod
    def clear_memory() -> None:
        """Force garbage collection and clear CUDA cache if available."""
        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

    @staticmethod
    def get_system_resources() -> Tuple[int, int]:
        """Get available system resources."""
        cpu_cores = max(1, (os.cpu_count() or 1) // 2)
        mem = psutil.virtual_memory()
        available_memory = mem.available // (1024 * 1024)  # Convert to MB
        return cpu_cores, available_memory

    @staticmethod
    @contextmanager
    def suppress_output():
        """Context manager to suppress stdout and stderr."""
        with open(os.devnull, 'w') as devnull:
            old_stdout, old_stderr = sys.stdout, sys.stderr
            sys.stdout, sys.stderr = devnull, devnull
            try:
                yield
            finally:
                sys.stdout, sys.stderr = old_stdout, old_stderr

class AIModelHandler:
    def __init__(self, model: Any):
        self.model = model

    def generate_response(self, prompt: str) -> str:
        """Generate a response using the AI model."""
        try:
            if isinstance(self.model, tuple):  # Transformer model
                model, tokenizer = self.model
                inputs = tokenizer(prompt, return_tensors="pt", max_length=512, truncation=True)
                outputs = model.generate(**inputs, max_length=200)
                return tokenizer.decode(outputs[0], skip_special_tokens=True)
            elif isinstance(self.model, Llama):  # Llama model
                response = self.model(prompt, max_tokens=200, stop=["</response>"])
                return response["choices"][0]["text"].strip()
            else:
                return "AI model not available"
        except Exception as e:
            logger.error(f"Error generating AI response: {str(e)}")
            return "Error generating response"

class ReportGenerator:
    def __init__(self, ai_model: Optional[Any] = None):
        self.ai_model = AIModelHandler(ai_model) if ai_model else None
        self.timestamp = datetime.now()

    def _generate_html_header(self) -> str:
        """Generate HTML header with styles."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnX-ai Security Scan Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            padding: 20px;
            background: #1a237e;
            color: white;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .summary {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .finding {
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .severity-critical { color: #d32f2f; }
        .severity-high { color: #f44336; }
        .severity-medium { color: #fb8c00; }
        .severity-low { color: #4caf50; }
        .severity-info { color: #2196f3; }
        .location {
            background: #f8f9fa;
            padding: 10px;
            margin: 5px 0;
            border-left: 4px solid #1a237e;
        }
        .steps {
            padding-left: 20px;
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
        }
        .risk-score {
            font-size: 1.2em;
            font-weight: bold;
            padding: 10px;
            margin: 10px 0;
            text-align: center;
        }
    </style>
</head>
<body>
<div class="container">
"""

    def _generate_html_summary(self, results: List[VulnerabilityResult]) -> str:
        """Generate HTML summary section."""
        severity_counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        }
        
        total_vulnerabilities = 0
        for result in results:
            severity = result.severity.upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            total_vulnerabilities += len(result.locations)

        html_summary = '<div class="summary">\n'
        html_summary += '<h2>Summary of Findings</h2>\n'
        
        for severity, count in severity_counts.items():
            if count > 0:
                html_summary += f'<p class="severity-{severity.lower()}">'
                html_summary += f'● {severity}: {count} {"finding" if count == 1 else "findings"}</p>\n'
        
        html_summary += f'<p><strong>Total Vulnerabilities Found: {total_vulnerabilities}</strong></p>\n'
        html_summary += '</div>\n'
        return html_summary

    def generate_html_report(self, url: str, results: List[VulnerabilityResult]) -> str:
        """Generate a comprehensive HTML security report."""
        report = self._generate_html_header()
        
        # Header section
        report += f"""
        <div class="header">
            <h1>VulnX-ai Security Scan Report</h1>
            <p>Scan Time: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Target URL: {html.escape(url)}</p>
        </div>
        """
        
        # Summary section
        report += self._generate_html_summary(results)
        
        # Risk score
        risk_score = self._generate_risk_score(results)
        score_class = 'severity-low' if risk_score < 3 else 'severity-medium' if risk_score < 7 else 'severity-high'
        report += f'<div class="risk-score {score_class}">Overall Risk Score: {risk_score}/10.0</div>'
        
        # Detailed findings
        if results:
            report += '<h2>Detailed Findings</h2>'
            
            for i, result in enumerate(results, 1):
                report += f'<div class="finding">'
                report += f'<h3 class="severity-{result.severity.lower()}">[{i}] {html.escape(result.name)}</h3>'
                report += f'<p><strong>Severity:</strong> <span class="severity-{result.severity.lower()}">{result.severity}</span></p>'
                report += f'<p><strong>Impact:</strong> {html.escape(result.impact)}</p>'
                report += f'<p><strong>Description:</strong><br>{html.escape(result.description)}</p>'
                
                # Locations
                report += '<h4>Affected Locations:</h4>'
                for loc in result.locations:
                    report += '<div class="location">'
                    report += f'<p><strong>Element:</strong> {html.escape(loc.element)}</p>'
                    report += f'<p><strong>Location:</strong> {html.escape(loc.location)}</p>'
                    report += f'<p><strong>Detail:</strong> {html.escape(loc.detail)}</p>'
                    report += '</div>'
                
                # Remediation
                remediation = self._get_ai_remediation(result)
                report += '<h4>Remediation Guidance:</h4>'
                report += f'<p><strong>Priority:</strong> {html.escape(remediation.priority)}</p>'
                report += f'<p><strong>Difficulty:</strong> {html.escape(remediation.difficulty)}</p>'
                report += f'<p><strong>General Guidance:</strong><br>{html.escape(remediation.general_guidance)}</p>'
                
                report += '<p><strong>Specific Steps:</strong></p><ul class="steps">'
                for step in remediation.specific_steps:
                    report += f'<li>{html.escape(step)}</li>'
                report += '</ul>'
                
                report += '<p><strong>Additional Resources:</strong></p><ul>'
                for resource in remediation.resources:
                    report += f'<li>{html.escape(resource)}</li>'
                report += '</ul>'
                
                report += '</div>'
        else:
            report += '<p class="severity-low">No vulnerabilities were detected.</p>'
        
        # Footer
        report += """
        <div class="footer">
            <p>End of Report</p>
        </div>
        </div>
        </body>
        </html>
        """
        
        return report

    def _generate_header(self) -> str:
        """Generate a formatted header for the report."""
        return f"""
{colored('='*80, 'blue')}
{colored('VulnX-ai Security Scan Report', 'blue', attrs=['bold'])}
{colored('='*80, 'blue')}
Scan Time: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
"""

    def _generate_summary(self, results: List[VulnerabilityResult]) -> str:
        """Generate a summary of findings."""
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        total_vulnerabilities = 0
        for result in results:
            severity = result.severity.upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            total_vulnerabilities += len(result.locations)

        summary = f"\n{colored('SUMMARY OF FINDINGS', 'white', attrs=['bold'])}\n"
        summary += f"{colored('─'*40, 'white')}\n"
        
        for severity, count in severity_counts.items():
            if count > 0:
                level = SeverityLevel.get_level(severity)
                summary += f"{colored(f'● {severity.ljust(8)}', level['color'])} : {count} {'finding' if count == 1 else 'findings'}\n"
        
        summary += f"\nTotal Vulnerabilities Found: {colored(str(total_vulnerabilities), 'yellow', attrs=['bold'])}\n"
        return summary

    def _generate_risk_score(self, results: List[VulnerabilityResult]) -> float:
        """Calculate overall risk score based on vulnerabilities."""
        if not results:
            return 0.0
        
        total_score = 0.0
        for result in results:
            severity_level = SeverityLevel.get_level(result.severity)
            total_score += severity_level['score'] * len(result.locations)
        
        # Normalize score to 0-10 range
        normalized_score = min(10.0, total_score / max(len(results), 1))
        return round(normalized_score, 1)

    def _get_ai_remediation(self, vulnerability: VulnerabilityResult) -> RemediationAdvice:
        """Generate AI-driven remediation advice."""
        if not self.ai_model:
            return self._get_static_remediation(vulnerability.name)

        try:
            prompt = f"""
            Provide specific remediation advice for {vulnerability.name} vulnerability.
            Context: {vulnerability.description}
            Impact: {vulnerability.impact}
            Locations affected: {len(vulnerability.locations)}
            Format as:
            General Guidance: <guidance>
            Steps: <comma-separated steps>
            Priority: <priority>
            Difficulty: <difficulty>
            Resources: <comma-separated resources>
            """
            
            response = self.ai_model.generate_response(prompt)
            return self._parse_ai_response(response)
        except Exception as e:
            logger.error(f"Error generating AI remediation: {str(e)}")
            return self._get_static_remediation(vulnerability.name)

    def _parse_ai_response(self, response: str) -> RemediationAdvice:
        """Parse AI response into structured remediation advice."""
        try:
            lines = response.split('\n')
            guidance = ""
            steps = []
            priority = "Medium"
            difficulty = "Medium"
            resources = []

            for line in lines:
                if line.startswith("General Guidance:"):
                    guidance = line.split(":", 1)[1].strip()
                elif line.startswith("Steps:"):
                    steps = [s.strip() for s in line.split(":", 1)[1].split(",")]
                elif line.startswith("Priority:"):
                    priority = line.split(":", 1)[1].strip()
                elif line.startswith("Difficulty:"):
                    difficulty = line.split(":", 1)[1].strip()
                elif line.startswith("Resources:"):
                    resources = [r.strip() for r in line.split(":", 1)[1].split(",")]

            return RemediationAdvice(
                general_guidance=guidance,
                specific_steps=steps,
                priority=priority,
                difficulty=difficulty,
                resources=resources
            )
        except Exception as e:
            logger.error(f"Error parsing AI response: {str(e)}")
            return self._get_static_remediation("General")

    def _get_static_remediation(self, vuln_type: str) -> RemediationAdvice:
        """Provide static remediation advice when AI is not available."""
        # Static remediation database
        remediation_database = {
            "Cross-Site Scripting (XSS)": RemediationAdvice(
                general_guidance="Implement proper input validation and output encoding.",
                specific_steps=[
                    "Use HTML encoding for dynamic content",
                    "Implement Content Security Policy (CSP)",
                    "Sanitize user input using security libraries",
                    "Use framework-provided XSS protection features"
                ],
                priority="High",
                difficulty="Medium",
                resources=[
                    "OWASP XSS Prevention Cheat Sheet",
                    "OWASP CSP Cheat Sheet"
                ]
            ),
            "SQL Injection": RemediationAdvice(
                general_guidance="Use parameterized queries and input validation.",
                specific_steps=[
                    "Replace dynamic SQL with prepared statements",
                    "Implement proper input validation",
                    "Use ORM frameworks when possible",
                    "Apply principle of least privilege to database users"
                ],
                priority="Critical",
                difficulty="Medium",
                resources=[
                    "OWASP SQL Injection Prevention Cheat Sheet",
                    "Bobby Tables: A guide to preventing SQL injection"
                ]
            )
        }
        
        return remediation_database.get(vuln_type, RemediationAdvice(
            general_guidance="Implement security best practices and proper input validation.",
            specific_steps=["Validate all user inputs", "Apply security patches regularly"],
            priority="Medium",
            difficulty="Medium",
            resources=["OWASP Top 10", "SANS Security Guidelines"]
        ))

    def generate_report(self, url: str, results: List[VulnerabilityResult]) -> str:
        """Generate a comprehensive security report."""
        report = self._generate_header()
        
        # Add scan information
        report += f"\n{colored('SCAN INFORMATION', 'white', attrs=['bold'])}\n"
        report += f"{colored('─'*40, 'white')}\n"
        report += f"Target URL: {colored(url, 'cyan')}\n"
        
        # Add summary
        report += self._generate_summary(results)
        
        # Calculate and add risk score
        risk_score = self._generate_risk_score(results)
        score_color = 'green' if risk_score < 3 else 'yellow' if risk_score < 7 else 'red'
        report += f"\n{colored('OVERALL RISK SCORE', 'white', attrs=['bold'])}: "
        report += f"{colored(str(risk_score), score_color, attrs=['bold'])}/10.0\n"
        
        # Detailed findings
        if results:
            report += f"\n{colored('DETAILED FINDINGS', 'white', attrs=['bold'])}\n"
            report += f"{colored('='*80, 'white')}\n"
            
            for i, result in enumerate(results, 1):
                severity_level = SeverityLevel.get_level(result.severity)
                
                # Vulnerability header
                report += f"\n{colored(f'[{i}] {result.name}', 'white', attrs=['bold'])}\n"
                report += colored('─'*80, 'white') + '\n'
                
                # Severity and impact
                report += f"{colored('Severity:', 'white', attrs=['bold'])} "
                report += f"{colored(severity_level['label'], severity_level['color'], attrs=['bold'])}\n"
                report += f"{colored('Impact:', 'white', attrs=['bold'])} {result.impact}\n"
                
                # Description
                report += f"\n{colored('Description:', 'white', attrs=['bold'])}\n"
                report += textwrap.fill(result.description, width=80) + '\n'
                
                # Affected locations
                report += f"\n{colored('Affected Locations:', 'white', attrs=['bold'])}\n"
                for loc in result.locations:
                    report += f"● {colored('Element:', 'yellow')} {loc.element}\n"
                    report += f"  {colored('Location:', 'yellow')} {loc.location}\n"
                    report += f"  {colored('Detail:', 'yellow')} {loc.detail}\n\n"
                
                # Add remediation advice
                remediation = self._get_ai_remediation(result)
                report += f"{colored('Remediation Guidance:', 'white', attrs=['bold'])}\n"
                report += f"{colored('Priority:', 'cyan')} {remediation.priority}\n"
                report += f"{colored('Difficulty:', 'cyan')} {remediation.difficulty}\n"
                report += f"\n{colored('General Guidance:', 'cyan')}\n"
                report += textwrap.fill(remediation.general_guidance, width=80) + '\n'
                
                report += f"\n{colored('Specific Steps:', 'cyan')}\n"
                for step in remediation.specific_steps:
                    report += f"● {step}\n"
                
                report += f"\n{colored('Additional Resources:', 'cyan')}\n"
                for resource in remediation.resources:
                    report += f"● {resource}\n"
                
                report += colored('─'*80, 'white') + '\n'
        else:
            report += colored("\nNo vulnerabilities were detected.", 'green')
        
        # Add footer
        report += f"\n{colored('='*80, 'blue')}\n"
        report += colored("End of Report", 'blue', attrs=['bold'])
        report += f"\n{colored('='*80, 'blue')}\n"
        
        return report

class VulnerabilityScanner:
    def __init__(self, ai_model: Optional[Any] = None):
        self.report_generator = ReportGenerator(ai_model)
        self.checks: Dict[str, VulnerabilityCheck] = {
            'xss': VulnerabilityCheck(
                name='Cross-Site Scripting (XSS)',
                description='Checks for XSS vulnerabilities including reflected, stored, and DOM-based XSS.',
                severity='High',
                subchecks=['Reflected XSS', 'Stored XSS', 'DOM-based XSS'],
                impact='Can allow attackers to execute malicious scripts in users\' browsers.',
                patterns=[
                    r'<script.*?>.*?</script>',
                    r'on\w+=".*?"',
                    r'javascript:.*?',
                    r'data:text/html.*?base64,',
                    r'&#x[0-9a-fA-F]+;'
                ]
            ),
            'sqli': VulnerabilityCheck(
                name='SQL Injection',
                description='Tests for SQL injection vulnerabilities in input parameters and forms.',
                severity='Critical',
                subchecks=['Error-based SQLi', 'Blind SQLi', 'Time-based SQLi'],
                impact='May allow unauthorized access to or manipulation of the database.',
                patterns=[
                    r'id=\d+',
                    r'SELECT.*?FROM',
                    r'WHERE.*?=.*?',
                    r'UNION.*?SELECT',
                    r'INSERT.*?INTO'
                ]
            ),
            'csrf': VulnerabilityCheck(
                name='Cross-Site Request Forgery',
                description='Checks for missing or weak CSRF protections.',
                severity='Medium',
                subchecks=['Token Validation', 'SameSite Cookie Settings'],
                impact='May allow attackers to perform unauthorized actions.',
                patterns=[
                    r'<form.*?>(?!.*csrf)',
                    r'action=.*?method=["\']POST["\']',
                    r'<form[^>]*method=["\']POST["\'][^>]*>'
                ]
            )
        }
        
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'VulnX-ai Security Scanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        }

    def scan_url(self, url: str) -> str:
        """Scan a URL and generate a comprehensive report."""
        try:
            # Validate URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            logger.info(f"Starting scan of {url}")
            results = self._perform_scan(url)
            return self.report_generator.generate_report(url, results), results
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            return colored("An error occurred during the scan. Please check the logs.", "red"), []

    def _perform_scan(self, url: str) -> List[VulnerabilityResult]:
        """Perform the actual scan."""
        try:
            response = self.session.get(
                url,
                timeout=30,
                verify=True,
                allow_redirects=True
            )
            response.raise_for_status()
            
            results = self._analyze_content(url, response.text)
            
            # Additional checks for HTTP headers
            self._check_security_headers(response, results)
            
            return results
        except requests.exceptions.RequestException as e:
            logger.error(f"Error scanning URL {url}: {str(e)}")
            return []

    def _check_security_headers(self, response: requests.Response, results: List[VulnerabilityResult]) -> None:
        """Check for missing security headers."""
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'Content-Security-Policy': 'Missing Content Security Policy'
        }
        
        missing_headers = []
        for header, message in security_headers.items():
            if header not in response.headers:
                missing_headers.append(VulnerabilityLocation(
                    element='HTTP Header',
                    location=header,
                    detail=message
                ))
        
        if missing_headers:
            results.append(VulnerabilityResult(
                name='Missing Security Headers',
                severity='Medium',
                locations=missing_headers,
                description='Important security headers are missing from the HTTP response',
                impact='May expose the application to various attacks including clickjacking and MIME-type confusion'
            ))

    def _analyze_content(self, url: str, content: str) -> List[VulnerabilityResult]:
        """Analyze content for vulnerabilities."""
        results = []
        for check_type, check in self.checks.items():
            locations = self._find_vulnerability_locations(content, check_type)
            if locations:
                results.append(VulnerabilityResult(
                    name=check.name,
                    severity=check.severity,
                    locations=locations,
                    description=check.description,
                    impact=check.impact
                ))
        return results

    def _find_vulnerability_locations(self, content: str, check_type: str) -> List[VulnerabilityLocation]:
        """Find vulnerability locations in content."""
        if not content:
            return []

        locations = []
        check = self.checks[check_type]
        soup = BeautifulSoup(content, 'html.parser')

        # Check patterns in raw content
        for pattern in check.patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                locations.append(VulnerabilityLocation(
                    element='raw content',
                    location=f"Match: {match.group()[:50]}{'...' if len(match.group()) > 50 else ''}",
                    detail=f'Pattern match: {pattern}'
                ))

        # Check forms
        self._check_forms(soup, check_type, locations)
        
        # Check links and scripts
        if check_type == 'xss':
            self._check_links(soup, locations)
            self._check_scripts(soup, locations)

        return locations

    def _check_forms(self, soup: BeautifulSoup, check_type: str, locations: List[VulnerabilityLocation]) -> None:
        """Check forms for vulnerabilities."""
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', '').upper()
            
            if check_type == 'csrf' and method == 'POST':
                if not self._has_csrf_protection(form):
                    locations.append(VulnerabilityLocation(
                        element='form',
                        location=f"Form action='{action}'",
                        detail='POST form without CSRF protection'
                    ))

            if check_type == 'xss':
                self._check_form_inputs(form, action, locations)

            if check_type == 'sqli':
                self._check_form_for_sql_injection(form, action, locations)

    def _check_links(self, soup: BeautifulSoup, locations: List[VulnerabilityLocation]) -> None:
        """Check links for XSS vulnerabilities."""
        for link in soup.find_all('a'):
            href = link.get('href', '')
            if 'javascript:' in href.lower() or 'data:' in href.lower():
                locations.append(VulnerabilityLocation(
                    element='link',
                    location=f"href='{href}'",
                    detail='Potentially unsafe JavaScript or data URI in href'
                ))

    def _check_scripts(self, soup: BeautifulSoup, locations: List[VulnerabilityLocation]) -> None:
        """Check script tags for potential XSS vulnerabilities."""
        for script in soup.find_all('script'):
            src = script.get('src', '')
            if src and not src.startswith(('https://', 'http://', '/')):
                locations.append(VulnerabilityLocation(
                    element='script',
                    location=f"src='{src}'",
                    detail='Script source using relative path or unknown protocol'
                ))
            
            if script.string:
                if 'document.write' in script.string or 'eval(' in script.string:
                    locations.append(VulnerabilityLocation(
                        element='script',
                        location='inline script',
                        detail='Potentially dangerous JavaScript functions detected'
                    ))

    @staticmethod
    def _has_csrf_protection(form: BeautifulSoup) -> bool:
        """Check if a form has CSRF protection."""
        # Check for CSRF token in hidden inputs
        for input_tag in form.find_all('input', type='hidden'):
            name = input_tag.get('name', '').lower()
            if 'csrf' in name or 'token' in name:
                return True
                
        # Check for CSRF meta tag
        meta_tags = form.find_all('meta', attrs={'name': re.compile(r'csrf|token', re.I)})
        return len(meta_tags) > 0

    def _check_form_inputs(self, form: BeautifulSoup, action: str, locations: List[VulnerabilityLocation]) -> None:
        """Check form inputs for vulnerabilities."""
        vulnerable_types = ['text', 'search', 'url', 'tel', 'email', 'password']
        for input_field in form.find_all('input'):
            if input_field.get('type') in vulnerable_types:
                locations.append(VulnerabilityLocation(
                    element='form input',
                    location=f"Form action='{action}', input name='{input_field.get('name')}'",
                    detail='Potentially vulnerable to XSS via user input'
                ))

    def _check_form_for_sql_injection(self, form: BeautifulSoup, action: str, locations: List[VulnerabilityLocation]) -> None:
        """Check form inputs for potential SQL injection vulnerabilities."""
        suspicious_names = ['id', 'user', 'username', 'password', 'query', 'search']
        for input_field in form.find_all('input'):
            name = input_field.get('name', '').lower()
            if any(suspicious in name for suspicious in suspicious_names):
                locations.append(VulnerabilityLocation(
                    element='form input',
                    location=f"Form action='{action}', input name='{name}'",
                    detail='Potential SQL injection point in form input'
                ))

class ModelManager:
    def __init__(self, device: torch.device):
        self.device = device
        self.resource_manager = ResourceManager()

    def load_model(self, model_path: str) -> Union[Tuple[AutoModelForCausalLM, AutoTokenizer], Llama, None]:
        """Load the appropriate model based on the file type."""
        try:
            if model_path.endswith('.safetensors'):
                return self._load_transformer_model(model_path)
            else:
                return self._load_llama_model(model_path)
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            return None

    def _load_transformer_model(self, model_path: str) -> Tuple[AutoModelForCausalLM, AutoTokenizer]:
        """Load a transformer-based model."""
        logger.info("Loading transformer model...")
        with self.resource_manager.suppress_output():
            tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
            model = AutoModelForCausalLM.from_pretrained(
                model_path,
                trust_remote_code=True,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                device_map="auto" if torch.cuda.is_available() else None,
                low_cpu_mem_usage=True
            ).to(self.device)
        return model, tokenizer

    def _load_llama_model(self, model_path: str) -> Llama:
        """Load a Llama model."""
        logger.info("Loading Llama model...")
        cpu_cores, available_memory = self.resource_manager.get_system_resources()
        n_ctx = min(512, max(256, available_memory // 16))
        n_batch = max(8, min(32, available_memory // 512))

        with self.resource_manager.suppress_output():
            return Llama(
                model_path=model_path,
                n_threads=cpu_cores,
                n_ctx=n_ctx,
                n_batch=n_batch,
                use_mlock=False,
                use_mmap=True
            )

def main():

    # Set up device
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Using device: {device}")

    # Initialize model manager
    model_manager = ModelManager(device)
    
    # Set process priority
    try:
        process = psutil.Process()
        process.nice(10)  # Lower priority to be resource-friendly
    except Exception as e:
        logger.warning(f"Could not set process priority: {str(e)}")

    # Load model
    model_path = Path("/bert_cybersec/model.safetensors")
    model = None if not model_path.exists() else model_manager.load_model(str(model_path))

    print(colored("\nWelcome to VulnX-ai Security Scanner", "blue", attrs=["bold"]))
    print(colored("Running in resource-efficient mode\n", "cyan"))

    while True:
        try:
            url = input("\nEnter the URL to scan (or 'quit' to exit): ").strip()
            if url.lower() == 'quit':
                break
                
            if not url:
                print(colored("Error: Please provide a valid URL", "red"))
                continue

            scanner = VulnerabilityScanner(model)
            print(colored("\nInitiating scan...", "yellow"))
            
            # Modify the scan_url method to return both the report and results
            report, results = scanner.scan_url(url)
            print(report)
            
            # Optionally save the report
            save_report = input("\nWould you like to save this report? (y/n): ").strip().lower()
            if save_report == 'y':
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                # Get the shortened version of the URL (domain only)
                short_url = shorten_url(url)
                # Generate the filename using the short URL
                filename = f"security_scan_{short_url}@{timestamp}.html"
                # Now we have access to both the results and url
                html_report = scanner.report_generator.generate_html_report(url, results)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html_report)
                print(colored(f"\nReport saved as: {filename}", "green"))

        except KeyboardInterrupt:
            print(colored("\nScan interrupted by user.", "yellow"))
            break
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            print(colored("\nAn error occurred during scanning. Check the logs for details.", "red"))
        finally:
            ResourceManager.clear_memory()

    print(colored("\nThank you for using VulnX-ai Security Scanner!", "blue"))

if __name__ == "__main__":
    main()