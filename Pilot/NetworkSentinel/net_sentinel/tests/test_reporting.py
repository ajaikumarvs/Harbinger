"""
Tests for Net-Sentinel Reporting Components
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module provides test cases for report generation
and formatting functionality.
"""

import pytest
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from datetime import datetime
from unittest.mock import Mock, patch
import tempfile
import os
from bs4 import BeautifulSoup

from net_sentinel.reporting import (
    HTMLReporter,
    XMLReporter,
    Report,
    Finding,
    ReportMetadata,
    Severity,
    ReportFormat,
    ReportGenerationError
)
from tests import BaseTestCase, TestConfig

class TestHTMLReporter(BaseTestCase):
    """Test cases for HTML report generation."""
    
    def setup_method(self, method):
        """Set up test method."""
        super().setup_method(method)
        self.reporter = HTMLReporter()
        self.report = self._create_sample_report()
    
    def test_generate_report(self):
        """Test basic HTML report generation."""
        output_path = Path(self.temp_dir) / "report.html"
        
        self.reporter.generate_report(
            self.report,
            str(output_path)
        )
        
        assert output_path.exists()
        content = output_path.read_text()
        
        # Parse HTML and verify structure
        soup = BeautifulSoup(content, 'html.parser')
        
        # Check basic structure
        assert soup.title.text == "Net-Sentinel Scan Report"
        assert soup.find("div", class_="findings-section")
        
        # Verify vulnerabilities are included
        findings = soup.find_all("div", class_="finding-card")
        assert len(findings) == len(self.report.findings)
        
        # Check severity badges
        severity_badges = soup.find_all("span", class_="severity-badge")
        assert all(
            badge.text.lower() in [s.value for s in Severity]
            for badge in severity_badges
        )
    
    def test_chart_generation(self):
        """Test chart generation in HTML reports."""
        output_path = Path(self.temp_dir) / "report_with_charts.html"
        
        self.reporter.generate_report(
            self.report,
            str(output_path),
            include_raw_data=True
        )
        
        content = output_path.read_text()
        soup = BeautifulSoup(content, 'html.parser')
        
        # Check for chart containers
        charts = soup.find_all("div", class_="chart-container")
        assert len(charts) >= 3  # Should have at least severity, timeline, and service charts
        
        # Verify Plotly inclusion
        assert soup.find("script", src=lambda s: "plotly" in str(s))
    
    def test_report_validation(self):
        """Test report validation during generation."""
        # Test with invalid report
        invalid_report = Report(
            metadata=None,  # Invalid - metadata is required
            findings=[],
            hosts=[],
            services=[]
        )
        
        output_path = Path(self.temp_dir) / "invalid_report.html"
        
        with pytest.raises(ReportGenerationError):
            self.reporter.generate_report(invalid_report, str(output_path))
    
    def test_custom_template(self):
        """Test custom template usage."""
        template_dir = Path(self.temp_dir) / "templates"
        template_dir.mkdir()
        
        # Create custom template
        custom_template = """
        <!DOCTYPE html>
        <html>
        <head><title>Custom Report</title></head>
        <body>
            <h1>Custom Template</h1>
            {% for finding in report.findings %}
            <div class="finding">{{ finding.title }}</div>
            {% endfor %}
        </body>
        </html>
        """
        
        (template_dir / "report.html").write_text(custom_template)
        
        # Create reporter with custom template
        reporter = HTMLReporter(template_dir=str(template_dir))
        output_path = Path(self.temp_dir) / "custom_report.html"
        
        reporter.generate_report(self.report, str(output_path))
        
        content = output_path.read_text()
        soup = BeautifulSoup(content, 'html.parser')
        
        assert soup.title.text == "Custom Report"
        assert soup.h1.text == "Custom Template"

class TestXMLReporter(BaseTestCase):
    """Test cases for XML report generation."""
    
    def setup_method(self, method):
        """Set up test method."""
        super().setup_method(method)
        self.reporter = XMLReporter()
        self.report = self._create_sample_report()
    
    def test_generate_report(self):
        """Test basic XML report generation."""
        output_path = Path(self.temp_dir) / "report.xml"
        
        self.reporter.generate_report(
            self.report,
            str(output_path)
        )
        
        assert output_path.exists()
        
        # Parse and validate XML
        tree = ET.parse(output_path)
        root = tree.getroot()
        
        assert root.tag == "net-sentinel-report"
        assert root.find("metadata") is not None
        assert root.find("findings") is not None
        
        # Verify findings count
        findings = root.findall(".//finding")
        assert len(findings) == len(self.report.findings)
    
    def test_different_schemas(self):
        """Test different XML schema formats."""
        schemas = [
            ('native', "net-sentinel-report"),
            ('oval', "oval_definitions"),
            ('scap', "scap_report"),
            ('cvrf', "cvrfdoc")
        ]
        
        for schema_name, root_tag in schemas:
            reporter = XMLReporter(schema=schema_name)
            output_path = Path(self.temp_dir) / f"report_{schema_name}.xml"
            
            reporter.generate_report(self.report, str(output_path))
            
            tree = ET.parse(output_path)
            root = tree.getroot()
            
            assert root.tag == root_tag
    
    def test_content_validation(self):
        """Test XML content validation."""
        output_path = Path(self.temp_dir) / "report_validated.xml"
        
        # Enable validation
        reporter = XMLReporter(validate=True)
        reporter.generate_report(self.report, str(output_path))
        
        # Parse and check required elements
        tree = ET.parse(output_path)
        root = tree.getroot()
        
        required_elements = [
            "metadata",
            "findings",
            "hosts",
            "services"
        ]
        
        for element in required_elements:
            assert root.find(element) is not None
            
        # Check metadata fields
        metadata = root.find("metadata")
        assert metadata.find("scan_time") is not None
        assert metadata.find("target") is not None
    
    def test_report_hashing(self):
        """Test report hash generation."""
        output_path = Path(self.temp_dir) / "report_hashed.xml"
        
        self.reporter.generate_report(
            self.report,
            str(output_path)
        )
        
        tree = ET.parse(output_path)
        root = tree.getroot()
        
        # Verify hash attribute
        assert "content_hash" in root.attrib
        assert len(root.attrib["content_hash"]) == 64  # SHA-256 hash length

    @staticmethod
    def _create_sample_report() -> Report:
        """Create sample report for testing."""
        return Report(
            metadata=ReportMetadata(
                scan_time=datetime.now(),
                scan_duration=120.5,
                tool_version="1.0.0",
                scan_type="full",
                target="192.168.1.0/24",
                total_hosts=10,
                total_services=25,
                total_findings=5,
                scan_options={}
            ),
            findings=[
                Finding(
                    title="Critical Service Exposed",
                    description="A critical service is exposed",
                    severity=Severity.CRITICAL,
                    cvss_score=9.1,
                    remediation="Restrict access"
                ),
                Finding(
                    title="Weak Configuration",
                    description="Service has weak configuration",
                    severity=Severity.MEDIUM,
                    cvss_score=5.5,
                    remediation="Strengthen configuration"
                )
            ],
            hosts=[
                {
                    "ip": "192.168.1.100",
                    "hostname": "test-host",
                    "ports": [80, 443]
                }
            ],
            services=[
                {
                    "port": 80,
                    "service": "http",
                    "version": "2.4.29"
                }
            ]
        )

@pytest.fixture
def sample_report_data():
    """Provide sample report data."""
    return {
        "metadata": {
            "scan_time": datetime.now().isoformat(),
            "target": "192.168.1.0/24",
            "tool_version": "1.0.0"
        },
        "findings": [
            {
                "title": "Open Port",
                "severity": "high",
                "description": "Port 22 is open",
                "remediation": "Close port if not needed"
            }
        ],
        "hosts": [
            {
                "ip": "192.168.1.100",
                "ports": [22, 80]
            }
        ]
    }

@pytest.fixture
def mock_chart_data():
    """Provide mock chart data."""
    return {
        "severity_distribution": {
            "critical": 2,
            "high": 3,
            "medium": 5,
            "low": 8
        },
        "timeline": [
            {"time": "2024-12-10T12:00:00", "events": 10},
            {"time": "2024-12-10T12:05:00", "events": 15}
        ]
    }