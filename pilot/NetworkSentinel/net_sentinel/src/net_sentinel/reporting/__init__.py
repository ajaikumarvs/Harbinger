"""
Net-Sentinel Reporting Module
~~~~~~~~~~~~~~~~~~~~~~~~

This module handles report generation and formatting for scan results,
supporting multiple output formats including HTML and XML.

Basic usage:
    >>> from net_sentinel.reporting import ReportGenerator, ReportFormat
    >>> generator = ReportGenerator()
    >>> generator.generate_report(results, format=ReportFormat.HTML)
"""

import logging
from typing import Dict, List, Any, Optional, Union
from enum import Enum, auto
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path

logger = logging.getLogger(__name__)

class ReportFormat(Enum):
    """Supported report formats."""
    HTML = auto()
    XML = auto()
    JSON = auto()
    MARKDOWN = auto()

class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Finding:
    """Represents a security finding in the report."""
    title: str
    description: str
    severity: Severity
    cvss_score: Optional[float] = None
    cve_ids: List[str] = None
    remediation: Optional[str] = None
    references: List[str] = None
    technical_details: Dict[str, Any] = None
    
    def __post_init__(self):
        """Initialize optional fields."""
        if self.cve_ids is None:
            self.cve_ids = []
        if self.references is None:
            self.references = []
        if self.technical_details is None:
            self.technical_details = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary format."""
        return {
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'cvss_score': self.cvss_score,
            'cve_ids': self.cve_ids,
            'remediation': self.remediation,
            'references': self.references,
            'technical_details': self.technical_details
        }

@dataclass
class ReportMetadata:
    """Metadata for the report."""
    scan_time: datetime
    scan_duration: float
    tool_version: str
    scan_type: str
    target: str
    scan_options: Dict[str, Any]
    total_hosts: int
    total_services: int
    total_findings: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary format."""
        return {
            'scan_time': self.scan_time.isoformat(),
            'scan_duration': self.scan_duration,
            'tool_version': self.tool_version,
            'scan_type': self.scan_type,
            'target': self.target,
            'scan_options': self.scan_options,
            'total_hosts': self.total_hosts,
            'total_services': self.total_services,
            'total_findings': self.total_findings
        }

@dataclass
class Report:
    """Complete scan report."""
    metadata: ReportMetadata
    findings: List[Finding]
    hosts: List[Dict[str, Any]]
    services: List[Dict[str, Any]]
    raw_data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary format."""
        return {
            'metadata': self.metadata.to_dict(),
            'findings': [f.to_dict() for f in self.findings],
            'hosts': self.hosts,
            'services': self.services,
            'raw_data': self.raw_data
        }
    
    def get_findings_by_severity(
        self,
        severity: Severity
    ) -> List[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]
    
    def get_finding_statistics(self) -> Dict[str, int]:
        """Get statistics about findings."""
        stats = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            stats[finding.severity.value] += 1
        return stats

class ReportGenerationError(Exception):
    """Exception raised for report generation errors."""
    pass

# Import main components
from .html_generator import HTMLReporter
from .xml_generator import XMLReporter

__all__ = [
    'HTMLReporter',
    'XMLReporter',
    'Report',
    'Finding',
    'ReportMetadata',
    'ReportFormat',
    'Severity',
    'ReportGenerationError'
]

def create_report(
    scan_results: Dict[str, Any],
    scan_options: Dict[str, Any]
) -> Report:
    """
    Create a report from scan results.
    
    Args:
        scan_results: Raw scan results
        scan_options: Options used for scanning
        
    Returns:
        Formatted Report object
        
    Raises:
        ReportGenerationError: If report creation fails
    """
    try:
        # Extract metadata
        metadata = ReportMetadata(
            scan_time=datetime.now(),
            scan_duration=scan_results.get('duration', 0.0),
            tool_version=scan_results.get('version', '1.0.0'),
            scan_type=scan_options.get('scan_type', 'unknown'),
            target=scan_options.get('target', 'unknown'),
            scan_options=scan_options,
            total_hosts=len(scan_results.get('hosts', [])),
            total_services=sum(len(h.get('services', [])) 
                             for h in scan_results.get('hosts', [])),
            total_findings=len(scan_results.get('findings', []))
        )
        
        # Process findings
        findings = []
        for raw_finding in scan_results.get('findings', []):
            findings.append(Finding(
                title=raw_finding['title'],
                description=raw_finding['description'],
                severity=Severity(raw_finding['severity']),
                cvss_score=raw_finding.get('cvss_score'),
                cve_ids=raw_finding.get('cve_ids', []),
                remediation=raw_finding.get('remediation'),
                references=raw_finding.get('references', []),
                technical_details=raw_finding.get('technical_details', {})
            ))
        
        return Report(
            metadata=metadata,
            findings=findings,
            hosts=scan_results.get('hosts', []),
            services=scan_results.get('services', []),
            raw_data=scan_results
        )
        
    except Exception as e:
        logger.error(f"Failed to create report: {str(e)}")
        raise ReportGenerationError(f"Failed to create report: {str(e)}")

def validate_report(report: Report) -> bool:
    """
    Validate report structure and content.
    
    Args:
        report: Report to validate
        
    Returns:
        bool indicating if report is valid
        
    Raises:
        ValueError: If report is invalid
    """
    if not isinstance(report.metadata, ReportMetadata):
        raise ValueError("Invalid report metadata")
    
    if not all(isinstance(f, Finding) for f in report.findings):
        raise ValueError("Invalid findings")
    
    if not isinstance(report.hosts, list):
        raise ValueError("Invalid hosts data")
    
    if not isinstance(report.services, list):
        raise ValueError("Invalid services data")
    
    return True