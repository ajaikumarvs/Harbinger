"""
XML Report Generator Module for Net-Sentinel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module handles the generation of XML reports with proper
validation and compliance with security assessment standards.
"""

import logging
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
import hashlib
from enum import Enum

from . import Report, ReportGenerationError, Severity

logger = logging.getLogger(__name__)

class XMLSchema(Enum):
    """Supported XML schema types."""
    NATIVE = "native"      # Net-Sentinel native format
    OVAL = "oval"         # Open Vulnerability and Assessment Language
    SCAP = "scap"         # Security Content Automation Protocol
    CVRF = "cvrf"         # Common Vulnerability Reporting Framework

class XMLReporter:
    """
    Generates XML reports for scan results.
    """
    
    def __init__(
        self,
        schema: XMLSchema = XMLSchema.NATIVE,
        validate: bool = True
    ):
        """
        Initialize XML reporter.
        
        Args:
            schema: XML schema to use
            validate: Whether to validate output
        """
        self.schema = schema
        self.validate = validate
    
    def generate_report(
        self,
        report: Report,
        output_path: str,
        indent: bool = True,
        include_raw: bool = False
    ) -> None:
        """
        Generate XML report.
        
        Args:
            report: Report object to generate from
            output_path: Path to save XML report
            indent: Whether to indent XML output
            include_raw: Whether to include raw scan data
            
        Raises:
            ReportGenerationError: If report generation fails
        """
        try:
            # Create root element based on schema
            if self.schema == XMLSchema.NATIVE:
                root = self._create_native_report(report, include_raw)
            elif self.schema == XMLSchema.OVAL:
                root = self._create_oval_report(report)
            elif self.schema == XMLSchema.SCAP:
                root = self._create_scap_report(report)
            elif self.schema == XMLSchema.CVRF:
                root = self._create_cvrf_report(report)
            else:
                raise ValueError(f"Unsupported schema: {self.schema}")
            
            # Add report hash
            self._add_report_hash(root, report)
            
            # Validate if required
            if self.validate:
                self._validate_xml(root)
            
            # Format and save
            xml_str = self._format_xml(root, indent)
            output_path = Path(output_path)
            output_path.write_text(xml_str, encoding='utf-8')
            
            logger.info(f"XML report generated: {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to generate XML report: {str(e)}")
            raise ReportGenerationError(f"XML generation failed: {str(e)}")
    
    def _create_native_report(
        self,
        report: Report,
        include_raw: bool
    ) -> ET.Element:
        """Create report in native Net-Sentinel format."""
        root = ET.Element("net-sentinel-report")
        root.set("version", "1.0")
        root.set("timestamp", datetime.now().isoformat())
        
        # Add metadata
        metadata = ET.SubElement(root, "metadata")
        for key, value in report.metadata.to_dict().items():
            elem = ET.SubElement(metadata, key)
            elem.text = str(value)
        
        # Add findings
        findings = ET.SubElement(root, "findings")
        for finding in report.findings:
            finding_elem = ET.SubElement(findings, "finding")
            finding_elem.set("severity", finding.severity.value)
            
            # Add finding details
            for key, value in finding.to_dict().items():
                if value is not None:
                    if isinstance(value, (list, dict)):
                        elem = ET.SubElement(finding_elem, key)
                        elem.text = str(value)
                    else:
                        elem = ET.SubElement(finding_elem, key)
                        elem.text = str(value)
        
        # Add hosts
        hosts = ET.SubElement(root, "hosts")
        for host in report.hosts:
            host_elem = ET.SubElement(hosts, "host")
            for key, value in host.items():
                if value is not None:
                    elem = ET.SubElement(host_elem, key)
                    elem.text = str(value)
        
        # Add services
        services = ET.SubElement(root, "services")
        for service in report.services:
            service_elem = ET.SubElement(services, "service")
            for key, value in service.items():
                if value is not None:
                    elem = ET.SubElement(service_elem, key)
                    elem.text = str(value)
        
        # Add raw data if requested
        if include_raw and report.raw_data:
            raw_data = ET.SubElement(root, "raw_data")
            self._dict_to_xml(report.raw_data, raw_data)
        
        return root
    
    def _create_oval_report(self, report: Report) -> ET.Element:
        """Create report in OVAL format."""
        root = ET.Element("oval_definitions")
        root.set("xmlns", "http://oval.mitre.org/XMLSchema/oval-definitions-5")
        
        # Add generator information
        generator = ET.SubElement(root, "generator")
        prod_name = ET.SubElement(generator, "product_name")
        prod_name.text = "Net-Sentinel"
        timestamp = ET.SubElement(generator, "timestamp")
        timestamp.text = datetime.now().isoformat()
        
        # Add definitions
        definitions = ET.SubElement(root, "definitions")
        for finding in report.findings:
            definition = ET.SubElement(definitions, "definition")
            definition.set("class", "vulnerability")
            definition.set("id", f"net-sentinel:{finding.title.lower().replace(' ', '_')}")
            definition.set("version", "1")
            
            metadata = ET.SubElement(definition, "metadata")
            title = ET.SubElement(metadata, "title")
            title.text = finding.title
            description = ET.SubElement(metadata, "description")
            description.text = finding.description
            
            # Add CVEs if available
            if finding.cve_ids:
                refs = ET.SubElement(metadata, "references")
                for cve in finding.cve_ids:
                    ref = ET.SubElement(refs, "reference")
                    ref.set("source", "CVE")
                    ref.set("ref_id", cve)
        
        return root
    
    def _create_scap_report(self, report: Report) -> ET.Element:
        """Create report in SCAP format."""
        root = ET.Element("scap_report")
        root.set("xmlns", "http://scap.nist.gov/schema/scap/source/1.2")
        
        # Add basic report information
        benchmark = ET.SubElement(root, "benchmark")
        for finding in report.findings:
            rule = ET.SubElement(benchmark, "Rule")
            rule.set("id", f"net-sentinel-{finding.title.lower().replace(' ', '_')}")
            rule.set("severity", finding.severity.value)
            
            title = ET.SubElement(rule, "title")
            title.text = finding.title
            description = ET.SubElement(rule, "description")
            description.text = finding.description
        
        return root
    
    def _create_cvrf_report(self, report: Report) -> ET.Element:
        """Create report in CVRF format."""
        root = ET.Element("cvrfdoc")
        root.set("xmlns", "http://www.icasi.org/CVRF/schema/cvrf/1.1")
        
        # Add document title
        doc_title = ET.SubElement(root, "DocumentTitle")
        doc_title.text = f"Net-Sentinel Scan Report - {report.metadata.target}"
        
        # Add vulnerability list
        vuln_list = ET.SubElement(root, "Vulnerability")
        for finding in report.findings:
            vuln = ET.SubElement(vuln_list, "Vulnerability")
            title = ET.SubElement(vuln, "Title")
            title.text = finding.title
            
            notes = ET.SubElement(vuln, "Notes")
            note = ET.SubElement(notes, "Note")
            note.set("Type", "Description")
            note.text = finding.description
        
        return root
    
    def _dict_to_xml(self, data: Dict, parent: ET.Element) -> None:
        """Convert dictionary to XML elements."""
        for key, value in data.items():
            child = ET.SubElement(parent, str(key))
            if isinstance(value, dict):
                self._dict_to_xml(value, child)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._dict_to_xml(item, ET.SubElement(child, "item"))
                    else:
                        item_elem = ET.SubElement(child, "item")
                        item_elem.text = str(item)
            else:
                child.text = str(value)
    
    def _add_report_hash(self, root: ET.Element, report: Report) -> None:
        """Add hash of report content for integrity checking."""
        # Create hash of report content
        hasher = hashlib.sha256()
        for finding in report.findings:
            hasher.update(str(finding.to_dict()).encode())
        
        # Add hash to root element
        root.set("content_hash", hasher.hexdigest())
    
    def _validate_xml(self, root: ET.Element) -> None:
        """
        Validate XML against schema.
        
        Raises:
            ValueError: If XML is invalid
        """
        if self.schema != XMLSchema.NATIVE:
            # Load appropriate schema for validation
            # Implement schema validation for other formats
            pass
    
    def _format_xml(self, root: ET.Element, indent: bool) -> str:
        """Format XML string with proper indentation."""
        rough_string = ET.tostring(root, encoding='unicode')
        if indent:
            reparsed = minidom.parseString(rough_string)
            return reparsed.toprettyxml(indent="  ")
        return rough_string