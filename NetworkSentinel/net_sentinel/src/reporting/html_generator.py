"""
HTML Report Generator Module for Net-Sentinel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module handles the generation of HTML reports with
interactive features and professional styling.
"""

import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import json
from datetime import datetime
from jinja2 import Environment, PackageLoader, select_autoescape
import base64
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from . import Report, ReportGenerationError, Severity

logger = logging.getLogger(__name__)

class HTMLReporter:
    """
    Generates interactive HTML reports for scan results.
    """
    
    def __init__(self, template_dir: Optional[str] = None):
        """
        Initialize HTML reporter.
        
        Args:
            template_dir: Optional custom template directory
        """
        self.template_dir = template_dir
        self._setup_environment()
    
    def _setup_environment(self) -> None:
        """Set up Jinja2 environment."""
        try:
            if self.template_dir:
                self.env = Environment(
                    loader=PackageLoader('net_sentinel', self.template_dir),
                    autoescape=select_autoescape(['html', 'xml'])
                )
            else:
                self.env = Environment(
                    loader=PackageLoader('net_sentinel', 'templates'),
                    autoescape=select_autoescape(['html', 'xml'])
                )
            
            # Add custom filters
            self.env.filters['format_datetime'] = self._format_datetime
            self.env.filters['severity_color'] = self._get_severity_color
            self.env.filters['to_json'] = json.dumps
            
        except Exception as e:
            logger.error(f"Failed to setup template environment: {str(e)}")
            raise ReportGenerationError("Template setup failed")
    
    def generate_report(
        self,
        report: Report,
        output_path: str,
        include_raw_data: bool = False
    ) -> None:
        """
        Generate HTML report.
        
        Args:
            report: Report object to generate from
            output_path: Path to save HTML report
            include_raw_data: Whether to include raw scan data
            
        Raises:
            ReportGenerationError: If report generation fails
        """
        try:
            # Create charts
            severity_chart = self._create_severity_chart(report)
            timeline_chart = self._create_timeline_chart(report)
            service_chart = self._create_service_chart(report)
            
            # Generate report context
            context = {
                'report': report,
                'severity_chart': severity_chart,
                'timeline_chart': timeline_chart,
                'service_chart': service_chart,
                'generation_time': datetime.now(),
                'include_raw_data': include_raw_data,
                'summary': self._generate_summary(report)
            }
            
            # Render template
            template = self.env.get_template('report.html')
            output = template.render(**context)
            
            # Save report
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(output)
            
            logger.info(f"HTML report generated: {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {str(e)}")
            raise ReportGenerationError(f"HTML generation failed: {str(e)}")
    
    def _create_severity_chart(self, report: Report) -> str:
        """Create severity distribution chart."""
        stats = report.get_finding_statistics()
        
        fig = go.Figure(data=[
            go.Bar(
                x=list(stats.keys()),
                y=list(stats.values()),
                marker_color=[
                    self._get_severity_color(sev)
                    for sev in stats.keys()
                ]
            )
        ])
        
        fig.update_layout(
            title="Finding Severity Distribution",
            xaxis_title="Severity Level",
            yaxis_title="Number of Findings",
            template="plotly_white"
        )
        
        return self._fig_to_html(fig)
    
    def _create_timeline_chart(self, report: Report) -> str:
        """Create scan timeline chart."""
        # Create timeline data
        events = []
        current_time = report.metadata.scan_time
        duration = report.metadata.scan_duration
        
        # Add events every 10% of scan duration
        for i in range(11):
            timestamp = current_time.timestamp() + (duration * i / 10)
            events.append({
                'time': datetime.fromtimestamp(timestamp),
                'value': i * 10
            })
        
        fig = go.Figure(data=[
            go.Scatter(
                x=[e['time'] for e in events],
                y=[e['value'] for e in events],
                mode='lines+markers',
                name='Scan Progress'
            )
        ])
        
        fig.update_layout(
            title="Scan Timeline",
            xaxis_title="Time",
            yaxis_title="Progress (%)",
            template="plotly_white"
        )
        
        return self._fig_to_html(fig)
    
    def _create_service_chart(self, report: Report) -> str:
        """Create service distribution chart."""
        # Count services
        service_counts = {}
        for service in report.services:
            name = service.get('service', 'unknown')
            service_counts[name] = service_counts.get(name, 0) + 1
        
        fig = go.Figure(data=[
            go.Pie(
                labels=list(service_counts.keys()),
                values=list(service_counts.values()),
                hole=.3
            )
        ])
        
        fig.update_layout(
            title="Service Distribution",
            template="plotly_white"
        )
        
        return self._fig_to_html(fig)
    
    def _generate_summary(self, report: Report) -> Dict[str, Any]:
        """Generate report summary."""
        return {
            'total_findings': len(report.findings),
            'critical_findings': len(report.get_findings_by_severity(Severity.CRITICAL)),
            'high_findings': len(report.get_findings_by_severity(Severity.HIGH)),
            'medium_findings': len(report.get_findings_by_severity(Severity.MEDIUM)),
            'low_findings': len(report.get_findings_by_severity(Severity.LOW)),
            'info_findings': len(report.get_findings_by_severity(Severity.INFO)),
            'total_hosts': len(report.hosts),
            'total_services': len(report.services),
            'scan_duration': report.metadata.scan_duration
        }
    
    def _fig_to_html(self, fig: go.Figure) -> str:
        """Convert Plotly figure to HTML string."""
        return fig.to_html(
            full_html=False,
            include_plotlyjs='cdn',
            config={'responsive': True}
        )
    
    @staticmethod
    def _format_datetime(dt: datetime) -> str:
        """Format datetime for display."""
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    
    @staticmethod
    def _get_severity_color(severity: str) -> str:
        """Get color for severity level."""
        colors = {
            'critical': '#dc3545',  # Red
            'high': '#fd7e14',      # Orange
            'medium': '#ffc107',    # Yellow
            'low': '#17a2b8',       # Cyan
            'info': '#6c757d'       # Gray
        }
        return colors.get(severity.lower(), '#6c757d')

# HTML template
def _create_vulnerability_map(self, report: Report) -> str:
        """Create vulnerability distribution map."""
        vuln_by_host = {}
        for finding in report.findings:
            affected_hosts = finding.technical_details.get('affected_hosts', [])
            for host in affected_hosts:
                if host not in vuln_by_host:
                    vuln_by_host[host] = {
                        'critical': 0, 'high': 0, 
                        'medium': 0, 'low': 0, 'info': 0
                    }
                vuln_by_host[host][finding.severity.value] += 1

        fig = go.Figure()
        
        # Add traces for each severity level
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            fig.add_trace(go.Bar(
                name=severity.capitalize(),
                x=list(vuln_by_host.keys()),
                y=[host_data[severity] for host_data in vuln_by_host.values()],
                marker_color=self._get_severity_color(severity)
            ))

        fig.update_layout(
            title="Vulnerability Distribution by Host",
            xaxis_title="Host",
            yaxis_title="Number of Vulnerabilities",
            barmode='stack',
            template="plotly_white"
        )

        return self._fig_to_html(fig)

    def _generate_executive_summary(self, report: Report) -> Dict[str, Any]:
        """Generate executive summary of findings."""
        return {
            'risk_score': self._calculate_risk_score(report),
            'critical_summary': self._summarize_critical_findings(report),
            'top_recommendations': self._get_top_recommendations(report),
            'scope_summary': {
                'networks_scanned': len(set(h['ip'].split('.')[0:3] for h in report.hosts)),
                'total_hosts': len(report.hosts),
                'responsive_hosts': len([h for h in report.hosts if h.get('status') == 'up']),
                'total_services': len(report.services),
                'unique_services': len(set(s.get('service') for s in report.services))
            }
        }

    def _calculate_risk_score(self, report: Report) -> float:
        """Calculate overall risk score based on findings."""
        severity_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
            Severity.INFO: 0
        }
        
        max_score = len(report.findings) * 10  # Maximum possible score
        actual_score = sum(
            severity_weights[finding.severity]
            for finding in report.findings
        )
        
        return (actual_score / max_score * 100) if max_score > 0 else 0

    def _summarize_critical_findings(self, report: Report) -> List[Dict[str, Any]]:
        """Summarize critical findings for executive summary."""
        critical_findings = report.get_findings_by_severity(Severity.CRITICAL)
        return [{
            'title': f.title,
            'affected_hosts': len(f.technical_details.get('affected_hosts', [])),
            'cvss_score': f.cvss_score,
            'key_impact': f.description.split('.')[0]  # First sentence of description
        } for f in critical_findings]

    def _get_top_recommendations(self, report: Report) -> List[str]:
        """Get top security recommendations."""
        # Prioritize recommendations from critical and high findings
        high_priority_findings = (
            report.get_findings_by_severity(Severity.CRITICAL) +
            report.get_findings_by_severity(Severity.HIGH)
        )
        
        recommendations = []
        for finding in high_priority_findings:
            if finding.remediation:
                recommendations.append(finding.remediation)
        
        # Return top 5 unique recommendations
        return list(dict.fromkeys(recommendations))[:5]

    def _create_trend_data(self, report: Report) -> str:
        """Create trend analysis visualization."""
        # This would typically compare with historical data
        # For now, we'll create a mock trend
        fig = go.Figure()
        
        # Mock historical data points
        dates = [
            report.metadata.scan_time - pd.Timedelta(days=x)
            for x in range(30, -1, -5)
        ]
        
        for severity in ['critical', 'high', 'medium', 'low']:
            # Generate mock trend data
            values = [
                len(report.get_findings_by_severity(getattr(Severity, severity.upper())))
                for _ in dates
            ]
            
            fig.add_trace(go.Scatter(
                x=dates,
                y=values,
                name=severity.capitalize(),
                line=dict(
                    color=self._get_severity_color(severity),
                    width=2
                )
            ))

        fig.update_layout(
            title="Vulnerability Trend (30 Days)",
            xaxis_title="Date",
            yaxis_title="Number of Findings",
            template="plotly_white",
            showlegend=True
        )

        return self._fig_to_html(fig)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Net-Sentinel Scan Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        .severity-badge {
            padding: 5px 10px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
        }
        .severity-critical { background-color: #dc3545; }
        .severity-high { background-color: #fd7e14; }
        .severity-medium { background-color: #ffc107; }
        .severity-low { background-color: #17a2b8; }
        .severity-info { background-color: #6c757d; }
        
        .finding-card {
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 15px;
            background-color: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }
        
        .section-header {
            margin: 30px 0 20px 0;
            padding-bottom: 10px;
            border-bottom: 2px solid #dee2e6;
        }
        
        .chart-container {
            margin: 20px 0;
            padding: 15px;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body class="bg-light">
    <div class="container-fluid py-4">
        <h1 class="text-center mb-4">Net-Sentinel Scan Report</h1>
        
        <!-- Scan Summary -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title">Scan Summary</h2>
                        <div class="row">
                            <div class="col-md-6">
                                <dl class="row">
                                    <dt class="col-sm-4">Scan Time</dt>
                                    <dd class="col-sm-8">{{ report.metadata.scan_time|format_datetime }}</dd>
                                    
                                    <dt class="col-sm-4">Duration</dt>
                                    <dd class="col-sm-8">{{ report.metadata.scan_duration|round(2) }} seconds</dd>
                                    
                                    <dt class="col-sm-4">Target</dt>
                                    <dd class="col-sm-8">{{ report.metadata.target }}</dd>
                                </dl>
                            </div>
                            <div class="col-md-6">
                                <dl class="row">
                                    <dt class="col-sm-4">Total Hosts</dt>
                                    <dd class="col-sm-8">{{ summary.total_hosts }}</dd>
                                    
                                    <dt class="col-sm-4">Total Services</dt>
                                    <dd class="col-sm-8">{{ summary.total_services }}</dd>
                                    
                                    <dt class="col-sm-4">Total Findings</dt>
                                    <dd class="col-sm-8">{{ summary.total_findings }}</dd>
                                </dl>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Charts -->
        <div class="row mb-4">
            <div class="col-md-4">
                <div class="chart-container">
                    {{ severity_chart|safe }}
                </div>
            </div>
            <div class="col-md-4">
                <div class="chart-container">
                    {{ timeline_chart|safe }}
                </div>
            </div>
            <div class="col-md-4">
                <div class="chart-container">
                    {{ service_chart|safe }}
                </div>
            </div>
        </div>
        
        <!-- Findings -->
        <h2 class="section-header">Findings</h2>
        {% for finding in report.findings %}
        <div class="finding-card card">
            <div class="finding-header">
                <h5 class="mb-0">{{ finding.title }}</h5>
                <span class="severity-badge severity-{{ finding.severity.value }}">
                    {{ finding.severity.value|upper }}
                </span>
            </div>
            <div class="card-body">
                <p class="card-text">{{ finding.description }}</p>
                {% if finding.cvss_score %}
                <p><strong>CVSS Score:</strong> {{ finding.cvss_score }}</p>
                {% endif %}
                {% if finding.remediation %}
                <div class="mt-3">
                    <h6>Remediation</h6>
                    <p>{{ finding.remediation }}</p>
                </div>
                {% endif %}
                {% if finding.references %}
                <div class="mt-3">
                    <h6>References</h6>
                    <ul>
                    {% for ref in finding.references %}
                        <li><a href="{{ ref }}" target="_blank">{{ ref }}</a></li>
                    {% endfor %}
                    </ul>
                </div>
                {% endif %}
            </div>
        </div>
        {% endfor %}
        
        <!-- Host Details -->
        <h2 class="section-header">Host Details</h2>
        <div class="row">
        {% for host in report.hosts %}
            <div class="col-md-6 mb-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">{{ host.ip }}</h5>
                        {% if host.hostname %}
                        <p><strong>Hostname:</strong> {{ host.hostname }}</p>
                        {% endif %}
                        <h6 class="mt-3">Open Ports</h6>
                        <ul class="list-unstyled">
                        {% for port in host.ports %}
                            <li>
                                <span class="badge bg-secondary">{{ port.port }}/{{ port.protocol }}</span>
                                {% if port.service %}
                                <span>{{ port.service }}</span>
                                {% endif %}
                            </li>
                        {% endfor %}
                        </ul>
                    </div>
                </div>
            </div>
        {% endfor %}
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""