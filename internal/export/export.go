package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// SimpleExportManager provides basic export functionality
type SimpleExportManager struct {
	config ExportConfig
}

// ExportConfig represents export configuration
type ExportConfig struct {
	CompanyName       string
	CompanyLogo       string
	IncludeCharts     bool
	IncludeAIAnalysis bool
	ReportTemplate    string
}

// ExportFormat represents different export formats
type ExportFormat string

const (
	FormatPDF  ExportFormat = "pdf"
	FormatDOCX ExportFormat = "docx"
	FormatJSON ExportFormat = "json"
	FormatTXT  ExportFormat = "txt"
)

// ExportManager is an alias for SimpleExportManager for compatibility
type ExportManager = SimpleExportManager

// NewExportManager creates a new export manager
func NewExportManager(config ExportConfig) *ExportManager {
	return &ExportManager{
		config: config,
	}
}

// ExportReport exports a scan result to the specified format
func (em *SimpleExportManager) ExportReport(result *models.ScanResult, format ExportFormat, outputPath string) error {
	switch format {
	case FormatJSON:
		return em.exportToJSON(result, outputPath)
	case FormatTXT:
		return em.exportToText(result, outputPath)
	default:
		return fmt.Errorf("export format %s not yet implemented", format)
	}
}

// exportToJSON exports scan result as JSON
func (em *SimpleExportManager) exportToJSON(result *models.ScanResult, outputPath string) error {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	return os.WriteFile(outputPath, buf.Bytes(), 0644)
}

// exportToText exports scan result as plain text
func (em *SimpleExportManager) exportToText(result *models.ScanResult, outputPath string) error {
	var content strings.Builder

	content.WriteString("HARBINGER SECURITY ASSESSMENT REPORT\n")
	content.WriteString("=====================================\n\n")

	if em.config.CompanyName != "" {
		content.WriteString(fmt.Sprintf("Prepared by: %s\n", em.config.CompanyName))
	}

	content.WriteString(fmt.Sprintf("Target: %s\n", result.URL))
	content.WriteString(fmt.Sprintf("Scan Date: %s\n", result.Timestamp.Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("Report Generated: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("Security Score: %d/100\n", result.SecurityScore))
	content.WriteString(fmt.Sprintf("Scan Duration: %v\n", result.ScanDuration.Round(time.Second)))
	content.WriteString("\n")

	// Executive Summary
	if result.AIAnalysis.ExecutiveSummary != "" {
		content.WriteString("EXECUTIVE SUMMARY\n")
		content.WriteString("-----------------\n")
		content.WriteString(result.AIAnalysis.ExecutiveSummary)
		content.WriteString("\n\n")
	}

	// Overview
	content.WriteString("SCAN OVERVIEW\n")
	content.WriteString("-------------\n")
	content.WriteString(fmt.Sprintf("Technologies Detected: %d\n", len(result.TechStack)))
	content.WriteString(fmt.Sprintf("Vulnerabilities Found: %d\n", len(result.Vulnerabilities)))
	content.WriteString(fmt.Sprintf("Scanners Used: %s\n", strings.Join(result.ScannersUsed, ", ")))
	content.WriteString("\n")

	// Technology Stack
	if len(result.TechStack) > 0 {
		content.WriteString("TECHNOLOGY STACK\n")
		content.WriteString("----------------\n")
		for _, tech := range result.TechStack {
			content.WriteString(fmt.Sprintf("• %s %s (%s) - %.1f%% confidence\n",
				tech.Name, tech.Version, tech.Category, tech.Confidence*100))
		}
		content.WriteString("\n")
	}

	// Vulnerabilities
	content.WriteString("VULNERABILITIES\n")
	content.WriteString("---------------\n")
	if len(result.Vulnerabilities) == 0 {
		content.WriteString("No vulnerabilities detected.\n")
	} else {
		for i, vuln := range result.Vulnerabilities {
			content.WriteString(fmt.Sprintf("%d. %s - %s (Score: %.1f)\n",
				i+1, vuln.CVE, vuln.Severity, vuln.Score))
			content.WriteString(fmt.Sprintf("   Description: %s\n", vuln.Description))
			if vuln.Remediation != "" {
				content.WriteString(fmt.Sprintf("   Remediation: %s\n", vuln.Remediation))
			}
			content.WriteString("\n")
		}
	}

	// AI Analysis
	if em.config.IncludeAIAnalysis && result.AIAnalysis.TechnicalAnalysis != "" {
		content.WriteString("TECHNICAL ANALYSIS\n")
		content.WriteString("------------------\n")
		content.WriteString(result.AIAnalysis.TechnicalAnalysis)
		content.WriteString("\n\n")
	}

	// Remediation Plan
	if len(result.AIAnalysis.RemediationPlan) > 0 {
		content.WriteString("REMEDIATION PLAN\n")
		content.WriteString("----------------\n")
		for i, step := range result.AIAnalysis.RemediationPlan {
			content.WriteString(fmt.Sprintf("%d. %s\n", i+1, step.Description))
			content.WriteString(fmt.Sprintf("   Priority: %d | Impact: %s | Effort: %s | Timeline: %s\n",
				step.Priority, step.Impact, step.Effort, step.Timeline))
			content.WriteString("\n")
		}
	}

	// Recommendations
	content.WriteString("RECOMMENDATIONS\n")
	content.WriteString("---------------\n")
	content.WriteString("1. Regularly update all software components to the latest versions\n")
	content.WriteString("2. Implement comprehensive security monitoring and logging\n")
	content.WriteString("3. Conduct periodic security assessments and penetration testing\n")
	content.WriteString("4. Establish incident response procedures\n")
	content.WriteString("5. Provide security awareness training for all personnel\n\n")

	content.WriteString("---\n")
	content.WriteString(fmt.Sprintf("Report generated by Harbinger Security Scanner on %s\n",
		time.Now().Format("2006-01-02 15:04:05")))

	return os.WriteFile(outputPath, []byte(content.String()), 0644)
}

// GenerateReportName creates a standardized report filename
func GenerateReportName(result *models.ScanResult, format ExportFormat) string {
	timestamp := result.Timestamp.Format("2006-01-02_15-04-05")
	domain := strings.ReplaceAll(result.URL, "https://", "")
	domain = strings.ReplaceAll(domain, "http://", "")
	domain = strings.ReplaceAll(domain, "/", "_")

	return fmt.Sprintf("harbinger_report_%s_%s.%s", domain, timestamp, string(format))
}
