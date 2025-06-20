package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ajaikumarvs/harbinger/internal/export"
	"github.com/ajaikumarvs/harbinger/internal/storage"
	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// ResultsModel represents the scan results view
type ResultsModel struct {
	result         models.ScanResult
	table          table.Model
	activeTab      int
	tabs           []string
	exportManager  *export.ExportManager
	storageManager *storage.StorageManager
	width          int
	height         int
}

// NewResultsModel creates a new results model
func NewResultsModel(result models.ScanResult) ResultsModel {
	// Initialize export manager
	exportConfig := export.ExportConfig{
		CompanyName:       "Harbinger Security",
		IncludeCharts:     true,
		IncludeAIAnalysis: true,
	}
	exportManager := export.NewExportManager(exportConfig)

	// Initialize storage manager
	storageManager, _ := storage.NewStorageManager()
	// Create table for vulnerabilities
	columns := []table.Column{
		{Title: "CVE", Width: 15},
		{Title: "Severity", Width: 10},
		{Title: "Score", Width: 8},
		{Title: "Description", Width: 40},
	}

	rows := []table.Row{}
	for _, vuln := range result.Vulnerabilities {
		rows = append(rows, table.Row{
			vuln.CVE,
			vuln.Severity,
			fmt.Sprintf("%.1f", vuln.Score),
			vuln.Description,
		})
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(10),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	return ResultsModel{
		result:         result,
		table:          t,
		activeTab:      0,
		tabs:           []string{"Overview", "Vulnerabilities", "Technologies", "AI Analysis", "Export"},
		exportManager:  exportManager,
		storageManager: storageManager,
	}
}

// Init implements tea.Model
func (m ResultsModel) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model
func (m ResultsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			// Go back to main menu
			return NewMainMenuModel(), nil
		case "tab":
			m.activeTab = (m.activeTab + 1) % len(m.tabs)
		case "shift+tab":
			m.activeTab = (m.activeTab - 1 + len(m.tabs)) % len(m.tabs)
		}
	}

	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

// View implements tea.Model
func (m ResultsModel) View() string {
	// Header
	header := headerStyle.Render("📊 Scan Results")

	// Tab bar
	tabBar := m.renderTabs()

	// Content based on active tab
	var content string
	switch m.activeTab {
	case 0:
		content = m.renderOverview()
	case 1:
		content = m.renderVulnerabilities()
	case 2:
		content = m.renderTechnologies()
	case 3:
		content = m.renderAIAnalysis()
	case 4:
		content = m.renderExport()
	}

	// Help text
	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Tab/Shift+Tab to switch tabs • ESC for main menu • Ctrl+C to quit")

	// Combine all parts
	full := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		tabBar,
		content,
		help,
	)

	return full
}

func (m ResultsModel) renderTabs() string {
	var tabs []string
	for i, tab := range m.tabs {
		if i == m.activeTab {
			tabs = append(tabs, focusedStyle.Render(fmt.Sprintf("[%s]", tab)))
		} else {
			tabs = append(tabs, blurredStyle.Render(tab))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, tabs...)
}

func (m ResultsModel) renderOverview() string {
	// Security score with color coding
	var scoreColor lipgloss.Color
	switch {
	case m.result.SecurityScore >= 80:
		scoreColor = successColor
	case m.result.SecurityScore >= 60:
		scoreColor = warningColor
	default:
		scoreColor = errorColor
	}

	scoreStyle := lipgloss.NewStyle().
		Foreground(scoreColor).
		Bold(true)

	overview := lipgloss.NewStyle().
		Margin(1, 0).
		Render(fmt.Sprintf(
			"Target: %s\n"+
				"Scan Date: %s\n"+
				"Duration: %v\n"+
				"Security Score: %s\n"+
				"Technologies: %d\n"+
				"Vulnerabilities: %d",
			m.result.URL,
			m.result.Timestamp.Format("2006-01-02 15:04:05"),
			m.result.ScanDuration.Round(1),
			scoreStyle.Render(fmt.Sprintf("%d/100", m.result.SecurityScore)),
			len(m.result.TechStack),
			len(m.result.Vulnerabilities),
		))

	return overview
}

func (m ResultsModel) renderVulnerabilities() string {
	if len(m.result.Vulnerabilities) == 0 {
		return lipgloss.NewStyle().
			Foreground(successColor).
			Margin(1, 0).
			Render("🎉 No vulnerabilities found!")
	}

	return lipgloss.NewStyle().
		Margin(1, 0).
		Render(m.table.View())
}

func (m ResultsModel) renderTechnologies() string {
	if len(m.result.TechStack) == 0 {
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262")).
			Margin(1, 0).
			Render("No technologies detected.")
	}

	var techList []string
	for _, tech := range m.result.TechStack {
		confidence := fmt.Sprintf("%.0f%%", tech.Confidence*100)
		techList = append(techList, fmt.Sprintf(
			"• %s %s (%s) - %s confidence",
			tech.Name,
			tech.Version,
			tech.Category,
			confidence,
		))
	}

	return lipgloss.NewStyle().
		Margin(1, 0).
		Render(lipgloss.JoinVertical(lipgloss.Left, techList...))
}

func (m ResultsModel) renderAIAnalysis() string {
	// Check if AI analysis is available
	if m.result.AIAnalysis.ExecutiveSummary == "" &&
		m.result.AIAnalysis.TechnicalAnalysis == "" &&
		len(m.result.AIAnalysis.RootCauseAnalysis) == 0 {
		// No AI analysis available
		aiContent := lipgloss.NewStyle().
			Margin(1, 0).
			Render(
				"🤖 AI Analysis\n\n" +
					"AI analysis is not available for this scan.\n\n" +
					"To enable AI analysis:\n" +
					"• Configure an AI provider in Settings → API Keys\n" +
					"• Supported providers: Google Gemini, OpenAI, Claude\n" +
					"• Test your API key connection\n" +
					"• Re-run the scan to get AI-powered insights\n\n" +
					"💡 AI analysis provides:\n" +
					"• Executive summaries for business stakeholders\n" +
					"• Technical analysis and remediation guidance\n" +
					"• Root cause analysis and prevention strategies\n" +
					"• Business impact assessments\n" +
					"• Compliance gap identification\n" +
					"• Educational security insights",
			)
		return aiContent
	}

	// Build AI analysis content
	var content strings.Builder

	// Header
	content.WriteString("🤖 AI-Powered Security Analysis\n\n")

	// Executive Summary
	if m.result.AIAnalysis.ExecutiveSummary != "" {
		content.WriteString("📊 EXECUTIVE SUMMARY\n")
		content.WriteString(strings.Repeat("─", 50) + "\n")
		content.WriteString(m.result.AIAnalysis.ExecutiveSummary + "\n\n")
	}

	// Technical Analysis
	if m.result.AIAnalysis.TechnicalAnalysis != "" {
		content.WriteString("🔧 TECHNICAL ANALYSIS\n")
		content.WriteString(strings.Repeat("─", 50) + "\n")
		content.WriteString(m.result.AIAnalysis.TechnicalAnalysis + "\n\n")
	}

	// Root Cause Analysis
	if len(m.result.AIAnalysis.RootCauseAnalysis) > 0 {
		content.WriteString("🔍 ROOT CAUSE ANALYSIS\n")
		content.WriteString(strings.Repeat("─", 50) + "\n")
		for category, analysis := range m.result.AIAnalysis.RootCauseAnalysis {
			if category != "general" {
				content.WriteString(fmt.Sprintf("• %s: %s\n", strings.Title(category), analysis))
			} else {
				content.WriteString(analysis + "\n")
			}
		}
		content.WriteString("\n")
	}

	// Remediation Plan
	if len(m.result.AIAnalysis.RemediationPlan) > 0 {
		content.WriteString("🛠️ REMEDIATION PLAN\n")
		content.WriteString(strings.Repeat("─", 50) + "\n")
		for _, step := range m.result.AIAnalysis.RemediationPlan {
			content.WriteString(fmt.Sprintf("Priority %d: %s\n", step.Priority, step.Description))
			content.WriteString(fmt.Sprintf("  Impact: %s\n", step.Impact))
			content.WriteString(fmt.Sprintf("  Effort: %s | Timeline: %s\n\n", step.Effort, step.Timeline))
		}
	}

	// Business Impact
	if m.result.AIAnalysis.BusinessImpact.BusinessImpact != "" {
		content.WriteString("💼 BUSINESS IMPACT ASSESSMENT\n")
		content.WriteString(strings.Repeat("─", 50) + "\n")
		content.WriteString(fmt.Sprintf("Overall Risk: %s\n", m.result.AIAnalysis.BusinessImpact.OverallRisk))
		content.WriteString(m.result.AIAnalysis.BusinessImpact.BusinessImpact + "\n\n")
	}

	// Compliance Gaps
	if len(m.result.AIAnalysis.ComplianceGaps) > 0 {
		content.WriteString("⚖️ COMPLIANCE ANALYSIS\n")
		content.WriteString(strings.Repeat("─", 50) + "\n")
		for _, gap := range m.result.AIAnalysis.ComplianceGaps {
			content.WriteString(fmt.Sprintf("Framework: %s\n", gap.Framework))
			if gap.Requirement != "" {
				content.WriteString(fmt.Sprintf("Requirement: %s\n", gap.Requirement))
			}
			content.WriteString(fmt.Sprintf("Gap: %s\n", gap.Gap))
			if gap.Remediation != "" {
				content.WriteString(fmt.Sprintf("Remediation: %s\n", gap.Remediation))
			}
			content.WriteString("\n")
		}
	}

	// Educational Insights
	if len(m.result.AIAnalysis.EducationalInsights) > 0 {
		content.WriteString("🎓 EDUCATIONAL INSIGHTS\n")
		content.WriteString(strings.Repeat("─", 50) + "\n")
		for _, insight := range m.result.AIAnalysis.EducationalInsights {
			content.WriteString(fmt.Sprintf("Topic: %s\n", insight.Topic))
			content.WriteString(insight.Explanation + "\n")
			if insight.BestPractice != "" {
				content.WriteString(fmt.Sprintf("Best Practice: %s\n", insight.BestPractice))
			}
			content.WriteString("\n")
		}
	}

	// Add scrolling hint if content is long
	aiContent := content.String()
	if len(aiContent) > 1000 {
		aiContent += "\n💡 Use ↑/↓ arrows to scroll through the analysis"
	}

	return lipgloss.NewStyle().
		Margin(1, 0).
		Render(aiContent)
}

func (m ResultsModel) renderExport() string {
	var content strings.Builder

	content.WriteString("📄 Export Report\n\n")

	content.WriteString("Available Export Formats:\n")
	content.WriteString("• PDF - Professional report with formatting\n")
	content.WriteString("• DOCX - Microsoft Word format\n")
	content.WriteString("• JSON - Raw data export\n\n")

	content.WriteString("Export Options:\n")
	content.WriteString("• Executive Summary - High-level overview\n")
	content.WriteString("• Technical Report - Detailed technical analysis\n")
	content.WriteString("• Compliance Report - Regulatory compliance focused\n\n")

	content.WriteString("Performance Metrics:\n")
	content.WriteString(fmt.Sprintf("• Scan Duration: %v\n", m.result.ScanDuration.Round(time.Millisecond)))
	content.WriteString(fmt.Sprintf("• Scanners Used: %s\n", strings.Join(m.result.ScannersUsed, ", ")))
	if len(m.result.APICallsUsed) > 0 {
		content.WriteString("• AI API Calls: ")
		var apiUsage []string
		for provider, count := range m.result.APICallsUsed {
			apiUsage = append(apiUsage, fmt.Sprintf("%s (%d)", provider, count))
		}
		content.WriteString(strings.Join(apiUsage, ", ") + "\n")
	}
	content.WriteString("\n")

	content.WriteString("📊 Quick Actions:\n")
	content.WriteString("• Press 'e' to export as PDF\n")
	content.WriteString("• Press 'd' to export as DOCX\n")
	content.WriteString("• Press 'j' to export as JSON\n")
	content.WriteString("• Press 's' to save to database\n\n")

	// Storage information
	if m.storageManager != nil {
		stats, err := m.storageManager.GetStorageStats()
		if err == nil {
			content.WriteString("💾 Storage Information:\n")
			content.WriteString(fmt.Sprintf("• Total Scans Stored: %d\n", stats.TotalScans))
			content.WriteString(fmt.Sprintf("• Database Size: %s\n", humanizeBytes(stats.TotalSize)))
			content.WriteString(fmt.Sprintf("• Data Directory: %s\n", stats.DatabasePath))
		}
	}

	return lipgloss.NewStyle().
		Margin(1, 0).
		Render(content.String())
}

// Helper function to humanize byte sizes
func humanizeBytes(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	} else if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
}
