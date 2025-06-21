package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"

	"github.com/ajaikumarvs/harbinger/internal/export"
	"github.com/ajaikumarvs/harbinger/internal/storage"
	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// ResultsModel represents the scan results view
type ResultsModel struct {
	result           models.ScanResult
	table            table.Model
	activeTab        int
	tabs             []string
	exportManager    *export.ExportManager
	storageManager   *storage.StorageManager
	width            int
	height           int
	aiViewport       viewport.Model
	aiActiveSection  int
	aiSections       []aiSection
	markdownRenderer *glamour.TermRenderer
}

// aiSection represents a section in the AI analysis
type aiSection struct {
	Title   string
	Content string
	Icon    string
}

// buildAISections creates AI analysis sections from the report
func buildAISections(analysis models.AIReport) []aiSection {
	var sections []aiSection

	// Executive Summary
	if analysis.ExecutiveSummary != "" {
		sections = append(sections, aiSection{
			Title:   "Executive Summary",
			Content: formatMarkdownSection("Executive Summary", analysis.ExecutiveSummary, "📊"),
			Icon:    "📊",
		})
	}

	// Technical Analysis
	if analysis.TechnicalAnalysis != "" {
		sections = append(sections, aiSection{
			Title:   "Technical Analysis",
			Content: formatMarkdownSection("Technical Analysis", analysis.TechnicalAnalysis, "🔧"),
			Icon:    "🔧",
		})
	}

	// Root Cause Analysis
	if len(analysis.RootCauseAnalysis) > 0 {
		var content strings.Builder
		content.WriteString("# 🔍 Root Cause Analysis\n\n")
		for category, analysis := range analysis.RootCauseAnalysis {
			if category != "general" {
				content.WriteString(fmt.Sprintf("## %s\n\n%s\n\n", strings.Title(category), analysis))
			} else {
				content.WriteString(fmt.Sprintf("%s\n\n", analysis))
			}
		}
		sections = append(sections, aiSection{
			Title:   "Root Cause Analysis",
			Content: content.String(),
			Icon:    "🔍",
		})
	}

	// Remediation Plan
	if len(analysis.RemediationPlan) > 0 {
		var content strings.Builder
		content.WriteString("# 🛠️ Remediation Plan\n\n")
		for _, step := range analysis.RemediationPlan {
			content.WriteString(fmt.Sprintf("## Priority %d\n\n", step.Priority))
			content.WriteString(fmt.Sprintf("**Description:** %s\n\n", step.Description))
			content.WriteString(fmt.Sprintf("**Impact:** %s\n\n", step.Impact))
			content.WriteString(fmt.Sprintf("**Effort:** %s | **Timeline:** %s\n\n", step.Effort, step.Timeline))
			content.WriteString("---\n\n")
		}
		sections = append(sections, aiSection{
			Title:   "Remediation Plan",
			Content: content.String(),
			Icon:    "🛠️",
		})
	}

	// Business Impact
	if analysis.BusinessImpact.BusinessImpact != "" {
		var content strings.Builder
		content.WriteString("# 💼 Business Impact Assessment\n\n")
		content.WriteString(fmt.Sprintf("**Overall Risk:** %s\n\n", analysis.BusinessImpact.OverallRisk))
		content.WriteString(fmt.Sprintf("%s\n\n", analysis.BusinessImpact.BusinessImpact))
		if analysis.BusinessImpact.FinancialImpact != "" {
			content.WriteString(fmt.Sprintf("**Financial Impact:** %s\n\n", analysis.BusinessImpact.FinancialImpact))
		}
		if analysis.BusinessImpact.ReputationRisk != "" {
			content.WriteString(fmt.Sprintf("**Reputation Risk:** %s\n\n", analysis.BusinessImpact.ReputationRisk))
		}
		sections = append(sections, aiSection{
			Title:   "Business Impact",
			Content: content.String(),
			Icon:    "💼",
		})
	}

	// Compliance Gaps
	if len(analysis.ComplianceGaps) > 0 {
		var content strings.Builder
		content.WriteString("# ⚖️ Compliance Analysis\n\n")
		for _, gap := range analysis.ComplianceGaps {
			content.WriteString(fmt.Sprintf("## %s\n\n", gap.Framework))
			if gap.Requirement != "" {
				content.WriteString(fmt.Sprintf("**Requirement:** %s\n\n", gap.Requirement))
			}
			content.WriteString(fmt.Sprintf("**Gap:** %s\n\n", gap.Gap))
			if gap.Remediation != "" {
				content.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", gap.Remediation))
			}
			content.WriteString("---\n\n")
		}
		sections = append(sections, aiSection{
			Title:   "Compliance Analysis",
			Content: content.String(),
			Icon:    "⚖️",
		})
	}

	// Educational Insights
	if len(analysis.EducationalInsights) > 0 {
		var content strings.Builder
		content.WriteString("# 🎓 Educational Insights\n\n")
		for _, insight := range analysis.EducationalInsights {
			content.WriteString(fmt.Sprintf("## %s\n\n", insight.Topic))
			content.WriteString(fmt.Sprintf("%s\n\n", insight.Explanation))
			if insight.BestPractice != "" {
				content.WriteString(fmt.Sprintf("**Best Practice:** %s\n\n", insight.BestPractice))
			}
			if len(insight.References) > 0 {
				content.WriteString("**References:**\n")
				for _, ref := range insight.References {
					content.WriteString(fmt.Sprintf("- %s\n", ref))
				}
				content.WriteString("\n")
			}
			content.WriteString("---\n\n")
		}
		sections = append(sections, aiSection{
			Title:   "Educational Insights",
			Content: content.String(),
			Icon:    "🎓",
		})
	}

	return sections
}

// formatMarkdownSection formats a simple markdown section
func formatMarkdownSection(title, content, icon string) string {
	return fmt.Sprintf("# %s %s\n\n%s\n\n", icon, title, content)
}

// updateAIContent updates the AI viewport with the current section content
func (m *ResultsModel) updateAIContent() {
	if len(m.aiSections) == 0 || m.aiActiveSection >= len(m.aiSections) {
		m.aiViewport.SetContent("No AI analysis available")
		return
	}

	section := m.aiSections[m.aiActiveSection]
	renderedContent, err := m.markdownRenderer.Render(section.Content)
	if err != nil {
		// Fallback to plain text if markdown rendering fails
		m.aiViewport.SetContent(section.Content)
	} else {
		m.aiViewport.SetContent(renderedContent)
	}
	m.aiViewport.GotoTop()
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

	// Initialize markdown renderer with dark theme
	renderer, _ := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(80),
	)

	// Initialize viewport for AI analysis
	vp := viewport.New(80, 20)
	vp.Style = lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		PaddingRight(2)

	return ResultsModel{
		result:           result,
		table:            t,
		activeTab:        0,
		tabs:             []string{"Overview", "Vulnerabilities", "Technologies", "AI Analysis", "Export"},
		exportManager:    exportManager,
		storageManager:   storageManager,
		aiViewport:       vp,
		aiActiveSection:  0,
		aiSections:       buildAISections(result.AIAnalysis),
		markdownRenderer: renderer,
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

		// Update AI viewport size
		headerHeight := 6 // Header + tabs + margins
		footerHeight := 3 // Help text
		contentHeight := msg.Height - headerHeight - footerHeight
		m.aiViewport.Width = msg.Width - 4      // Account for margins
		m.aiViewport.Height = contentHeight - 2 // Account for section selector

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

		// Handle AI Analysis tab navigation
		if m.activeTab == 3 && len(m.aiSections) > 0 { // AI Analysis tab
			switch msg.String() {
			case "left", "h":
				if m.aiActiveSection > 0 {
					m.aiActiveSection--
					m.updateAIContent()
				}
			case "right", "l":
				if m.aiActiveSection < len(m.aiSections)-1 {
					m.aiActiveSection++
					m.updateAIContent()
				}
			case "up", "k":
				m.aiViewport.LineUp(1)
			case "down", "j":
				m.aiViewport.LineDown(1)
			case "pgup":
				m.aiViewport.HalfViewUp()
			case "pgdown":
				m.aiViewport.HalfViewDown()
			case "home":
				m.aiViewport.GotoTop()
			case "end":
				m.aiViewport.GotoBottom()
			}
		}
	}

	// Update models based on active tab
	switch m.activeTab {
	case 1: // Vulnerabilities tab
		m.table, cmd = m.table.Update(msg)
	case 3: // AI Analysis tab
		m.aiViewport, cmd = m.aiViewport.Update(msg)
	}

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
	var helpText string
	if m.activeTab == 3 && len(m.aiSections) > 0 { // AI Analysis tab
		helpText = "Tab/Shift+Tab: switch tabs • ← →/h l: AI sections • ↑ ↓/j k: scroll • ESC: main menu • Ctrl+C: quit"
	} else {
		helpText = "Tab/Shift+Tab to switch tabs • ESC for main menu • Ctrl+C to quit"
	}

	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render(helpText)

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
	if len(m.aiSections) == 0 {
		// No AI analysis available
		noAIContent := lipgloss.NewStyle().
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
		return noAIContent
	}

	// Ensure we have content in the viewport
	if m.aiViewport.Width == 0 {
		// Initialize viewport with current content
		m.updateAIContent()
	}

	// Section selector
	sectionSelector := m.renderSectionSelector()

	// Main content area
	viewportContent := m.aiViewport.View()

	// Navigation help
	navHelp := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Render("← → / h l: Switch sections • ↑ ↓ / j k: Scroll • PgUp/PgDn: Page scroll • Home/End: Top/Bottom")

	// Combine all parts
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		sectionSelector,
		viewportContent,
		navHelp,
	)

	return content
}

// renderSectionSelector renders the section navigation bar
func (m ResultsModel) renderSectionSelector() string {
	if len(m.aiSections) == 0 {
		return ""
	}

	var sections []string
	for i, section := range m.aiSections {
		sectionName := fmt.Sprintf("%s %s", section.Icon, section.Title)
		if i == m.aiActiveSection {
			sections = append(sections, focusedStyle.Render(fmt.Sprintf("[%s]", sectionName)))
		} else {
			sections = append(sections, blurredStyle.Render(sectionName))
		}
	}

	selectorStyle := lipgloss.NewStyle().
		Margin(0, 0, 1, 0).
		Padding(0, 1)

	return selectorStyle.Render(lipgloss.JoinHorizontal(lipgloss.Top, sections...))
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
