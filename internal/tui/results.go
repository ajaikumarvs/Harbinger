package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// ResultsModel represents the scan results view
type ResultsModel struct {
	result    models.ScanResult
	table     table.Model
	activeTab int
	tabs      []string
	width     int
	height    int
}

// NewResultsModel creates a new results model
func NewResultsModel(result models.ScanResult) ResultsModel {
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
		result:    result,
		table:     t,
		activeTab: 0,
		tabs:      []string{"Overview", "Vulnerabilities", "Technologies", "AI Analysis"},
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
	// Placeholder for AI analysis
	aiContent := lipgloss.NewStyle().
		Margin(1, 0).
		Render(
			"🤖 AI Analysis\n\n" +
				"Executive Summary:\n" +
				"This scan reveals a moderate security posture with several areas for improvement.\n\n" +
				"Key Recommendations:\n" +
				"• Update outdated components\n" +
				"• Implement security headers\n" +
				"• Review SSL/TLS configuration\n\n" +
				"Note: Full AI analysis requires API key configuration.",
		)

	return aiContent
}
