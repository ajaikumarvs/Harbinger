package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// HelpModel represents the help screen
type HelpModel struct {
	width  int
	height int
}

// NewHelpModel creates a new help model
func NewHelpModel() HelpModel {
	return HelpModel{}
}

// Init implements tea.Model
func (m HelpModel) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model
func (m HelpModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc", "enter", "q":
			// Go back to main menu
			return NewMainMenuModel(), nil
		}
	}

	return m, nil
}

// View implements tea.Model
func (m HelpModel) View() string {
	// Header
	header := headerStyle.Render("❓ Help & Documentation")

	// Help content
	helpContent := lipgloss.NewStyle().
		Margin(1, 0).
		Render(`🛡️  Harbinger Security Scanner

OVERVIEW:
Harbinger is a comprehensive CLI security scanning tool that combines
local scanning capabilities with AI-powered analysis to provide deep
insights into your application's security posture.

MAIN FEATURES:
• 🔍 Comprehensive Security Scanning
  - Port scanning and service detection
  - Technology stack identification
  - SSL/TLS analysis
  - Security header assessment
  - Directory and file discovery
  - DNS analysis and subdomain enumeration

• 🤖 AI-Powered Analysis
  - Executive summaries and technical analysis
  - Root cause analysis for vulnerabilities
  - Future threat predictions
  - Business impact assessments
  - Compliance gap analysis
  - Educational security insights

• 📊 Professional Reporting
  - Interactive TUI results navigation
  - PDF and DOCX export capabilities
  - Customizable report templates
  - Charts and visual data representation

• 📚 History Management
  - Persistent scan result storage
  - Search and filter capabilities
  - Comparison between scans

GETTING STARTED:
1. Configure API keys in Settings for AI analysis
2. Select "Scan" from the main menu
3. Enter your target URL
4. Watch the live scanning progress
5. Review results and AI insights
6. Export reports as needed

NAVIGATION:
• Arrow keys or j/k - Navigate menus
• Enter - Select/confirm
• Tab/Shift+Tab - Switch between tabs
• ESC - Go back/cancel
• Ctrl+C - Quit application

SUPPORTED AI PROVIDERS:
• Google Gemini (Recommended)
• OpenAI GPT-4/GPT-3.5
• Anthropic Claude
• Custom API endpoints

API KEYS:
API keys are stored securely and encrypted at rest. Configure them
in Settings > API Keys to enable advanced AI analysis features.

SCAN TYPES:
• Quick Scan - Basic security assessment (2-5 minutes)
• Standard Scan - Comprehensive analysis (5-15 minutes)
• Deep Scan - Extensive scanning with AI analysis (15-30 minutes)

For more information, visit: github.com/ajaikumarvs/harbinger`)

	// Help text
	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(2, 0).
		Render("Press ESC, Enter, or Q to return to main menu • Ctrl+C to quit")

	// Combine all parts
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		helpContent,
		help,
	)

	return content
}
