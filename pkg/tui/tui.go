package tui

import (
	"context"
	"fmt"
	"time"

	"github.com/ajaikumarvs/harbinger/internal/models"
	"github.com/ajaikumarvs/harbinger/pkg/scanner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// RunScanTUI starts the TUI for scanning
func RunScanTUI(target string, config interface{}) error {
	p := tea.NewProgram(NewScanModel(target), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// ScanModel represents the TUI model for scanning
type ScanModel struct {
	target   string
	status   *models.ScanStatus
	result   *models.ScanResult
	scanner  *scanner.Scanner
	ctx      context.Context
	cancel   context.CancelFunc
	width    int
	height   int
	scanning bool
	done     bool
	err      error
}

// NewScanModel creates a new scan model
func NewScanModel(target string) *ScanModel {
	ctx, cancel := context.WithCancel(context.Background())
	return &ScanModel{
		target:  target,
		status:  &models.ScanStatus{StartTime: time.Now()},
		scanner: scanner.New(),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Init initializes the model
func (m *ScanModel) Init() tea.Cmd {
	return tea.Batch(
		m.startScan(),
		m.tickCmd(),
	)
}

// Update handles messages
func (m *ScanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.cancel()
			return m, tea.Quit
		case "r":
			if m.done {
				// Restart scan
				m.done = false
				m.scanning = false
				m.err = nil
				m.status = &models.ScanStatus{StartTime: time.Now()}
				m.result = nil
				ctx, cancel := context.WithCancel(context.Background())
				m.ctx = ctx
				m.cancel = cancel
				return m, tea.Batch(m.startScan(), m.tickCmd())
			}
		}

	case scanStartMsg:
		m.scanning = true
		m.status.Phase = models.PhaseInitializing
		m.status.Message = "Starting vulnerability scan..."
		return m, m.performScan()

	case scanUpdateMsg:
		m.status = msg.status
		return m, nil

	case scanCompleteMsg:
		m.scanning = false
		m.done = true
		m.result = msg.result
		m.status.Phase = models.PhaseComplete
		m.status.Progress = 100
		m.status.Message = "Scan completed successfully!"
		return m, nil

	case scanErrorMsg:
		m.scanning = false
		m.done = true
		m.err = msg.err
		m.status.Phase = models.PhaseError
		m.status.Message = fmt.Sprintf("Scan failed: %v", msg.err)
		return m, nil

	case tickMsg:
		if m.scanning {
			m.status.ElapsedTime = time.Since(m.status.StartTime)
			return m, m.tickCmd()
		}
		return m, nil
	}

	return m, nil
}

// View renders the TUI
func (m *ScanModel) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	var content string

	// Header
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("205")).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(0, 1).
		Width(m.width - 4)

	header := headerStyle.Render(fmt.Sprintf("🔍 Harbinger - Vulnerability Scanner\nTarget: %s", m.target))

	if m.scanning {
		content = m.renderScanProgress()
	} else if m.done {
		if m.err != nil {
			content = m.renderError()
		} else {
			content = m.renderResults()
		}
	} else {
		content = "Initializing scan..."
	}

	// Footer
	var footer string
	if m.scanning {
		footer = "Press 'q' or Ctrl+C to quit"
	} else if m.done {
		if m.err == nil {
			footer = "Press 'r' to restart scan, 'q' to quit"
		} else {
			footer = "Press 'r' to retry scan, 'q' to quit"
		}
	}

	footerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Align(lipgloss.Center).
		Width(m.width)

	return lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		"",
		content,
		"",
		footerStyle.Render(footer),
	)
}

func (m *ScanModel) renderScanProgress() string {
	if m.status == nil {
		return "Starting scan..."
	}

	// Create progress bar
	progressWidth := 50
	filledWidth := int(float64(progressWidth) * m.status.Progress / 100)

	progressBar := "["
	for i := 0; i < progressWidth; i++ {
		if i < filledWidth {
			progressBar += "█"
		} else {
			progressBar += "░"
		}
	}
	progressBar += "]"

	progressStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("205")).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(1, 2)

	content := fmt.Sprintf("Phase: %s\n\n%s %.1f%%\n\nStatus: %s",
		m.status.Phase,
		progressBar,
		m.status.Progress,
		m.status.Message)

	if !m.status.StartTime.IsZero() {
		elapsed := m.status.ElapsedTime.Truncate(time.Second)
		content += fmt.Sprintf("\nElapsed: %s", elapsed)
	}

	return progressStyle.Render(content)
}

func (m *ScanModel) renderError() string {
	errorStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("196")).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("196")).
		Padding(1, 2)

	return errorStyle.Render(fmt.Sprintf("❌ Scan failed:\n%v", m.err))
}

func (m *ScanModel) renderResults() string {
	if m.result == nil {
		return "No results available"
	}

	resultStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(1, 2)

	// Create sections for different result types
	sections := []string{}

	// Summary section
	summary := fmt.Sprintf("✅ Scan completed successfully!\n\n")
	summary += fmt.Sprintf("🎯 Target: %s\n", m.result.Target)
	summary += fmt.Sprintf("⏱️  Duration: %s\n", m.result.Duration.Truncate(time.Second))

	if m.result.Score != nil {
		gradeColor := getGradeColor(m.result.Score.Grade)
		gradeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Bold(true)
		summary += fmt.Sprintf("🏆 Security Grade: %s (%d/100)\n",
			gradeStyle.Render(m.result.Score.Grade),
			m.result.Score.Overall)
	}

	sections = append(sections, summary)

	// Vulnerabilities section
	if len(m.result.Vulnerabilities) > 0 {
		vulnSection := fmt.Sprintf("🚨 Vulnerabilities: %d found\n", len(m.result.Vulnerabilities))

		// Count by severity
		severityCounts := make(map[string]int)
		for _, vuln := range m.result.Vulnerabilities {
			severityCounts[vuln.Severity]++
		}

		for severity, count := range severityCounts {
			color := getSeverityColor(severity)
			severityStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(color))
			vulnSection += fmt.Sprintf("  %s: %d\n", severityStyle.Render(severity), count)
		}

		sections = append(sections, vulnSection)
	} else {
		sections = append(sections, "✅ No vulnerabilities detected")
	}

	// Additional findings
	if len(m.result.Subdomains) > 0 {
		sections = append(sections, fmt.Sprintf("🌐 Subdomains: %d discovered", len(m.result.Subdomains)))
	}

	if len(m.result.ArchivedURLs) > 0 {
		sections = append(sections, fmt.Sprintf("📚 Archived URLs: %d found", len(m.result.ArchivedURLs)))
	}

	// AI Summary if available
	if m.result.AISummary != "" {
		aiSection := fmt.Sprintf("🤖 AI Analysis:\n%s", m.result.AISummary)
		sections = append(sections, aiSection)
	}

	content := ""
	for i, section := range sections {
		if i > 0 {
			content += "\n\n"
		}
		content += section
	}

	return resultStyle.Render(content)
}

// Helper functions for colors
func getGradeColor(grade string) string {
	switch grade {
	case "A+", "A":
		return "46" // Green
	case "A-", "B+", "B":
		return "226" // Yellow
	case "B-", "C+", "C":
		return "208" // Orange
	default:
		return "196" // Red
	}
}

func getSeverityColor(severity string) string {
	switch severity {
	case models.SeverityCritical:
		return "196" // Red
	case models.SeverityHigh:
		return "208" // Orange
	case models.SeverityMedium:
		return "226" // Yellow
	case models.SeverityLow:
		return "46" // Green
	default:
		return "248" // Gray
	}
}

// Commands and messages
func (m *ScanModel) startScan() tea.Cmd {
	return func() tea.Msg {
		return scanStartMsg{}
	}
}

func (m *ScanModel) performScan() tea.Cmd {
	return func() tea.Msg {
		result, err := m.scanner.Scan(m.ctx, m.target)
		if err != nil {
			return scanErrorMsg{err: err}
		}
		return scanCompleteMsg{result: result}
	}
}

func (m *ScanModel) tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Message types
type scanStartMsg struct{}
type scanUpdateMsg struct{ status *models.ScanStatus }
type scanCompleteMsg struct{ result *models.ScanResult }
type scanErrorMsg struct{ err error }
type tickMsg time.Time
