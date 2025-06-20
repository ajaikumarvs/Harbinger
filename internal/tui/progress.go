package tui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// TickMsg represents a timer tick
type TickMsg time.Time

// ScanCompleteMsg represents scan completion
type ScanCompleteMsg struct {
	Result *models.ScanResult
}

// ScanProgressModel represents the scan progress screen
type ScanProgressModel struct {
	targetURL    string
	progress     progress.Model
	spinner      spinner.Model
	scanProgress models.ScanProgress
	startTime    time.Time
	width        int
	height       int
	completed    bool
	result       *models.ScanResult
}

// NewScanProgressModel creates a new scan progress model
func NewScanProgressModel(targetURL string) ScanProgressModel {
	p := progress.New(progress.WithDefaultGradient())
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return ScanProgressModel{
		targetURL: targetURL,
		progress:  p,
		spinner:   s,
		startTime: time.Now(),
		scanProgress: models.ScanProgress{
			ScanID:           fmt.Sprintf("scan_%d", time.Now().Unix()),
			TotalSteps:       10, // Will be updated based on actual scanners
			CompletedSteps:   0,
			Progress:         0.0,
			ActiveScanners:   []string{"Port Scanner", "Technology Detection"},
			CurrentOperation: "Initializing scan...",
			Logs: []string{
				"Starting security scan...",
				fmt.Sprintf("Target: %s", targetURL),
			},
		},
	}
}

// Init implements tea.Model
func (m ScanProgressModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		tickCmd(), // Start the ticker
		// TODO: Start actual scan process
	)
}

// Update implements tea.Model
func (m ScanProgressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.progress.Width = msg.Width - 4
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			if m.completed {
				// Go back to main menu
				return NewMainMenuModel(), nil
			}
		case "enter":
			if m.completed && m.result != nil {
				// View results
				resultsModel := NewResultsModel(*m.result)
				return resultsModel, resultsModel.Init()
			}
		}

	case TickMsg:
		// Simulate scan progress
		if !m.completed {
			m.scanProgress.CompletedSteps++
			m.scanProgress.Progress = float64(m.scanProgress.CompletedSteps) / float64(m.scanProgress.TotalSteps)

			// Update current operation based on progress
			switch m.scanProgress.CompletedSteps {
			case 1:
				m.scanProgress.CurrentOperation = "Port scanning..."
				m.scanProgress.CurrentScanner = "Port Scanner"
			case 3:
				m.scanProgress.CurrentOperation = "Detecting technologies..."
				m.scanProgress.CurrentScanner = "Technology Detection"
			case 5:
				m.scanProgress.CurrentOperation = "SSL/TLS analysis..."
				m.scanProgress.CurrentScanner = "SSL Analyzer"
			case 7:
				m.scanProgress.CurrentOperation = "Header analysis..."
				m.scanProgress.CurrentScanner = "Header Analyzer"
			case 9:
				m.scanProgress.CurrentOperation = "AI analysis..."
				m.scanProgress.CurrentScanner = "AI Processor"
			case 10:
				m.scanProgress.CurrentOperation = "Scan completed!"
				m.completed = true
				// Create mock result
				m.result = &models.ScanResult{
					ID:            m.scanProgress.ScanID,
					URL:           m.targetURL,
					Timestamp:     m.startTime,
					Status:        models.ScanStatusCompleted,
					SecurityScore: 75,
					TechStack: []models.Technology{
						{Name: "nginx", Version: "1.18.0", Category: "Web Server", Confidence: 0.95},
						{Name: "React", Version: "17.0.2", Category: "Frontend Framework", Confidence: 0.90},
					},
					Vulnerabilities: []models.Vulnerability{
						{
							CVE:         "CVE-2023-1234",
							Severity:    "Medium",
							Score:       6.5,
							Description: "Example vulnerability found during scan",
							Remediation: "Update to latest version",
						},
					},
					ScanDuration: time.Since(m.startTime),
				}
				return m, nil
			}

			// Add log entry
			if m.scanProgress.CompletedSteps <= len(m.scanProgress.Logs) {
				m.scanProgress.Logs = append(m.scanProgress.Logs,
					fmt.Sprintf("[%s] %s",
						time.Now().Format("15:04:05"),
						m.scanProgress.CurrentOperation))
			}

			return m, tickCmd()
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

// View implements tea.Model
func (m ScanProgressModel) View() string {
	if m.completed {
		return m.renderCompleted()
	}
	return m.renderProgress()
}

func (m ScanProgressModel) renderProgress() string {
	// Header
	header := headerStyle.Render("🔍 Scanning in Progress")

	// Target info
	targetInfo := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render(fmt.Sprintf("Target: %s", m.targetURL))

	// Progress bar
	progressBar := lipgloss.NewStyle().
		Margin(1, 0).
		Render(m.progress.ViewAs(m.scanProgress.Progress))

	// Progress stats
	stats := lipgloss.NewStyle().
		Margin(1, 0).
		Render(fmt.Sprintf(
			"Progress: %d/%d steps (%.1f%%)",
			m.scanProgress.CompletedSteps,
			m.scanProgress.TotalSteps,
			m.scanProgress.Progress*100,
		))

	// Current operation
	currentOp := lipgloss.NewStyle().
		Foreground(infoColor).
		Margin(1, 0).
		Render(fmt.Sprintf("%s %s", m.spinner.View(), m.scanProgress.CurrentOperation))

	// Active scanners
	activeScannersStr := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render(fmt.Sprintf("Active: %s", m.scanProgress.CurrentScanner))

	// Recent logs (last 5)
	logTitle := lipgloss.NewStyle().
		Bold(true).
		Margin(1, 0, 0, 0).
		Render("Recent Activity:")

	var recentLogs []string
	start := len(m.scanProgress.Logs) - 5
	if start < 0 {
		start = 0
	}
	for i := start; i < len(m.scanProgress.Logs); i++ {
		recentLogs = append(recentLogs, m.scanProgress.Logs[i])
	}

	logsContent := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(0, 0, 1, 0).
		Render(fmt.Sprintf("%s", lipgloss.JoinVertical(lipgloss.Left, recentLogs...)))

	// Help text
	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Ctrl+C to quit")

	// Combine all parts
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		targetInfo,
		progressBar,
		stats,
		currentOp,
		activeScannersStr,
		logTitle,
		logsContent,
		help,
	)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content)
}

func (m ScanProgressModel) renderCompleted() string {
	// Header
	header := lipgloss.NewStyle().
		Foreground(successColor).
		Bold(true).
		Margin(1, 0).
		Render("✅ Scan Completed Successfully!")

	// Summary
	summary := lipgloss.NewStyle().
		Margin(1, 0).
		Render(fmt.Sprintf(
			"Target: %s\nDuration: %v\nSecurity Score: %d/100",
			m.targetURL,
			m.result.ScanDuration.Round(time.Second),
			m.result.SecurityScore,
		))

	// Quick stats
	stats := lipgloss.NewStyle().
		Margin(1, 0).
		Render(fmt.Sprintf(
			"Technologies Found: %d\nVulnerabilities: %d",
			len(m.result.TechStack),
			len(m.result.Vulnerabilities),
		))

	// Help text
	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(2, 0).
		Render("Press Enter to view results • ESC for main menu • Ctrl+C to quit")

	// Combine all parts
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		summary,
		stats,
		help,
	)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content)
}

// tickCmd returns a command that ticks every second
func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}
