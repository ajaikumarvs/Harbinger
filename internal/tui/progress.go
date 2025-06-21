package tui

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ajaikumarvs/harbinger/internal/storage"
	"github.com/ajaikumarvs/harbinger/pkg/models"
	"github.com/ajaikumarvs/harbinger/pkg/scanner"
)

// TickMsg represents a timer tick
type TickMsg time.Time

// ScanCompleteMsg represents scan completion
type ScanCompleteMsg struct {
	Result *models.ScanResult
}

// ScanSavedMsg represents successful scan save
type ScanSavedMsg struct {
	Success bool
	Error   error
}

// ScanProgressModel represents the scan progress screen
type ScanProgressModel struct {
	targetURL      string
	progress       progress.Model
	spinner        spinner.Model
	scanProgress   models.ScanProgress
	startTime      time.Time
	width          int
	height         int
	completed      bool
	result         *models.ScanResult
	scanEngine     *scanner.Engine
	aiEngine       *scanner.AIEnhancedEngine // Store AI engine for enhanced scans
	scanCtx        context.Context
	scanCancel     context.CancelFunc
	scanMutex      sync.RWMutex
	storageManager *storage.StorageManager
	saved          bool
	saveError      error
}

// NewScanProgressModel creates a new scan progress model
func NewScanProgressModel(targetURL string) ScanProgressModel {
	p := progress.New(progress.WithDefaultGradient())
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	// Create AI-enhanced scan engine
	aiEngine, err := scanner.GetDefaultAIEngine()
	var engine *scanner.Engine
	if err != nil {
		// Fallback to regular engine if AI engine fails
		engine = scanner.GetDefaultEngine()
		aiEngine = nil
	} else {
		// Use the base engine from AI-enhanced engine for progress tracking
		engine = aiEngine.Engine
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize storage manager
	storageManager, err := storage.NewStorageManager()
	if err != nil {
		// Log the error but continue without storage (scan will still work)
		storageManager = nil
	}

	return ScanProgressModel{
		targetURL:      targetURL,
		progress:       p,
		spinner:        s,
		startTime:      time.Now(),
		scanEngine:     engine,
		aiEngine:       aiEngine,
		scanCtx:        ctx,
		scanCancel:     cancel,
		storageManager: storageManager,
		saved:          false,
		scanProgress: models.ScanProgress{
			ScanID:           fmt.Sprintf("scan_%d", time.Now().Unix()),
			TotalSteps:       6, // Number of scanners in the engine
			CompletedSteps:   0,
			Progress:         0.0,
			ActiveScanners:   []string{},
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
	// Set up progress callback
	m.scanEngine.SetProgressCallback(func(progress models.ScanProgress) {
		m.scanMutex.Lock()
		m.scanProgress = progress
		m.scanMutex.Unlock()
	})

	// Set up logging callback
	m.scanEngine.SetLogger(func(logMsg string) {
		m.scanMutex.Lock()
		m.scanProgress.Logs = append(m.scanProgress.Logs,
			fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), logMsg))
		m.scanMutex.Unlock()
	})

	return tea.Batch(
		m.spinner.Tick,
		m.startScanCmd(),
		tickCmd(), // Start the ticker
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
			if m.scanCancel != nil {
				m.scanCancel() // Cancel the scan
			}
			return m, tea.Quit
		case "esc":
			if m.completed {
				// Go back to main menu
				return NewMainMenuModel(), nil
			} else {
				// Cancel scan and go back
				if m.scanCancel != nil {
					m.scanCancel()
				}
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
		// Check if scan is still running
		if !m.completed {
			return m, tickCmd()
		}

	case ScanCompleteMsg:
		m.completed = true
		m.result = msg.Result

		// Automatically save the scan to storage
		if m.result != nil {
			return m, m.saveScanCmd()
		}
		return m, nil

	case ScanSavedMsg:
		m.saved = msg.Success
		m.saveError = msg.Error
		return m, nil

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
	// Get current progress (thread-safe)
	m.scanMutex.RLock()
	currentProgress := m.scanProgress
	m.scanMutex.RUnlock()

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
		Render(m.progress.ViewAs(currentProgress.Progress))

	// Progress stats
	stats := lipgloss.NewStyle().
		Margin(1, 0).
		Render(fmt.Sprintf(
			"Progress: %d/%d steps (%.1f%%)",
			currentProgress.CompletedSteps,
			currentProgress.TotalSteps,
			currentProgress.Progress*100,
		))

	// Current operation
	currentOp := lipgloss.NewStyle().
		Foreground(infoColor).
		Margin(1, 0).
		Render(fmt.Sprintf("%s %s", m.spinner.View(), currentProgress.CurrentOperation))

	// Active scanners
	activeScannersStr := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render(fmt.Sprintf("Active: %s", currentProgress.CurrentScanner))

	// Recent logs (last 5)
	logTitle := lipgloss.NewStyle().
		Bold(true).
		Margin(1, 0, 0, 0).
		Render("Recent Activity:")

	var recentLogs []string
	start := len(currentProgress.Logs) - 5
	if start < 0 {
		start = 0
	}
	for i := start; i < len(currentProgress.Logs); i++ {
		recentLogs = append(recentLogs, currentProgress.Logs[i])
	}

	logsContent := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(0, 0, 1, 0).
		Render(fmt.Sprintf("%s", lipgloss.JoinVertical(lipgloss.Left, recentLogs...)))

	// Help text
	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("ESC to cancel • Ctrl+C to quit")

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

	// Save status
	var saveStatus string
	if m.saved {
		saveStatus = lipgloss.NewStyle().
			Foreground(successColor).
			Margin(1, 0).
			Render("💾 Scan saved to history successfully!")
	} else if m.saveError != nil {
		saveStatus = lipgloss.NewStyle().
			Foreground(errorColor).
			Margin(1, 0).
			Render(fmt.Sprintf("💾 Save error: %v", m.saveError))
	} else {
		saveStatus = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262")).
			Margin(1, 0).
			Render("💾 Saving scan to history...")
	}

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
		saveStatus,
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

// startScanCmd starts the actual scan process
func (m ScanProgressModel) startScanCmd() tea.Cmd {
	return func() tea.Msg {
		var result *models.ScanResult
		var err error

		// Use AI-enhanced scan if available, otherwise regular scan
		if m.aiEngine != nil {
			result, err = m.aiEngine.ScanWithAI(m.scanCtx, m.targetURL)
		} else {
			result, err = m.scanEngine.Scan(m.scanCtx, m.targetURL)
		}

		if err != nil {
			// Handle error - for now just create a failed result
			result = &models.ScanResult{
				ID:           m.scanProgress.ScanID,
				URL:          m.targetURL,
				Timestamp:    m.startTime,
				Status:       models.ScanStatusFailed,
				ScanDuration: time.Since(m.startTime),
			}
		}

		return ScanCompleteMsg{Result: result}
	}
}

// saveScanCmd saves the scan result to storage
func (m ScanProgressModel) saveScanCmd() tea.Cmd {
	return func() tea.Msg {
		if m.storageManager != nil && m.result != nil {
			err := m.storageManager.SaveScanResult(m.result)
			return ScanSavedMsg{Success: err == nil, Error: err}
		}
		return ScanSavedMsg{Success: false, Error: fmt.Errorf("storage not available")}
	}
}
