package tui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// HistoryItem represents a history list item
type HistoryItem struct {
	result models.ScanResult
}

func (i HistoryItem) Title() string {
	return fmt.Sprintf("%s - Score: %d/100", i.result.URL, i.result.SecurityScore)
}

func (i HistoryItem) Description() string {
	return fmt.Sprintf("Scanned: %s | Vulnerabilities: %d",
		i.result.Timestamp.Format("2006-01-02 15:04"),
		len(i.result.Vulnerabilities))
}

func (i HistoryItem) FilterValue() string { return i.result.URL }

// HistoryModel represents the history view
type HistoryModel struct {
	list   list.Model
	width  int
	height int
}

// NewHistoryModel creates a new history model
func NewHistoryModel() HistoryModel {
	// Mock history data - in real implementation, this would load from storage
	items := []list.Item{
		HistoryItem{
			result: models.ScanResult{
				ID:            "scan_1",
				URL:           "https://example.com",
				Timestamp:     time.Now().Add(-24 * time.Hour),
				SecurityScore: 85,
				Vulnerabilities: []models.Vulnerability{
					{CVE: "CVE-2023-1234", Severity: "Low", Score: 3.2},
				},
				ScanDuration: 2 * time.Minute,
			},
		},
		HistoryItem{
			result: models.ScanResult{
				ID:            "scan_2",
				URL:           "https://test.com",
				Timestamp:     time.Now().Add(-48 * time.Hour),
				SecurityScore: 62,
				Vulnerabilities: []models.Vulnerability{
					{CVE: "CVE-2023-5678", Severity: "Medium", Score: 6.5},
					{CVE: "CVE-2023-9012", Severity: "High", Score: 8.2},
				},
				ScanDuration: 3 * time.Minute,
			},
		},
		HistoryItem{
			result: models.ScanResult{
				ID:              "scan_3",
				URL:             "https://secure.example.org",
				Timestamp:       time.Now().Add(-72 * time.Hour),
				SecurityScore:   92,
				Vulnerabilities: []models.Vulnerability{},
				ScanDuration:    1 * time.Minute,
			},
		},
	}

	const defaultWidth = 80

	l := list.New(items, list.NewDefaultDelegate(), defaultWidth, 14)
	l.Title = "📚 Scan History"
	l.SetShowStatusBar(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle

	return HistoryModel{list: l}
}

// Init implements tea.Model
func (m HistoryModel) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model
func (m HistoryModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetWidth(msg.Width)
		m.list.SetHeight(msg.Height - 4)
		return m, nil

	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			// Go back to main menu
			return NewMainMenuModel(), nil
		case "enter":
			// View selected scan result
			i, ok := m.list.SelectedItem().(HistoryItem)
			if ok {
				resultsModel := NewResultsModel(i.result)
				return resultsModel, resultsModel.Init()
			}
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// View implements tea.Model
func (m HistoryModel) View() string {
	// Header
	header := headerStyle.Render("📚 Previous Scans")

	// Instructions
	instructions := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Select a scan to view detailed results")

	// List view
	listView := m.list.View()

	// Help text
	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Enter to view details • ESC for main menu • Ctrl+C to quit")

	// Stats summary
	stats := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render(fmt.Sprintf("Total scans: %d", len(m.list.Items())))

	// Combine all parts
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		instructions,
		listView,
		stats,
		help,
	)

	return content
}
