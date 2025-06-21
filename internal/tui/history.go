package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ajaikumarvs/harbinger/internal/storage"
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
	list           list.Model
	width          int
	height         int
	storageManager *storage.StorageManager
	loaded         bool
	loadError      error
}

// NewHistoryModel creates a new history model
func NewHistoryModel() HistoryModel {
	// Initialize empty list
	const defaultWidth = 80
	l := list.New([]list.Item{}, list.NewDefaultDelegate(), defaultWidth, 14)
	l.Title = "📚 Scan History"
	l.SetShowStatusBar(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle

	// Initialize storage manager
	storageManager, err := storage.NewStorageManager()
	var loadError error
	if err != nil {
		loadError = fmt.Errorf("failed to initialize storage: %w", err)
		storageManager = nil
	}

	return HistoryModel{
		list:           l,
		storageManager: storageManager,
		loaded:         false,
		loadError:      loadError,
	}
}

// loadHistoryCmd loads scan history from storage
func (m *HistoryModel) loadHistoryCmd() tea.Cmd {
	return func() tea.Msg {
		if m.storageManager == nil {
			return historyLoadedMsg{error: fmt.Errorf("storage manager not initialized")}
		}

		// Load recent scans (last 50)
		scanIndexes, err := m.storageManager.ListScanResults(50, 0)
		if err != nil {
			return historyLoadedMsg{error: fmt.Errorf("failed to list scan results: %w", err)}
		}

		var items []list.Item
		var loadErrors []string

		for _, index := range scanIndexes {
			// Load full scan result
			result, err := m.storageManager.GetScanResult(index.ID)
			if err != nil {
				loadErrors = append(loadErrors, fmt.Sprintf("Failed to load scan %s: %v", index.ID, err))
				continue // Skip errors, just don't include this scan
			}
			items = append(items, HistoryItem{result: *result})
		}

		// If we had load errors but some items, still return success with items
		if len(loadErrors) > 0 && len(items) == 0 {
			return historyLoadedMsg{error: fmt.Errorf("failed to load any scans: %s", loadErrors[0])}
		}

		return historyLoadedMsg{items: items}
	}
}

// historyLoadedMsg represents the result of loading history
type historyLoadedMsg struct {
	items []list.Item
	error error
}

// Init implements tea.Model
func (m HistoryModel) Init() tea.Cmd {
	return m.loadHistoryCmd()
}

// Update implements tea.Model
func (m HistoryModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case historyLoadedMsg:
		m.loaded = true
		if msg.error != nil {
			m.loadError = msg.error
		} else {
			m.list.SetItems(msg.items)
			m.loadError = nil
		}
		return m, nil

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
		case "r":
			// Refresh history
			m.loaded = false
			return m, m.loadHistoryCmd()
		case "enter":
			// View selected scan result
			i, ok := m.list.SelectedItem().(HistoryItem)
			if ok {
				resultsModel := NewResultsModel(i.result)
				return resultsModel, resultsModel.Init()
			}
		case "d":
			// Delete selected scan
			if m.loaded && len(m.list.Items()) > 0 {
				i, ok := m.list.SelectedItem().(HistoryItem)
				if ok {
					return m, m.deleteScanCmd(i.result.ID)
				}
			}
		}
	}

	if m.loaded {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	return m, nil
}

// deleteScanCmd deletes a scan from storage
func (m *HistoryModel) deleteScanCmd(scanID string) tea.Cmd {
	return func() tea.Msg {
		if m.storageManager == nil {
			return nil
		}

		err := m.storageManager.DeleteScanResult(scanID)
		if err != nil {
			return nil // Ignore delete errors for now
		}

		// Reload history after deletion
		return historyLoadedMsg{items: []list.Item{}, error: nil} // Trigger reload
	}
}

// View implements tea.Model
func (m HistoryModel) View() string {
	// Header
	header := headerStyle.Render("📚 Previous Scans")

	if !m.loaded {
		// Show loading state
		loading := lipgloss.NewStyle().
			Margin(2, 0).
			Render("Loading scan history...")

		help := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262")).
			Margin(1, 0).
			Render("ESC for main menu • Ctrl+C to quit")

		return lipgloss.JoinVertical(lipgloss.Left, header, loading, help)
	}

	if m.loadError != nil {
		// Show error state
		var errorDetails string
		if m.storageManager == nil {
			errorDetails = "Storage manager failed to initialize. This could be due to:\n" +
				"• Permission issues with home directory\n" +
				"• LevelDB dependency problems\n" +
				"• Database corruption\n\n" +
				fmt.Sprintf("Error: %v", m.loadError)
		} else {
			errorDetails = fmt.Sprintf("Storage is available but loading failed:\n%v", m.loadError)
		}

		errorMsg := lipgloss.NewStyle().
			Foreground(errorColor).
			Margin(2, 0).
			Render(errorDetails)

		help := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262")).
			Margin(1, 0).
			Render("R to retry • ESC for main menu • Ctrl+C to quit")

		return lipgloss.JoinVertical(lipgloss.Left, header, errorMsg, help)
	}

	// No AI analysis available
	if len(m.list.Items()) == 0 && m.loaded && m.loadError == nil {
		// Show empty state
		emptyMsg := lipgloss.NewStyle().
			Margin(2, 0).
			Render("📭 No scan history found\n\n" +
				"Your scan history will appear here after you:\n" +
				"• Complete your first security scan\n" +
				"• Scans are automatically saved to history\n" +
				"• Use 'R' to refresh this view\n\n" +
				"💡 Tip: Go to 'Scan' from the main menu to start your first scan!")

		help := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262")).
			Margin(1, 0).
			Render("R: refresh • ESC: main menu • Ctrl+C: quit")

		return lipgloss.JoinVertical(lipgloss.Left, header, emptyMsg, help)
	}

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
		Render("Enter: view details • D: delete • R: refresh • ESC: main menu • Ctrl+C: quit")

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
