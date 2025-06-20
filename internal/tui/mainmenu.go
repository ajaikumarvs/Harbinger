package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// MainMenuItem represents a menu item
type MainMenuItem struct {
	title, desc string
	action      string
}

func (i MainMenuItem) Title() string       { return i.title }
func (i MainMenuItem) Description() string { return i.desc }
func (i MainMenuItem) FilterValue() string { return i.title }

// MainMenuModel represents the main menu state
type MainMenuModel struct {
	list     list.Model
	choice   string
	quitting bool
	width    int
	height   int
}

// NewMainMenuModel creates a new main menu model
func NewMainMenuModel() MainMenuModel {
	items := []list.Item{
		MainMenuItem{
			title:  "🔍 Scan",
			desc:   "Start a new security scan",
			action: "scan",
		},
		MainMenuItem{
			title:  "📚 History",
			desc:   "View previous scan results",
			action: "history",
		},
		MainMenuItem{
			title:  "⚙️  Settings",
			desc:   "Configure API keys and preferences",
			action: "settings",
		},
		MainMenuItem{
			title:  "❓ Help",
			desc:   "Show usage instructions and documentation",
			action: "help",
		},
		MainMenuItem{
			title:  "🚪 Exit",
			desc:   "Quit the application",
			action: "exit",
		},
	}

	const defaultWidth = 20

	l := list.New(items, list.NewDefaultDelegate(), defaultWidth, 14)
	l.Title = "🛡️  Harbinger Security Scanner"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle

	return MainMenuModel{list: l}
}

// Init implements tea.Model
func (m MainMenuModel) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model
func (m MainMenuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetWidth(msg.Width)
		m.list.SetHeight(msg.Height - 2)
		return m, nil

	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "enter":
			i, ok := m.list.SelectedItem().(MainMenuItem)
			if ok {
				m.choice = i.action
				switch i.action {
				case "scan":
					// Transition to scan input
					scanModel := NewScanInputModel()
					return scanModel, scanModel.Init()
				case "history":
					// Transition to history view
					historyModel := NewHistoryModel()
					return historyModel, historyModel.Init()
				case "settings":
					// Transition to settings
					settingsModel := NewSettingsModel()
					return settingsModel, settingsModel.Init()
				case "help":
					// Transition to help
					helpModel := NewHelpModel()
					return helpModel, helpModel.Init()
				case "exit":
					m.quitting = true
					return m, tea.Quit
				}
			}
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// View implements tea.Model
func (m MainMenuModel) View() string {
	if m.quitting {
		return quitTextStyle.Render("Thanks for using Harbinger! 👋")
	}

	// Create header
	header := headerStyle.Render(fmt.Sprintf(
		"Welcome to Harbinger - Comprehensive Security Scanner\n" +
			"Use ↑/↓ to navigate, Enter to select, Ctrl+C to quit",
	))

	// Create main content area
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		"",
		m.list.View(),
	)

	// Create footer
	footer := footerStyle.Render("v1.0.0 | Built with ❤️  by ajaikumarvs")

	// Combine all parts
	return lipgloss.JoinVertical(
		lipgloss.Left,
		content,
		"",
		footer,
	)
}

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1).
			Bold(true)

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#5A67D8")).
			Padding(1, 2).
			Margin(0, 0, 1, 0).
			Bold(true)

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262")).
			Align(lipgloss.Center).
			Margin(1, 0, 0, 0)

	paginationStyle = list.DefaultStyles().PaginationStyle.
			PaddingLeft(4)

	helpStyle = list.DefaultStyles().HelpStyle.
			PaddingLeft(4).
			PaddingBottom(1)

	quitTextStyle = lipgloss.NewStyle().
			Margin(1, 0, 2, 4).
			Foreground(lipgloss.Color("#04B575")).
			Bold(true)

	// Common styles used across components
	focusedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#01FAC6")).
			Bold(true)

	blurredStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262"))

	cursorStyle = focusedStyle.Copy()

	noStyle = lipgloss.NewStyle()

	// Color definitions
	successColor = lipgloss.Color("#04B575")
	errorColor   = lipgloss.Color("#FF5F87")
	warningColor = lipgloss.Color("#FFAF00")
	infoColor    = lipgloss.Color("#5A67D8")
)
