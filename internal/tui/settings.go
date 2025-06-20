package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// SettingsMenuItem represents a settings menu item
type SettingsMenuItem struct {
	title, desc string
	action      string
}

func (i SettingsMenuItem) Title() string       { return i.title }
func (i SettingsMenuItem) Description() string { return i.desc }
func (i SettingsMenuItem) FilterValue() string { return i.title }

// SettingsModel represents the settings screen
type SettingsModel struct {
	list   list.Model
	width  int
	height int
}

// NewSettingsModel creates a new settings model
func NewSettingsModel() SettingsModel {
	items := []list.Item{
		SettingsMenuItem{
			title:  "🔑 API Keys",
			desc:   "Manage AI provider API keys",
			action: "api_keys",
		},
		SettingsMenuItem{
			title:  "🎨 Theme",
			desc:   "Customize appearance and colors",
			action: "theme",
		},
		SettingsMenuItem{
			title:  "⚡ Performance",
			desc:   "Scan concurrency and timeout settings",
			action: "performance",
		},
		SettingsMenuItem{
			title:  "📊 Export",
			desc:   "Configure report export preferences",
			action: "export",
		},
		SettingsMenuItem{
			title:  "🔙 Back",
			desc:   "Return to main menu",
			action: "back",
		},
	}

	const defaultWidth = 20

	l := list.New(items, list.NewDefaultDelegate(), defaultWidth, 14)
	l.Title = "⚙️  Settings"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle

	return SettingsModel{list: l}
}

// Init implements tea.Model
func (m SettingsModel) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model
func (m SettingsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
			return m, tea.Quit
		case "esc":
			// Go back to main menu
			return NewMainMenuModel(), nil
		case "enter":
			i, ok := m.list.SelectedItem().(SettingsMenuItem)
			if ok {
				switch i.action {
				case "api_keys":
					// Transition to API key management
					apiKeysModel := NewAPIKeysModel()
					return apiKeysModel, apiKeysModel.Init()
				case "theme":
					// Show theme settings (placeholder)
					return m, nil
				case "performance":
					// Show performance settings (placeholder)
					return m, nil
				case "export":
					// Show export settings (placeholder)
					return m, nil
				case "back":
					return NewMainMenuModel(), nil
				}
			}
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// View implements tea.Model
func (m SettingsModel) View() string {
	// Header
	header := headerStyle.Render("⚙️  Settings & Configuration")

	// Instructions
	instructions := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Configure Harbinger settings and preferences")

	// List view
	listView := m.list.View()

	// Help text
	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Enter to select • ESC for main menu • Ctrl+C to quit")

	// Combine all parts
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		instructions,
		listView,
		help,
	)

	return content
}

// APIKeysModel represents the API key management screen
type APIKeysModel struct {
	list       list.Model
	width      int
	height     int
	apiKeys    []models.APIKey
	showingAdd bool
}

// APIKeyItem represents an API key list item
type APIKeyItem struct {
	apiKey models.APIKey
}

func (i APIKeyItem) Title() string {
	status := "❌ Inactive"
	if i.apiKey.IsActive {
		status = "✅ Active"
	}
	return fmt.Sprintf("%s %s", string(i.apiKey.Provider), status)
}

func (i APIKeyItem) Description() string {
	lastTested := "Never tested"
	if !i.apiKey.LastTested.IsZero() {
		lastTested = fmt.Sprintf("Last tested: %s", i.apiKey.LastTested.Format("2006-01-02 15:04"))
	}
	return fmt.Sprintf("Model: %s | %s", i.apiKey.Model, lastTested)
}

func (i APIKeyItem) FilterValue() string { return string(i.apiKey.Provider) }

// NewAPIKeysModel creates a new API keys model
func NewAPIKeysModel() APIKeysModel {
	// Mock API keys data
	apiKeys := []models.APIKey{
		{
			Provider:   models.ProviderGemini,
			IsActive:   true,
			TestStatus: "OK",
			Model:      "gemini-pro",
		},
		{
			Provider:   models.ProviderOpenAI,
			IsActive:   false,
			TestStatus: "Not configured",
			Model:      "gpt-4",
		},
		{
			Provider:   models.ProviderClaude,
			IsActive:   false,
			TestStatus: "Not configured",
			Model:      "claude-3-sonnet",
		},
	}

	items := []list.Item{}
	for _, key := range apiKeys {
		items = append(items, APIKeyItem{apiKey: key})
	}

	// Add "Add New Key" option
	items = append(items, SettingsMenuItem{
		title:  "➕ Add New API Key",
		desc:   "Configure a new AI provider",
		action: "add_key",
	})

	// Add "Back" option
	items = append(items, SettingsMenuItem{
		title:  "🔙 Back",
		desc:   "Return to settings",
		action: "back",
	})

	l := list.New(items, list.NewDefaultDelegate(), 50, 14)
	l.Title = "🔑 API Key Management"
	l.SetShowStatusBar(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle

	return APIKeysModel{
		list:    l,
		apiKeys: apiKeys,
	}
}

// Init implements tea.Model
func (m APIKeysModel) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model
func (m APIKeysModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
			return m, tea.Quit
		case "esc":
			// Go back to settings
			return NewSettingsModel(), nil
		case "enter":
			selectedItem := m.list.SelectedItem()
			if item, ok := selectedItem.(SettingsMenuItem); ok {
				switch item.action {
				case "add_key":
					// Show add key form (placeholder)
					return m, nil
				case "back":
					return NewSettingsModel(), nil
				}
			}
			// If it's an API key item, show details/edit (placeholder)
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// View implements tea.Model
func (m APIKeysModel) View() string {
	// Header
	header := headerStyle.Render("🔑 API Key Management")

	// Instructions
	instructions := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Manage AI provider API keys for enhanced analysis")

	// Current provider status
	var activeProvider string
	for _, key := range m.apiKeys {
		if key.IsActive {
			activeProvider = string(key.Provider)
			break
		}
	}
	if activeProvider == "" {
		activeProvider = "None configured"
	}

	status := lipgloss.NewStyle().
		Foreground(infoColor).
		Margin(1, 0).
		Render(fmt.Sprintf("Active Provider: %s", activeProvider))

	// List view
	listView := m.list.View()

	// Help text
	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Enter to configure • ESC to go back • Ctrl+C to quit")

	// Security note
	securityNote := lipgloss.NewStyle().
		Foreground(warningColor).
		Margin(1, 0).
		Render("🔒 API keys are stored securely and encrypted at rest")

	// Combine all parts
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		instructions,
		status,
		listView,
		help,
		securityNote,
	)

	return content
}
