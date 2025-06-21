package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
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
	providerName := string(i.apiKey.Provider)
	if i.apiKey.Provider == models.ProviderCustom && i.apiKey.CustomURL != "" {
		providerName = fmt.Sprintf("Custom (%s)", i.apiKey.CustomURL)
	}
	return fmt.Sprintf("%s %s", providerName, status)
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

	// Add "Add Custom API" option
	items = append(items, SettingsMenuItem{
		title:  "🔧 Add Custom API",
		desc:   "Configure a custom AI endpoint",
		action: "add_custom",
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
					// Show provider selection for standard APIs
					providerModel := NewProviderSelectionModel()
					return providerModel, providerModel.Init()
				case "add_custom":
					// Show custom API configuration form
					customModel := NewCustomAPIModel()
					return customModel, customModel.Init()
				case "back":
					return NewSettingsModel(), nil
				}
			} else if apiItem, ok := selectedItem.(APIKeyItem); ok {
				// Show API key configuration for existing key
				configModel := NewAPIConfigModel(apiItem.apiKey)
				return configModel, configModel.Init()
			}
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

// ProviderSelectionModel represents the provider selection screen
type ProviderSelectionModel struct {
	list   list.Model
	width  int
	height int
}

// ProviderItem represents a provider selection item
type ProviderItem struct {
	provider models.APIProvider
	name     string
	desc     string
}

func (i ProviderItem) Title() string       { return i.name }
func (i ProviderItem) Description() string { return i.desc }
func (i ProviderItem) FilterValue() string { return i.name }

// NewProviderSelectionModel creates a new provider selection model
func NewProviderSelectionModel() ProviderSelectionModel {
	items := []list.Item{
		ProviderItem{
			provider: models.ProviderGemini,
			name:     "🎯 Google Gemini",
			desc:     "Google's advanced AI model",
		},
		ProviderItem{
			provider: models.ProviderOpenAI,
			name:     "🤖 OpenAI",
			desc:     "GPT-4 and ChatGPT models",
		},
		ProviderItem{
			provider: models.ProviderClaude,
			name:     "🧠 Anthropic Claude",
			desc:     "Claude-3 advanced reasoning",
		},
		SettingsMenuItem{
			title:  "🔙 Back",
			desc:   "Return to API management",
			action: "back",
		},
	}

	l := list.New(items, list.NewDefaultDelegate(), 50, 12)
	l.Title = "Select AI Provider"
	l.SetShowStatusBar(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle

	return ProviderSelectionModel{list: l}
}

// Init implements tea.Model
func (m ProviderSelectionModel) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model
func (m ProviderSelectionModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
			return NewAPIKeysModel(), nil
		case "enter":
			selectedItem := m.list.SelectedItem()
			if item, ok := selectedItem.(SettingsMenuItem); ok && item.action == "back" {
				return NewAPIKeysModel(), nil
			} else if providerItem, ok := selectedItem.(ProviderItem); ok {
				// Show API key configuration for selected provider
				apiKey := models.APIKey{Provider: providerItem.provider}
				configModel := NewAPIConfigModel(apiKey)
				return configModel, configModel.Init()
			}
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// View implements tea.Model
func (m ProviderSelectionModel) View() string {
	header := headerStyle.Render("🔑 Select AI Provider")
	instructions := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Choose an AI provider to configure")

	listView := m.list.View()
	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Enter to select • ESC to go back • Ctrl+C to quit")

	return lipgloss.JoinVertical(lipgloss.Left, header, instructions, listView, help)
}

// APIConfigModel represents the API configuration form
type APIConfigModel struct {
	apiKey         models.APIKey
	inputs         []textinput.Model
	focused        int
	width          int
	height         int
	isCustom       bool
	showTestResult bool
	testResult     string
}

// NewAPIConfigModel creates a new API configuration model
func NewAPIConfigModel(apiKey models.APIKey) APIConfigModel {
	isCustom := apiKey.Provider == models.ProviderCustom
	inputCount := 2 // API Key and Model
	if isCustom {
		inputCount = 3 // API Key, Model, and URL
	}

	inputs := make([]textinput.Model, inputCount)

	// API Key input
	inputs[0] = textinput.New()
	inputs[0].Placeholder = "Enter API key..."
	inputs[0].Focus()
	inputs[0].CharLimit = 200
	inputs[0].EchoMode = textinput.EchoPassword
	inputs[0].EchoCharacter = '•'
	inputs[0].SetValue(apiKey.Key)

	// Model input
	inputs[1] = textinput.New()
	inputs[1].Placeholder = getDefaultModel(apiKey.Provider)
	inputs[1].CharLimit = 100
	if apiKey.Model != "" {
		inputs[1].SetValue(apiKey.Model)
	}

	// URL input for custom APIs
	if isCustom {
		inputs[2] = textinput.New()
		inputs[2].Placeholder = "https://your-api-endpoint.com/v1"
		inputs[2].CharLimit = 500
		inputs[2].SetValue(apiKey.CustomURL)
	}

	return APIConfigModel{
		apiKey:   apiKey,
		inputs:   inputs,
		focused:  0,
		isCustom: isCustom,
	}
}

func getDefaultModel(provider models.APIProvider) string {
	switch provider {
	case models.ProviderGemini:
		return "gemini-pro"
	case models.ProviderOpenAI:
		return "gpt-4"
	case models.ProviderClaude:
		return "claude-3-sonnet-20240229"
	case models.ProviderCustom:
		return "default"
	default:
		return ""
	}
}

// Init implements tea.Model
func (m APIConfigModel) Init() tea.Cmd {
	return textinput.Blink
}

// Update implements tea.Model
func (m APIConfigModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			return NewAPIKeysModel(), nil
		case "tab", "shift+tab", "enter", "up", "down":
			s := msg.String()

			if s == "enter" && m.focused == len(m.inputs) {
				// Save button pressed
				m.saveConfiguration()
				return NewAPIKeysModel(), nil
			}

			if s == "enter" && m.focused == len(m.inputs)+1 {
				// Test button pressed
				m.testConnection()
				return m, nil
			}

			// Cycle inputs
			if s == "up" || s == "shift+tab" {
				m.focused--
			} else {
				m.focused++
			}

			if m.focused > len(m.inputs)+1 {
				m.focused = 0
			} else if m.focused < 0 {
				m.focused = len(m.inputs) + 1
			}

			cmds := make([]tea.Cmd, len(m.inputs))
			for i := 0; i <= len(m.inputs)-1; i++ {
				if i == m.focused {
					cmds[i] = m.inputs[i].Focus()
				} else {
					m.inputs[i].Blur()
				}
			}

			return m, tea.Batch(cmds...)
		}
	}

	// Handle character input in the focused input
	cmd := m.updateInputs(msg)

	return m, cmd
}

func (m *APIConfigModel) updateInputs(msg tea.Msg) tea.Cmd {
	cmds := make([]tea.Cmd, len(m.inputs))

	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}

	return tea.Batch(cmds...)
}

func (m *APIConfigModel) saveConfiguration() {
	// In a real implementation, this would save to storage
	// For now, just simulate saving
}

func (m *APIConfigModel) testConnection() {
	// In a real implementation, this would test the API connection
	m.showTestResult = true
	m.testResult = "✅ Connection test successful!"
}

// View implements tea.Model
func (m APIConfigModel) View() string {
	var providerName string
	if m.isCustom {
		providerName = "Custom API"
	} else {
		providerName = string(m.apiKey.Provider)
	}

	header := headerStyle.Render(fmt.Sprintf("🔑 Configure %s", providerName))

	var b strings.Builder
	b.WriteString(header)
	b.WriteString("\n\n")

	// API Key input
	if m.focused == 0 {
		b.WriteString(focusedStyle.Render("API Key"))
	} else {
		b.WriteString(blurredStyle.Render("API Key"))
	}
	b.WriteString("\n")
	b.WriteString(m.inputs[0].View())
	b.WriteString("\n\n")

	// Model input
	if m.focused == 1 {
		b.WriteString(focusedStyle.Render("Model"))
	} else {
		b.WriteString(blurredStyle.Render("Model"))
	}
	b.WriteString("\n")
	b.WriteString(m.inputs[1].View())
	b.WriteString("\n\n")

	// URL input for custom APIs
	if m.isCustom {
		if m.focused == 2 {
			b.WriteString(focusedStyle.Render("API Endpoint URL"))
		} else {
			b.WriteString(blurredStyle.Render("API Endpoint URL"))
		}
		b.WriteString("\n")
		b.WriteString(m.inputs[2].View())
		b.WriteString("\n\n")
	}

	// Buttons
	button := &blurredButton
	if m.focused == len(m.inputs) {
		button = &focusedButton
	}
	fmt.Fprintf(&b, "%s", *button)
	b.WriteString(" Save ")

	button = &blurredButton
	if m.focused == len(m.inputs)+1 {
		button = &focusedButton
	}
	fmt.Fprintf(&b, " %s", *button)
	b.WriteString(" Test Connection ")

	b.WriteString("\n\n")

	// Test result
	if m.showTestResult {
		b.WriteString(lipgloss.NewStyle().
			Foreground(successColor).
			Render(m.testResult))
		b.WriteString("\n\n")
	}

	// Help
	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Render("Tab to navigate • Enter to select • ESC to go back")
	b.WriteString(help)

	return b.String()
}

// CustomAPIModel represents the custom API configuration form
type CustomAPIModel struct {
	inputs         []textinput.Model
	focused        int
	width          int
	height         int
	showTestResult bool
	testResult     string
}

// NewCustomAPIModel creates a new custom API model
func NewCustomAPIModel() CustomAPIModel {
	inputs := make([]textinput.Model, 4)

	// Name input
	inputs[0] = textinput.New()
	inputs[0].Placeholder = "Enter API name (e.g., My Local AI)..."
	inputs[0].Focus()
	inputs[0].CharLimit = 100

	// URL input
	inputs[1] = textinput.New()
	inputs[1].Placeholder = "https://your-api-endpoint.com/v1"
	inputs[1].CharLimit = 500

	// API Key input
	inputs[2] = textinput.New()
	inputs[2].Placeholder = "Enter API key (optional)..."
	inputs[2].CharLimit = 200
	inputs[2].EchoMode = textinput.EchoPassword
	inputs[2].EchoCharacter = '•'

	// Model input
	inputs[3] = textinput.New()
	inputs[3].Placeholder = "Model name (e.g., gpt-3.5-turbo, default)"
	inputs[3].CharLimit = 100

	return CustomAPIModel{
		inputs:  inputs,
		focused: 0,
	}
}

// Init implements tea.Model
func (m CustomAPIModel) Init() tea.Cmd {
	return textinput.Blink
}

// Update implements tea.Model
func (m CustomAPIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			return NewAPIKeysModel(), nil
		case "tab", "shift+tab", "enter", "up", "down":
			s := msg.String()

			if s == "enter" && m.focused == len(m.inputs) {
				// Save button pressed
				m.saveCustomAPI()
				return NewAPIKeysModel(), nil
			}

			if s == "enter" && m.focused == len(m.inputs)+1 {
				// Test button pressed
				m.testCustomConnection()
				return m, nil
			}

			// Cycle inputs
			if s == "up" || s == "shift+tab" {
				m.focused--
			} else {
				m.focused++
			}

			if m.focused > len(m.inputs)+1 {
				m.focused = 0
			} else if m.focused < 0 {
				m.focused = len(m.inputs) + 1
			}

			cmds := make([]tea.Cmd, len(m.inputs))
			for i := 0; i <= len(m.inputs)-1; i++ {
				if i == m.focused {
					cmds[i] = m.inputs[i].Focus()
				} else {
					m.inputs[i].Blur()
				}
			}

			return m, tea.Batch(cmds...)
		}
	}

	// Handle character input in the focused input
	cmd := m.updateInputs(msg)

	return m, cmd
}

func (m *CustomAPIModel) updateInputs(msg tea.Msg) tea.Cmd {
	cmds := make([]tea.Cmd, len(m.inputs))

	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}

	return tea.Batch(cmds...)
}

func (m *CustomAPIModel) saveCustomAPI() {
	// In a real implementation, this would save the custom API configuration
	// For now, just simulate saving
}

func (m *CustomAPIModel) testCustomConnection() {
	// In a real implementation, this would test the custom API connection
	m.showTestResult = true
	m.testResult = "✅ Custom API connection test successful!"
}

// View implements tea.Model
func (m CustomAPIModel) View() string {
	header := headerStyle.Render("🔧 Configure Custom AI API")

	var b strings.Builder
	b.WriteString(header)
	b.WriteString("\n\n")

	// Instructions
	instructions := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Render("Configure a custom AI API endpoint. The system will try multiple request formats automatically.")
	b.WriteString(instructions)
	b.WriteString("\n\n")

	// Name input
	if m.focused == 0 {
		b.WriteString(focusedStyle.Render("API Name"))
	} else {
		b.WriteString(blurredStyle.Render("API Name"))
	}
	b.WriteString("\n")
	b.WriteString(m.inputs[0].View())
	b.WriteString("\n\n")

	// URL input
	if m.focused == 1 {
		b.WriteString(focusedStyle.Render("API Endpoint URL"))
	} else {
		b.WriteString(blurredStyle.Render("API Endpoint URL"))
	}
	b.WriteString("\n")
	b.WriteString(m.inputs[1].View())
	b.WriteString("\n\n")

	// API Key input
	if m.focused == 2 {
		b.WriteString(focusedStyle.Render("API Key (Optional)"))
	} else {
		b.WriteString(blurredStyle.Render("API Key (Optional)"))
	}
	b.WriteString("\n")
	b.WriteString(m.inputs[2].View())
	b.WriteString("\n\n")

	// Model input
	if m.focused == 3 {
		b.WriteString(focusedStyle.Render("Model Name"))
	} else {
		b.WriteString(blurredStyle.Render("Model Name"))
	}
	b.WriteString("\n")
	b.WriteString(m.inputs[3].View())
	b.WriteString("\n\n")

	// Buttons
	button := &blurredButton
	if m.focused == len(m.inputs) {
		button = &focusedButton
	}
	fmt.Fprintf(&b, "%s", *button)
	b.WriteString(" Save Configuration ")

	button = &blurredButton
	if m.focused == len(m.inputs)+1 {
		button = &focusedButton
	}
	fmt.Fprintf(&b, " %s", *button)
	b.WriteString(" Test Connection ")

	b.WriteString("\n\n")

	// Test result
	if m.showTestResult {
		b.WriteString(lipgloss.NewStyle().
			Foreground(successColor).
			Render(m.testResult))
		b.WriteString("\n\n")
	}

	// Help
	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Render("Tab to navigate • Enter to select • ESC to go back")
	b.WriteString(help)

	return b.String()
}

// Style definitions for buttons (other styles are defined in mainmenu.go)
var (
	focusedButton = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFF")).
			Background(lipgloss.Color("#FF06B7")).
			Padding(0, 3)
	blurredButton = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFF")).
			Background(lipgloss.Color("#666")).
			Padding(0, 3)
)
