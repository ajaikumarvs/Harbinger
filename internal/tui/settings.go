package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ajaikumarvs/harbinger/internal/ai"
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
					// Show theme settings
					themeModel := NewThemeSettingsModel()
					return themeModel, themeModel.Init()
				case "performance":
					// Show performance settings
					perfModel := NewPerformanceSettingsModel()
					return perfModel, perfModel.Init()
				case "export":
					// Show export settings
					exportModel := NewExportSettingsModel()
					return exportModel, exportModel.Init()
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
	return newAPIKeysModelWithData(loadRealAPIKeys())
}

// NewAPIKeysModelWithRefresh creates a new API keys model with refreshed data
func NewAPIKeysModelWithRefresh() APIKeysModel {
	return newAPIKeysModelWithData(loadRealAPIKeys())
}

// newAPIKeysModelWithData creates the API keys model with provided data
func newAPIKeysModelWithData(apiKeys []models.APIKey) APIKeysModel {
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

// loadRealAPIKeys loads the actual API keys from storage
func loadRealAPIKeys() []models.APIKey {
	// Try to create a keystore to load real API keys
	keyStore, err := ai.NewKeyStore()
	if err != nil {
		// If keystore creation fails, return empty slice
		return []models.APIKey{}
	}

	// Get all API keys from storage
	apiKeys, err := keyStore.GetAllAPIKeys()
	if err != nil {
		// If loading fails, return empty slice
		return []models.APIKey{}
	}

	return apiKeys
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
			return NewAPIKeysModelWithRefresh(), nil
		case "enter":
			selectedItem := m.list.SelectedItem()
			if item, ok := selectedItem.(SettingsMenuItem); ok && item.action == "back" {
				return NewAPIKeysModelWithRefresh(), nil
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
			return NewAPIKeysModelWithRefresh(), nil
		case "tab", "shift+tab", "enter", "up", "down":
			s := msg.String()

			if s == "enter" && m.focused == len(m.inputs) {
				// Save button pressed
				m.saveConfiguration()
				return NewAPIKeysModelWithRefresh(), nil
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
	// Create AI service to save the configuration
	service, err := ai.NewService()
	if err != nil {
		// Handle error - for now just return
		return
	}

	// Get values from inputs
	apiKey := m.inputs[0].Value()
	model := m.inputs[1].Value()
	if model == "" {
		model = getDefaultModel(m.apiKey.Provider)
	}

	var customURL string
	if m.isCustom && len(m.inputs) > 2 {
		customURL = m.inputs[2].Value()
	}

	// Save the configuration
	if m.isCustom {
		err = service.ConfigureProviderWithURL(m.apiKey.Provider, apiKey, model, customURL)
	} else {
		err = service.ConfigureProvider(m.apiKey.Provider, apiKey, model)
	}

	if err != nil {
		// Handle error - for now just return
		return
	}
}

func (m *APIConfigModel) testConnection() {
	// Create AI service to test the connection
	service, err := ai.NewService()
	if err != nil {
		m.showTestResult = true
		m.testResult = "❌ Failed to create AI service"
		return
	}

	// Get values from inputs and temporarily configure
	apiKey := m.inputs[0].Value()
	model := m.inputs[1].Value()
	if model == "" {
		model = getDefaultModel(m.apiKey.Provider)
	}

	var customURL string
	if m.isCustom && len(m.inputs) > 2 {
		customURL = m.inputs[2].Value()
	}

	// First save the configuration
	if m.isCustom {
		err = service.ConfigureProviderWithURL(m.apiKey.Provider, apiKey, model, customURL)
	} else {
		err = service.ConfigureProvider(m.apiKey.Provider, apiKey, model)
	}

	if err != nil {
		m.showTestResult = true
		m.testResult = "❌ Configuration failed"
		return
	}

	// Test the connection
	ctx := context.Background()
	err = service.TestProvider(ctx, m.apiKey.Provider)

	m.showTestResult = true
	if err != nil {
		m.testResult = fmt.Sprintf("❌ Connection failed: %v", err)
	} else {
		m.testResult = "✅ Connection test successful!"
		// Also set as active provider if test is successful
		service.SetActiveProvider(m.apiKey.Provider)
	}
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
			return NewAPIKeysModelWithRefresh(), nil
		case "tab", "shift+tab", "enter", "up", "down":
			s := msg.String()

			if s == "enter" && m.focused == len(m.inputs) {
				// Save button pressed
				m.saveCustomAPI()
				return NewAPIKeysModelWithRefresh(), nil
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
	// Create AI service to save the custom API configuration
	service, err := ai.NewService()
	if err != nil {
		// Handle error - for now just return
		return
	}

	// Get values from inputs
	name := m.inputs[0].Value()
	url := m.inputs[1].Value()
	apiKey := m.inputs[2].Value()
	model := m.inputs[3].Value()

	if name == "" || url == "" {
		// Basic validation - name and URL are required
		return
	}

	if model == "" {
		model = "default"
	}

	// Save the custom API configuration
	err = service.ConfigureProviderWithURL(models.ProviderCustom, apiKey, model, url)
	if err != nil {
		// Handle error - for now just return
		return
	}
}

func (m *CustomAPIModel) testCustomConnection() {
	// Create AI service to test the custom API connection
	service, err := ai.NewService()
	if err != nil {
		m.showTestResult = true
		m.testResult = "❌ Failed to create AI service"
		return
	}

	// Get values from inputs
	name := m.inputs[0].Value()
	url := m.inputs[1].Value()
	apiKey := m.inputs[2].Value()
	model := m.inputs[3].Value()

	if name == "" || url == "" {
		m.showTestResult = true
		m.testResult = "❌ Name and URL are required"
		return
	}

	if model == "" {
		model = "default"
	}

	// First save the custom API configuration
	err = service.ConfigureProviderWithURL(models.ProviderCustom, apiKey, model, url)
	if err != nil {
		m.showTestResult = true
		m.testResult = "❌ Configuration failed"
		return
	}

	// Test the connection
	ctx := context.Background()
	err = service.TestProvider(ctx, models.ProviderCustom)

	m.showTestResult = true
	if err != nil {
		m.testResult = fmt.Sprintf("❌ Connection failed: %v", err)
	} else {
		m.testResult = "✅ Custom API connection test successful!"
		// Also set as active provider if test is successful
		service.SetActiveProvider(models.ProviderCustom)
	}
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

// ThemeSettingsModel represents the theme configuration screen
type ThemeSettingsModel struct {
	list         list.Model
	width        int
	height       int
	currentTheme string
}

// ThemeOption represents a theme option
type ThemeOption struct {
	name        string
	description string
	colors      []string
}

func (i ThemeOption) Title() string       { return i.name }
func (i ThemeOption) Description() string { return i.description }
func (i ThemeOption) FilterValue() string { return i.name }

// NewThemeSettingsModel creates a new theme settings model
func NewThemeSettingsModel() ThemeSettingsModel {
	items := []list.Item{
		ThemeOption{
			name:        "🌙 Dark (Default)",
			description: "Dark theme with blue accents",
			colors:      []string{"#1e1e2e", "#89b4fa", "#a6e3a1"},
		},
		ThemeOption{
			name:        "☀️ Light",
			description: "Light theme with clean appearance",
			colors:      []string{"#eff1f5", "#1e66f5", "#40a02b"},
		},
		ThemeOption{
			name:        "🌈 Colorful",
			description: "Vibrant theme with rainbow accents",
			colors:      []string{"#313244", "#f38ba8", "#fab387"},
		},
		ThemeOption{
			name:        "💻 Terminal",
			description: "Classic terminal green theme",
			colors:      []string{"#000000", "#00ff00", "#ffffff"},
		},
		SettingsMenuItem{
			title:  "🔙 Back",
			desc:   "Return to settings",
			action: "back",
		},
	}

	l := list.New(items, list.NewDefaultDelegate(), 50, 14)
	l.Title = "🎨 Theme Settings"
	l.SetShowStatusBar(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle

	return ThemeSettingsModel{
		list:         l,
		currentTheme: "Dark (Default)",
	}
}

// Init implements tea.Model
func (m ThemeSettingsModel) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model
func (m ThemeSettingsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
			return NewSettingsModel(), nil
		case "enter":
			selectedItem := m.list.SelectedItem()
			if item, ok := selectedItem.(ThemeOption); ok {
				m.currentTheme = item.name
				// Here you would typically save the theme preference
				// For now, we'll just update the current selection
				return m, nil
			}
			if item, ok := selectedItem.(SettingsMenuItem); ok && item.action == "back" {
				return NewSettingsModel(), nil
			}
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// View implements tea.Model
func (m ThemeSettingsModel) View() string {
	header := headerStyle.Render("🎨 Theme Settings")

	currentInfo := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render(fmt.Sprintf("Current theme: %s", m.currentTheme))

	listView := m.list.View()

	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Enter to select theme • ESC to go back • Ctrl+C to quit")

	return lipgloss.JoinVertical(lipgloss.Left, header, currentInfo, listView, help)
}

// PerformanceSettingsModel represents the performance configuration screen
type PerformanceSettingsModel struct {
	list     list.Model
	width    int
	height   int
	settings map[string]interface{}
}

// PerformanceOption represents a performance setting option
type PerformanceOption struct {
	name        string
	description string
	value       string
	action      string
}

func (i PerformanceOption) Title() string       { return i.name }
func (i PerformanceOption) Description() string { return i.description }
func (i PerformanceOption) FilterValue() string { return i.name }

// NewPerformanceSettingsModel creates a new performance settings model
func NewPerformanceSettingsModel() PerformanceSettingsModel {
	settings := map[string]interface{}{
		"max_concurrency": 5,
		"scan_timeout":    30,
		"ai_timeout":      60,
		"retry_attempts":  3,
	}

	items := []list.Item{
		PerformanceOption{
			name:        "🔄 Max Concurrency",
			description: fmt.Sprintf("Maximum concurrent scanners: %d", settings["max_concurrency"]),
			value:       "5",
			action:      "concurrency",
		},
		PerformanceOption{
			name:        "⏱️ Scan Timeout",
			description: fmt.Sprintf("Scanner timeout in seconds: %d", settings["scan_timeout"]),
			value:       "30",
			action:      "timeout",
		},
		PerformanceOption{
			name:        "🤖 AI Timeout",
			description: fmt.Sprintf("AI analysis timeout in seconds: %d", settings["ai_timeout"]),
			value:       "60",
			action:      "ai_timeout",
		},
		PerformanceOption{
			name:        "🔁 Retry Attempts",
			description: fmt.Sprintf("Failed scan retry attempts: %d", settings["retry_attempts"]),
			value:       "3",
			action:      "retry",
		},
		SettingsMenuItem{
			title:  "🔙 Back",
			desc:   "Return to settings",
			action: "back",
		},
	}

	l := list.New(items, list.NewDefaultDelegate(), 50, 14)
	l.Title = "⚡ Performance Settings"
	l.SetShowStatusBar(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle

	return PerformanceSettingsModel{
		list:     l,
		settings: settings,
	}
}

// Init implements tea.Model
func (m PerformanceSettingsModel) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model
func (m PerformanceSettingsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
			return NewSettingsModel(), nil
		case "enter":
			selectedItem := m.list.SelectedItem()
			if item, ok := selectedItem.(PerformanceOption); ok {
				// Here you would typically show an input field to modify the setting
				// For now, we'll just cycle through some preset values
				switch item.action {
				case "concurrency":
					current := m.settings["max_concurrency"].(int)
					if current >= 10 {
						m.settings["max_concurrency"] = 1
					} else {
						m.settings["max_concurrency"] = current + 1
					}
				case "timeout":
					current := m.settings["scan_timeout"].(int)
					if current >= 120 {
						m.settings["scan_timeout"] = 10
					} else {
						m.settings["scan_timeout"] = current + 10
					}
				case "ai_timeout":
					current := m.settings["ai_timeout"].(int)
					if current >= 180 {
						m.settings["ai_timeout"] = 30
					} else {
						m.settings["ai_timeout"] = current + 30
					}
				case "retry":
					current := m.settings["retry_attempts"].(int)
					if current >= 5 {
						m.settings["retry_attempts"] = 1
					} else {
						m.settings["retry_attempts"] = current + 1
					}
				}
				// Refresh the model with updated settings
				return NewPerformanceSettingsModel(), nil
			}
			if item, ok := selectedItem.(SettingsMenuItem); ok && item.action == "back" {
				return NewSettingsModel(), nil
			}
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// View implements tea.Model
func (m PerformanceSettingsModel) View() string {
	header := headerStyle.Render("⚡ Performance Settings")

	instructions := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Configure scanning performance and timeout settings")

	listView := m.list.View()

	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Enter to modify setting • ESC to go back • Ctrl+C to quit")

	return lipgloss.JoinVertical(lipgloss.Left, header, instructions, listView, help)
}

// ExportSettingsModel represents the export configuration screen
type ExportSettingsModel struct {
	list     list.Model
	width    int
	height   int
	settings map[string]interface{}
}

// ExportOption represents an export setting option
type ExportOption struct {
	name        string
	description string
	value       string
	action      string
}

func (i ExportOption) Title() string       { return i.name }
func (i ExportOption) Description() string { return i.description }
func (i ExportOption) FilterValue() string { return i.name }

// NewExportSettingsModel creates a new export settings model
func NewExportSettingsModel() ExportSettingsModel {
	settings := map[string]interface{}{
		"default_format":   "JSON",
		"include_raw_data": true,
		"auto_export":      false,
		"export_location":  "./reports/",
		"company_name":     "Your Company",
		"include_branding": true,
	}

	items := []list.Item{
		ExportOption{
			name:        "📄 Default Format",
			description: fmt.Sprintf("Default export format: %s", settings["default_format"]),
			value:       "JSON",
			action:      "format",
		},
		ExportOption{
			name:        "📊 Include Raw Data",
			description: fmt.Sprintf("Include raw scan data: %v", settings["include_raw_data"]),
			value:       "true",
			action:      "raw_data",
		},
		ExportOption{
			name:        "🔄 Auto Export",
			description: fmt.Sprintf("Automatically export after scan: %v", settings["auto_export"]),
			value:       "false",
			action:      "auto_export",
		},
		ExportOption{
			name:        "📁 Export Location",
			description: fmt.Sprintf("Export directory: %s", settings["export_location"]),
			value:       "./reports/",
			action:      "location",
		},
		ExportOption{
			name:        "🏢 Company Name",
			description: fmt.Sprintf("Company branding: %s", settings["company_name"]),
			value:       "Your Company",
			action:      "company",
		},
		ExportOption{
			name:        "🎨 Include Branding",
			description: fmt.Sprintf("Include company branding: %v", settings["include_branding"]),
			value:       "true",
			action:      "branding",
		},
		SettingsMenuItem{
			title:  "🔙 Back",
			desc:   "Return to settings",
			action: "back",
		},
	}

	l := list.New(items, list.NewDefaultDelegate(), 50, 14)
	l.Title = "📊 Export Settings"
	l.SetShowStatusBar(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle

	return ExportSettingsModel{
		list:     l,
		settings: settings,
	}
}

// Init implements tea.Model
func (m ExportSettingsModel) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model
func (m ExportSettingsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
			return NewSettingsModel(), nil
		case "enter":
			selectedItem := m.list.SelectedItem()
			if item, ok := selectedItem.(ExportOption); ok {
				// Toggle or cycle through values
				switch item.action {
				case "format":
					current := m.settings["default_format"].(string)
					if current == "JSON" {
						m.settings["default_format"] = "TXT"
					} else {
						m.settings["default_format"] = "JSON"
					}
				case "raw_data":
					m.settings["include_raw_data"] = !m.settings["include_raw_data"].(bool)
				case "auto_export":
					m.settings["auto_export"] = !m.settings["auto_export"].(bool)
				case "branding":
					m.settings["include_branding"] = !m.settings["include_branding"].(bool)
				case "location":
					// Would typically show a file picker or input field
					// For now just cycle through common locations
					current := m.settings["export_location"].(string)
					switch current {
					case "./reports/":
						m.settings["export_location"] = "./exports/"
					case "./exports/":
						m.settings["export_location"] = "~/Documents/harbinger/"
					default:
						m.settings["export_location"] = "./reports/"
					}
				case "company":
					// Would typically show an input field
					// For now just cycle through example names
					current := m.settings["company_name"].(string)
					switch current {
					case "Your Company":
						m.settings["company_name"] = "Security Corp"
					case "Security Corp":
						m.settings["company_name"] = "TechSec Ltd"
					default:
						m.settings["company_name"] = "Your Company"
					}
				}
				// Refresh the model with updated settings
				return NewExportSettingsModel(), nil
			}
			if item, ok := selectedItem.(SettingsMenuItem); ok && item.action == "back" {
				return NewSettingsModel(), nil
			}
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// View implements tea.Model
func (m ExportSettingsModel) View() string {
	header := headerStyle.Render("📊 Export Settings")

	instructions := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Configure report export preferences and formats")

	listView := m.list.View()

	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Enter to modify setting • ESC to go back • Ctrl+C to quit")

	return lipgloss.JoinVertical(lipgloss.Left, header, instructions, listView, help)
}
