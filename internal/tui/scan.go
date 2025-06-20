package tui

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ScanInputModel represents the scan input screen
type ScanInputModel struct {
	textInput textinput.Model
	err       error
	submitted bool
	width     int
	height    int
}

// NewScanInputModel creates a new scan input model
func NewScanInputModel() ScanInputModel {
	ti := textinput.New()
	ti.Placeholder = "https://example.com"
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 50

	return ScanInputModel{
		textInput: ti,
		err:       nil,
	}
}

// Init implements tea.Model
func (m ScanInputModel) Init() tea.Cmd {
	return textinput.Blink
}

// Update implements tea.Model
func (m ScanInputModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			// Go back to main menu
			return NewMainMenuModel(), nil
		case "enter":
			// Validate URL and start scan
			if m.validateURL(m.textInput.Value()) {
				m.submitted = true
				// Transition to scan progress
				scanProgress := NewScanProgressModel(m.textInput.Value())
				return scanProgress, scanProgress.Init()
			}
		}
	}

	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}

// View implements tea.Model
func (m ScanInputModel) View() string {
	// Header
	header := headerStyle.Render("🔍 Start New Security Scan")

	// Instructions
	instructions := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(1, 0).
		Render("Enter the URL you want to scan for security vulnerabilities:")

	// Input field
	inputStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#874BFD")).
		Padding(0, 1).
		Margin(1, 0)

	input := inputStyle.Render(m.textInput.View())

	// Error message
	var errorMsg string
	if m.err != nil {
		errorMsg = lipgloss.NewStyle().
			Foreground(errorColor).
			Margin(1, 0).
			Render(fmt.Sprintf("❌ Error: %v", m.err))
	}

	// Help text
	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#626262")).
		Margin(2, 0, 1, 0).
		Render("Press Enter to start scan • ESC to go back • Ctrl+C to quit")

	// Combine all parts
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		instructions,
		input,
		errorMsg,
		help,
	)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content)
}

// validateURL validates the input URL
func (m *ScanInputModel) validateURL(input string) bool {
	if strings.TrimSpace(input) == "" {
		m.err = fmt.Errorf("URL cannot be empty")
		return false
	}

	// Add https:// if no scheme is provided
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		input = "https://" + input
		m.textInput.SetValue(input)
	}

	_, err := url.Parse(input)
	if err != nil {
		m.err = fmt.Errorf("invalid URL format")
		return false
	}

	m.err = nil
	return true
}
