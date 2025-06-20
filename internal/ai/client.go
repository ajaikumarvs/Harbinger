package ai

import (
	"context"
	"fmt"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// Client represents an AI client interface
type Client interface {
	// Analyze performs AI analysis on scan results
	Analyze(ctx context.Context, result models.ScanResult, analysisType models.AIAnalysisType) (*models.AIReport, error)

	// TestConnection tests the AI provider connection
	TestConnection(ctx context.Context) error

	// GetProvider returns the provider type
	GetProvider() models.APIProvider

	// GetModel returns the model being used
	GetModel() string
}

// Manager manages multiple AI clients and provides a unified interface
type Manager struct {
	clients         map[models.APIProvider]Client
	activeProvider  models.APIProvider
	defaultProvider models.APIProvider
}

// NewManager creates a new AI manager
func NewManager() *Manager {
	return &Manager{
		clients: make(map[models.APIProvider]Client),
	}
}

// RegisterClient registers an AI client for a specific provider
func (m *Manager) RegisterClient(provider models.APIProvider, client Client) {
	m.clients[provider] = client
}

// SetActiveProvider sets the active AI provider
func (m *Manager) SetActiveProvider(provider models.APIProvider) error {
	if _, exists := m.clients[provider]; !exists {
		return fmt.Errorf("provider %s not registered", provider)
	}
	m.activeProvider = provider
	return nil
}

// SetDefaultProvider sets the default AI provider
func (m *Manager) SetDefaultProvider(provider models.APIProvider) {
	m.defaultProvider = provider
}

// GetActiveClient returns the currently active AI client
func (m *Manager) GetActiveClient() (Client, error) {
	if m.activeProvider == "" {
		if m.defaultProvider == "" {
			return nil, fmt.Errorf("no active or default provider set")
		}
		m.activeProvider = m.defaultProvider
	}

	client, exists := m.clients[m.activeProvider]
	if !exists {
		return nil, fmt.Errorf("active provider %s not found", m.activeProvider)
	}

	return client, nil
}

// AnalyzeWithProvider performs analysis using a specific provider
func (m *Manager) AnalyzeWithProvider(ctx context.Context, provider models.APIProvider, result models.ScanResult, analysisType models.AIAnalysisType) (*models.AIReport, error) {
	client, exists := m.clients[provider]
	if !exists {
		return nil, fmt.Errorf("provider %s not registered", provider)
	}

	return client.Analyze(ctx, result, analysisType)
}

// Analyze performs analysis using the active provider
func (m *Manager) Analyze(ctx context.Context, result models.ScanResult, analysisType models.AIAnalysisType) (*models.AIReport, error) {
	client, err := m.GetActiveClient()
	if err != nil {
		return nil, err
	}

	return client.Analyze(ctx, result, analysisType)
}

// TestConnection tests connection for a specific provider
func (m *Manager) TestConnection(ctx context.Context, provider models.APIProvider) error {
	client, exists := m.clients[provider]
	if !exists {
		return fmt.Errorf("provider %s not registered", provider)
	}

	return client.TestConnection(ctx)
}

// TestActiveConnection tests the active provider connection
func (m *Manager) TestActiveConnection(ctx context.Context) error {
	client, err := m.GetActiveClient()
	if err != nil {
		return err
	}

	return client.TestConnection(ctx)
}

// GetRegisteredProviders returns all registered providers
func (m *Manager) GetRegisteredProviders() []models.APIProvider {
	providers := make([]models.APIProvider, 0, len(m.clients))
	for provider := range m.clients {
		providers = append(providers, provider)
	}
	return providers
}

// IsProviderRegistered checks if a provider is registered
func (m *Manager) IsProviderRegistered(provider models.APIProvider) bool {
	_, exists := m.clients[provider]
	return exists
}
