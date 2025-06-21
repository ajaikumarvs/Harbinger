package ai

import (
	"context"
	"fmt"
	"time"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// Service provides AI analysis capabilities
type Service struct {
	manager  *Manager
	keyStore *KeyStore
	config   *Config
}

// Config represents AI service configuration
type Config struct {
	DefaultProvider models.APIProvider
	Timeout         time.Duration
	MaxRetries      int
}

// NewService creates a new AI service
func NewService() (*Service, error) {
	manager := NewManager()

	keyStore, err := NewKeyStore()
	if err != nil {
		return nil, fmt.Errorf("failed to create key store: %w", err)
	}

	config := &Config{
		DefaultProvider: models.ProviderGemini,
		Timeout:         120 * time.Second,
		MaxRetries:      3,
	}

	service := &Service{
		manager:  manager,
		keyStore: keyStore,
		config:   config,
	}

	// Initialize providers
	if err := service.initializeProviders(); err != nil {
		return nil, fmt.Errorf("failed to initialize providers: %w", err)
	}

	return service, nil
}

// PerformFullAnalysis performs comprehensive AI analysis on scan results
func (s *Service) PerformFullAnalysis(ctx context.Context, result models.ScanResult) (*models.AIReport, error) {
	client, err := s.manager.GetActiveClient()
	if err != nil {
		return nil, fmt.Errorf("no active AI provider configured: %w", err)
	}

	// Perform executive summary analysis
	executiveReport, err := client.Analyze(ctx, result, models.ExecutiveSummary)
	if err != nil {
		return nil, fmt.Errorf("failed to generate executive summary: %w", err)
	}

	// Perform technical analysis
	technicalReport, err := client.Analyze(ctx, result, models.TechnicalAnalysis)
	if err != nil {
		return nil, fmt.Errorf("failed to generate technical analysis: %w", err)
	}

	// Perform root cause analysis
	rootCauseReport, err := client.Analyze(ctx, result, models.RootCauseAnalysis)
	if err != nil {
		return nil, fmt.Errorf("failed to generate root cause analysis: %w", err)
	}

	// Perform business impact assessment
	businessReport, err := client.Analyze(ctx, result, models.BusinessImpactAssessment)
	if err != nil {
		return nil, fmt.Errorf("failed to generate business impact assessment: %w", err)
	}

	// Perform compliance analysis
	complianceReport, err := client.Analyze(ctx, result, models.ComplianceAnalysis)
	if err != nil {
		return nil, fmt.Errorf("failed to generate compliance analysis: %w", err)
	}

	// Perform educational insights
	educationalReport, err := client.Analyze(ctx, result, models.EducationalInsights)
	if err != nil {
		return nil, fmt.Errorf("failed to generate educational insights: %w", err)
	}

	// Combine all analyses into a comprehensive report
	fullReport := &models.AIReport{
		ExecutiveSummary:    executiveReport.ExecutiveSummary,
		TechnicalAnalysis:   technicalReport.TechnicalAnalysis,
		RootCauseAnalysis:   rootCauseReport.RootCauseAnalysis,
		BusinessImpact:      businessReport.BusinessImpact,
		ComplianceGaps:      complianceReport.ComplianceGaps,
		EducationalInsights: educationalReport.EducationalInsights,
		RemediationPlan:     s.generateRemediationPlan(result),
	}

	return fullReport, nil
}

// PerformSpecificAnalysis performs a specific type of AI analysis
func (s *Service) PerformSpecificAnalysis(ctx context.Context, result models.ScanResult, analysisType models.AIAnalysisType) (*models.AIReport, error) {
	client, err := s.manager.GetActiveClient()
	if err != nil {
		return nil, fmt.Errorf("no active AI provider configured: %w", err)
	}

	return client.Analyze(ctx, result, analysisType)
}

// ConfigureProvider sets up an AI provider with API key
func (s *Service) ConfigureProvider(provider models.APIProvider, apiKey, model string) error {
	return s.ConfigureProviderWithURL(provider, apiKey, model, "")
}

// ConfigureProviderWithURL sets up an AI provider with API key and custom URL
func (s *Service) ConfigureProviderWithURL(provider models.APIProvider, apiKey, model, customURL string) error {
	// Store the API key securely
	key := models.APIKey{
		Provider:   provider,
		Key:        apiKey,
		Model:      model,
		CustomURL:  customURL,
		IsActive:   false,
		TestStatus: "Not tested",
	}

	if err := s.keyStore.StoreAPIKey(key); err != nil {
		return fmt.Errorf("failed to store API key: %w", err)
	}

	// Create and register the client
	var client Client
	switch provider {
	case models.ProviderGemini:
		client = NewGeminiClient(apiKey, model)
	case models.ProviderOpenAI:
		client = NewOpenAIClient(apiKey, model)
	case models.ProviderClaude:
		client = NewClaudeClient(apiKey, model)
	case models.ProviderCustom:
		client = NewCustomClient(apiKey, model, customURL)
	default:
		return fmt.Errorf("unsupported provider: %s", provider)
	}

	s.manager.RegisterClient(provider, client)

	return nil
}

// TestProvider tests the connection to a specific AI provider
func (s *Service) TestProvider(ctx context.Context, provider models.APIProvider) error {
	err := s.manager.TestConnection(ctx, provider)

	// Update the key status
	status := "Connection successful"
	isActive := true
	if err != nil {
		status = fmt.Sprintf("Connection failed: %v", err)
		isActive = false
	}

	if updateErr := s.keyStore.UpdateAPIKeyStatus(provider, status, isActive); updateErr != nil {
		// Log the error but don't fail the test
		fmt.Printf("Warning: Failed to update key status: %v\n", updateErr)
	}

	return err
}

// SetActiveProvider sets the active AI provider
func (s *Service) SetActiveProvider(provider models.APIProvider) error {
	return s.manager.SetActiveProvider(provider)
}

// GetConfiguredProviders returns all configured providers
func (s *Service) GetConfiguredProviders() ([]models.APIKey, error) {
	return s.keyStore.GetAllAPIKeys()
}

// GetActiveProvider returns the currently active provider
func (s *Service) GetActiveProvider() (models.APIProvider, error) {
	client, err := s.manager.GetActiveClient()
	if err != nil {
		return "", err
	}
	return client.GetProvider(), nil
}

// RemoveProvider removes a provider configuration
func (s *Service) RemoveProvider(provider models.APIProvider) error {
	return s.keyStore.DeleteAPIKey(provider)
}

// IsAIEnabled checks if AI analysis is available
func (s *Service) IsAIEnabled() bool {
	_, err := s.manager.GetActiveClient()
	return err == nil
}

// initializeProviders initializes all configured providers
func (s *Service) initializeProviders() error {
	keys, err := s.keyStore.GetAllAPIKeys()
	if err != nil {
		return fmt.Errorf("failed to load API keys: %w", err)
	}

	var activeProvider models.APIProvider

	for _, key := range keys {
		var client Client
		switch key.Provider {
		case models.ProviderGemini:
			client = NewGeminiClient(key.Key, key.Model)
		case models.ProviderOpenAI:
			client = NewOpenAIClient(key.Key, key.Model)
		case models.ProviderClaude:
			client = NewClaudeClient(key.Key, key.Model)
		case models.ProviderCustom:
			client = NewCustomClient(key.Key, key.Model, key.CustomURL)
		default:
			continue // Skip unsupported providers
		}

		s.manager.RegisterClient(key.Provider, client)

		if key.IsActive {
			activeProvider = key.Provider
		}
	}

	// Set active provider
	if activeProvider != "" {
		s.manager.SetActiveProvider(activeProvider)
	} else if len(keys) > 0 {
		// Set first provider as active if no active provider is set
		s.manager.SetActiveProvider(keys[0].Provider)
	}

	return nil
}

// generateRemediationPlan generates a prioritized remediation plan
func (s *Service) generateRemediationPlan(result models.ScanResult) []models.RemediationStep {
	var steps []models.RemediationStep

	// Sort vulnerabilities by severity and generate remediation steps
	criticalCount := 0
	highCount := 0
	mediumCount := 0

	for _, vuln := range result.Vulnerabilities {
		switch vuln.Severity {
		case "Critical":
			criticalCount++
		case "High":
			highCount++
		case "Medium":
			mediumCount++
		}
	}

	priority := 1

	if criticalCount > 0 {
		steps = append(steps, models.RemediationStep{
			Priority:    priority,
			Description: fmt.Sprintf("Address %d critical vulnerabilities immediately", criticalCount),
			Impact:      "High - Immediate security risk",
			Effort:      "High",
			Timeline:    "Within 24 hours",
		})
		priority++
	}

	if highCount > 0 {
		steps = append(steps, models.RemediationStep{
			Priority:    priority,
			Description: fmt.Sprintf("Fix %d high-severity vulnerabilities", highCount),
			Impact:      "Medium - Significant security risk",
			Effort:      "Medium",
			Timeline:    "Within 1 week",
		})
		priority++
	}

	if mediumCount > 0 {
		steps = append(steps, models.RemediationStep{
			Priority:    priority,
			Description: fmt.Sprintf("Resolve %d medium-severity vulnerabilities", mediumCount),
			Impact:      "Low - Moderate security risk",
			Effort:      "Low",
			Timeline:    "Within 1 month",
		})
		priority++
	}

	// Add general security improvements
	steps = append(steps, models.RemediationStep{
		Priority:    priority,
		Description: "Implement regular security scanning and monitoring",
		Impact:      "High - Long-term security posture",
		Effort:      "Medium",
		Timeline:    "Ongoing",
	})

	return steps
}
