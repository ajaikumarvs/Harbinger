package scanner

import (
	"context"

	"github.com/ajaikumarvs/harbinger/internal/ai"
	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// AIEnhancedEngine wraps the Engine with AI capabilities
type AIEnhancedEngine struct {
	*Engine
	aiService *ai.Service
	enableAI  bool
}

// NewAIEnhancedEngine creates a new AI-enhanced scanning engine
func NewAIEnhancedEngine() (*AIEnhancedEngine, error) {
	baseEngine := NewEngine()

	// Initialize AI service
	aiService, err := ai.NewService()
	if err != nil {
		// AI service is optional, continue without it
		return &AIEnhancedEngine{
			Engine:    baseEngine,
			aiService: nil,
			enableAI:  false,
		}, nil
	}

	return &AIEnhancedEngine{
		Engine:    baseEngine,
		aiService: aiService,
		enableAI:  aiService.IsAIEnabled(),
	}, nil
}

// EnableAI enables or disables AI analysis
func (e *AIEnhancedEngine) EnableAI(enable bool) {
	e.enableAI = enable && e.aiService != nil && e.aiService.IsAIEnabled()
}

// IsAIEnabled returns whether AI analysis is enabled and available
func (e *AIEnhancedEngine) IsAIEnabled() bool {
	return e.enableAI
}

// GetAIService returns the AI service instance
func (e *AIEnhancedEngine) GetAIService() *ai.Service {
	return e.aiService
}

// ScanWithAI performs a comprehensive scan with AI analysis
func (e *AIEnhancedEngine) ScanWithAI(ctx context.Context, targetURL string) (*models.ScanResult, error) {
	// First perform the regular scan
	result, err := e.Engine.Scan(ctx, targetURL)
	if err != nil {
		return nil, err
	}

	// If AI is enabled and available, perform AI analysis
	if e.enableAI && e.aiService != nil {
		// Update progress to show AI analysis
		if e.progressCallback != nil {
			progress := models.ScanProgress{
				ScanID:           result.ID,
				TotalSteps:       1,
				CompletedSteps:   0,
				Progress:         0.0,
				CurrentScanner:   "AI Analysis",
				CurrentOperation: "Performing AI analysis...",
				Logs:             []string{"Starting AI analysis"},
			}
			e.progressCallback(progress)
		}

		if e.logger != nil {
			e.logger("Starting AI analysis")
		}

		// Perform comprehensive AI analysis
		aiReport, err := e.aiService.PerformFullAnalysis(ctx, *result)
		if err != nil {
			if e.logger != nil {
				e.logger("AI analysis failed: " + err.Error())
			}
			// Continue without AI analysis - don't fail the entire scan
		} else {
			result.AIAnalysis = *aiReport
			if e.logger != nil {
				e.logger("AI analysis completed successfully")
			}
		}

		// Update progress to completion
		if e.progressCallback != nil {
			progress := models.ScanProgress{
				ScanID:           result.ID,
				TotalSteps:       1,
				CompletedSteps:   1,
				Progress:         1.0,
				CurrentScanner:   "AI Analysis",
				CurrentOperation: "AI analysis completed",
				Logs:             []string{"AI analysis completed"},
			}
			e.progressCallback(progress)
		}
	}

	return result, nil
}

// PerformSpecificAIAnalysis performs a specific type of AI analysis
func (e *AIEnhancedEngine) PerformSpecificAIAnalysis(ctx context.Context, result models.ScanResult, analysisType models.AIAnalysisType) (*models.AIReport, error) {
	if !e.enableAI || e.aiService == nil {
		return nil, &AINotAvailableError{}
	}

	return e.aiService.PerformSpecificAnalysis(ctx, result, analysisType)
}

// ConfigureAIProvider configures an AI provider
func (e *AIEnhancedEngine) ConfigureAIProvider(provider models.APIProvider, apiKey, model string) error {
	if e.aiService == nil {
		return &AINotAvailableError{}
	}

	err := e.aiService.ConfigureProvider(provider, apiKey, model)
	if err != nil {
		return err
	}

	// Update enableAI status
	e.enableAI = e.aiService.IsAIEnabled()
	return nil
}

// TestAIProvider tests an AI provider connection
func (e *AIEnhancedEngine) TestAIProvider(ctx context.Context, provider models.APIProvider) error {
	if e.aiService == nil {
		return &AINotAvailableError{}
	}

	return e.aiService.TestProvider(ctx, provider)
}

// GetAIProviders returns configured AI providers
func (e *AIEnhancedEngine) GetAIProviders() ([]models.APIKey, error) {
	if e.aiService == nil {
		return nil, &AINotAvailableError{}
	}

	return e.aiService.GetConfiguredProviders()
}

// SetActiveAIProvider sets the active AI provider
func (e *AIEnhancedEngine) SetActiveAIProvider(provider models.APIProvider) error {
	if e.aiService == nil {
		return &AINotAvailableError{}
	}

	err := e.aiService.SetActiveProvider(provider)
	if err != nil {
		return err
	}

	// Update enableAI status
	e.enableAI = e.aiService.IsAIEnabled()
	return nil
}

// GetDefaultAIEngine creates an AI-enhanced engine with all default scanners
func GetDefaultAIEngine() (*AIEnhancedEngine, error) {
	engine, err := NewAIEnhancedEngine()
	if err != nil {
		return nil, err
	}

	// Register all scanners
	engine.RegisterScanner(NewPortScanner())
	engine.RegisterScanner(NewTechnologyScanner())
	engine.RegisterScanner(NewSSLScanner())
	engine.RegisterScanner(NewHeaderScanner())
	engine.RegisterScanner(NewDNSScanner())
	engine.RegisterScanner(NewDirectoryScanner())

	return engine, nil
}

// AINotAvailableError represents an error when AI is not available
type AINotAvailableError struct{}

func (e *AINotAvailableError) Error() string {
	return "AI analysis is not available - no AI service configured"
}
