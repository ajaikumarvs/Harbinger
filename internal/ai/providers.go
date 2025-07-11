package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// GeminiClient implements the AI client interface for Google Gemini
type GeminiClient struct {
	apiKey        string
	model         string
	baseURL       string
	httpClient    *http.Client
	promptBuilder *PromptBuilder
}

// GeminiRequest represents a request to the Gemini API
type GeminiRequest struct {
	Contents []GeminiContent `json:"contents"`
}

// GeminiContent represents content in a Gemini request
type GeminiContent struct {
	Parts []GeminiPart `json:"parts"`
}

// GeminiPart represents a part of Gemini content
type GeminiPart struct {
	Text string `json:"text"`
}

// GeminiResponse represents a response from the Gemini API
type GeminiResponse struct {
	Candidates []GeminiCandidate `json:"candidates"`
}

// GeminiCandidate represents a candidate response from Gemini
type GeminiCandidate struct {
	Content GeminiContent `json:"content"`
}

// NewGeminiClient creates a new Gemini client
func NewGeminiClient(apiKey, model string) *GeminiClient {
	if model == "" {
		model = "gemini-pro"
	}

	return &GeminiClient{
		apiKey:        apiKey,
		model:         model,
		baseURL:       "https://generativelanguage.googleapis.com/v1/models",
		httpClient:    &http.Client{Timeout: 60 * time.Second},
		promptBuilder: NewPromptBuilder(),
	}
}

// Analyze performs AI analysis using Gemini
func (c *GeminiClient) Analyze(ctx context.Context, result models.ScanResult, analysisType models.AIAnalysisType) (*models.AIReport, error) {
	systemPrompt, userPrompt, err := c.promptBuilder.BuildPrompt(analysisType, result)
	if err != nil {
		return nil, fmt.Errorf("failed to build prompt: %w", err)
	}

	fullPrompt := fmt.Sprintf("%s\n\n%s", systemPrompt, userPrompt)
	response, err := c.makeRequest(ctx, fullPrompt)
	if err != nil {
		return nil, fmt.Errorf("failed to make API request: %w", err)
	}

	return c.parseResponse(response, analysisType)
}

// TestConnection tests the connection to Gemini API
func (c *GeminiClient) TestConnection(ctx context.Context) error {
	testPrompt := "Test connection. Please respond with 'Connection successful'."
	_, err := c.makeRequest(ctx, testPrompt)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	return nil
}

// GetProvider returns the provider type
func (c *GeminiClient) GetProvider() models.APIProvider {
	return models.ProviderGemini
}

// GetModel returns the model being used
func (c *GeminiClient) GetModel() string {
	return c.model
}

func (c *GeminiClient) makeRequest(ctx context.Context, prompt string) (string, error) {
	reqBody := GeminiRequest{
		Contents: []GeminiContent{{Parts: []GeminiPart{{Text: prompt}}}},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/%s:generateContent?key=%s", c.baseURL, c.model, c.apiKey)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make HTTP request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var geminiResp GeminiResponse
	if err := json.Unmarshal(respBody, &geminiResp); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("no content in response")
	}

	return geminiResp.Candidates[0].Content.Parts[0].Text, nil
}

func (c *GeminiClient) parseResponse(response string, analysisType models.AIAnalysisType) (*models.AIReport, error) {
	aiReport := &models.AIReport{}

	switch analysisType {
	case models.ExecutiveSummary:
		aiReport.ExecutiveSummary = response
	case models.TechnicalAnalysis:
		aiReport.TechnicalAnalysis = response
	case models.RootCauseAnalysis:
		aiReport.RootCauseAnalysis = map[string]string{"general": response}
	case models.BusinessImpactAssessment:
		aiReport.BusinessImpact = models.BusinessRiskAssessment{
			OverallRisk:    "Medium",
			BusinessImpact: response,
		}
	case models.ComplianceAnalysis:
		aiReport.ComplianceGaps = []models.ComplianceIssue{{Framework: "General", Gap: response}}
	case models.EducationalInsights:
		aiReport.EducationalInsights = []models.SecurityLesson{{Topic: "Security Analysis", Explanation: response}}
	default:
		return nil, fmt.Errorf("unsupported analysis type: %v", analysisType)
	}

	return aiReport, nil
}

// OpenAIClient implements the AI client interface for OpenAI
type OpenAIClient struct {
	apiKey        string
	model         string
	baseURL       string
	httpClient    *http.Client
	promptBuilder *PromptBuilder
}

// OpenAIRequest represents a request to the OpenAI API
type OpenAIRequest struct {
	Model       string          `json:"model"`
	Messages    []OpenAIMessage `json:"messages"`
	Temperature float64         `json:"temperature,omitempty"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
}

// OpenAIMessage represents a message in the OpenAI API
type OpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAIResponse represents a response from the OpenAI API
type OpenAIResponse struct {
	Choices []OpenAIChoice `json:"choices"`
}

// OpenAIChoice represents a choice in the OpenAI response
type OpenAIChoice struct {
	Message OpenAIMessage `json:"message"`
}

// NewOpenAIClient creates a new OpenAI client
func NewOpenAIClient(apiKey, model string) *OpenAIClient {
	if model == "" {
		model = "gpt-4"
	}

	return &OpenAIClient{
		apiKey:        apiKey,
		model:         model,
		baseURL:       "https://api.openai.com/v1",
		httpClient:    &http.Client{Timeout: 120 * time.Second},
		promptBuilder: NewPromptBuilder(),
	}
}

// Analyze performs AI analysis using OpenAI
func (c *OpenAIClient) Analyze(ctx context.Context, result models.ScanResult, analysisType models.AIAnalysisType) (*models.AIReport, error) {
	systemPrompt, userPrompt, err := c.promptBuilder.BuildPrompt(analysisType, result)
	if err != nil {
		return nil, fmt.Errorf("failed to build prompt: %w", err)
	}

	response, err := c.makeRequest(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("failed to make API request: %w", err)
	}

	return c.parseResponse(response, analysisType)
}

// TestConnection tests the connection to OpenAI API
func (c *OpenAIClient) TestConnection(ctx context.Context) error {
	systemPrompt := "You are a helpful assistant."
	userPrompt := "Test connection. Please respond with 'Connection successful'."
	_, err := c.makeRequest(ctx, systemPrompt, userPrompt)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	return nil
}

// GetProvider returns the provider type
func (c *OpenAIClient) GetProvider() models.APIProvider {
	return models.ProviderOpenAI
}

// GetModel returns the model being used
func (c *OpenAIClient) GetModel() string {
	return c.model
}

func (c *OpenAIClient) makeRequest(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	messages := []OpenAIMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}

	reqBody := OpenAIRequest{
		Model:       c.model,
		Messages:    messages,
		Temperature: 0.3,
		MaxTokens:   4000,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/chat/completions", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make HTTP request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var openaiResp OpenAIResponse
	if err := json.Unmarshal(respBody, &openaiResp); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(openaiResp.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}

	return openaiResp.Choices[0].Message.Content, nil
}

func (c *OpenAIClient) parseResponse(response string, analysisType models.AIAnalysisType) (*models.AIReport, error) {
	aiReport := &models.AIReport{}

	switch analysisType {
	case models.ExecutiveSummary:
		aiReport.ExecutiveSummary = response
	case models.TechnicalAnalysis:
		aiReport.TechnicalAnalysis = response
	case models.RootCauseAnalysis:
		aiReport.RootCauseAnalysis = map[string]string{"general": response}
	case models.BusinessImpactAssessment:
		aiReport.BusinessImpact = models.BusinessRiskAssessment{
			OverallRisk:    "Medium",
			BusinessImpact: response,
		}
	case models.ComplianceAnalysis:
		aiReport.ComplianceGaps = []models.ComplianceIssue{{Framework: "General", Gap: response}}
	case models.EducationalInsights:
		aiReport.EducationalInsights = []models.SecurityLesson{{Topic: "Security Analysis", Explanation: response}}
	default:
		return nil, fmt.Errorf("unsupported analysis type: %v", analysisType)
	}

	return aiReport, nil
}

// ClaudeClient implements the AI client interface for Anthropic Claude
type ClaudeClient struct {
	apiKey        string
	model         string
	baseURL       string
	httpClient    *http.Client
	promptBuilder *PromptBuilder
}

// ClaudeRequest represents a request to the Claude API
type ClaudeRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	Messages  []ClaudeMessage `json:"messages"`
	System    string          `json:"system,omitempty"`
}

// ClaudeMessage represents a message in the Claude API
type ClaudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ClaudeResponse represents a response from the Claude API
type ClaudeResponse struct {
	Content []ClaudeContent `json:"content"`
}

// ClaudeContent represents content in the Claude response
type ClaudeContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// NewClaudeClient creates a new Claude client
func NewClaudeClient(apiKey, model string) *ClaudeClient {
	if model == "" {
		model = "claude-3-sonnet-20240229"
	}

	return &ClaudeClient{
		apiKey:        apiKey,
		model:         model,
		baseURL:       "https://api.anthropic.com/v1",
		httpClient:    &http.Client{Timeout: 120 * time.Second},
		promptBuilder: NewPromptBuilder(),
	}
}

// Analyze performs AI analysis using Claude
func (c *ClaudeClient) Analyze(ctx context.Context, result models.ScanResult, analysisType models.AIAnalysisType) (*models.AIReport, error) {
	systemPrompt, userPrompt, err := c.promptBuilder.BuildPrompt(analysisType, result)
	if err != nil {
		return nil, fmt.Errorf("failed to build prompt: %w", err)
	}

	response, err := c.makeRequest(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("failed to make API request: %w", err)
	}

	return c.parseResponse(response, analysisType)
}

// TestConnection tests the connection to Claude API
func (c *ClaudeClient) TestConnection(ctx context.Context) error {
	systemPrompt := "You are a helpful assistant."
	userPrompt := "Test connection. Please respond with 'Connection successful'."
	_, err := c.makeRequest(ctx, systemPrompt, userPrompt)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	return nil
}

// GetProvider returns the provider type
func (c *ClaudeClient) GetProvider() models.APIProvider {
	return models.ProviderClaude
}

// GetModel returns the model being used
func (c *ClaudeClient) GetModel() string {
	return c.model
}

func (c *ClaudeClient) makeRequest(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	messages := []ClaudeMessage{{Role: "user", Content: userPrompt}}

	reqBody := ClaudeRequest{
		Model:     c.model,
		MaxTokens: 4000,
		Messages:  messages,
		System:    systemPrompt,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/messages", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make HTTP request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var claudeResp ClaudeResponse
	if err := json.Unmarshal(respBody, &claudeResp); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(claudeResp.Content) == 0 {
		return "", fmt.Errorf("no content in response")
	}

	return claudeResp.Content[0].Text, nil
}

func (c *ClaudeClient) parseResponse(response string, analysisType models.AIAnalysisType) (*models.AIReport, error) {
	aiReport := &models.AIReport{}

	switch analysisType {
	case models.ExecutiveSummary:
		aiReport.ExecutiveSummary = response
	case models.TechnicalAnalysis:
		aiReport.TechnicalAnalysis = response
	case models.RootCauseAnalysis:
		aiReport.RootCauseAnalysis = map[string]string{"general": response}
	case models.BusinessImpactAssessment:
		aiReport.BusinessImpact = models.BusinessRiskAssessment{
			OverallRisk:    "Medium",
			BusinessImpact: response,
		}
	case models.ComplianceAnalysis:
		aiReport.ComplianceGaps = []models.ComplianceIssue{{Framework: "General", Gap: response}}
	case models.EducationalInsights:
		aiReport.EducationalInsights = []models.SecurityLesson{{Topic: "Security Analysis", Explanation: response}}
	default:
		return nil, fmt.Errorf("unsupported analysis type: %v", analysisType)
	}

	return aiReport, nil
}

// CustomClient implements the AI client interface for custom API endpoints
type CustomClient struct {
	apiKey        string
	model         string
	baseURL       string
	httpClient    *http.Client
	promptBuilder *PromptBuilder
}

// CustomRequest represents a generic request to a custom API
type CustomRequest struct {
	Model    string                   `json:"model,omitempty"`
	Messages []map[string]interface{} `json:"messages,omitempty"`
	Prompt   string                   `json:"prompt,omitempty"`
	Input    string                   `json:"input,omitempty"`
	Query    string                   `json:"query,omitempty"`
}

// CustomResponse represents a generic response from a custom API
type CustomResponse struct {
	Response string                 `json:"response,omitempty"`
	Text     string                 `json:"text,omitempty"`
	Content  string                 `json:"content,omitempty"`
	Answer   string                 `json:"answer,omitempty"`
	Result   string                 `json:"result,omitempty"`
	Output   string                 `json:"output,omitempty"`
	Choices  []CustomChoice         `json:"choices,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
}

// CustomChoice represents a choice in a custom API response
type CustomChoice struct {
	Text    string `json:"text,omitempty"`
	Content string `json:"content,omitempty"`
	Message struct {
		Content string `json:"content,omitempty"`
	} `json:"message,omitempty"`
}

// NewCustomClient creates a new custom API client
func NewCustomClient(apiKey, model, baseURL string) *CustomClient {
	if model == "" {
		model = "default"
	}
	if baseURL == "" {
		baseURL = "http://localhost:8080/api/v1"
	}

	return &CustomClient{
		apiKey:        apiKey,
		model:         model,
		baseURL:       baseURL,
		httpClient:    &http.Client{Timeout: 120 * time.Second},
		promptBuilder: NewPromptBuilder(),
	}
}

// Analyze performs AI analysis using a custom API endpoint
func (c *CustomClient) Analyze(ctx context.Context, result models.ScanResult, analysisType models.AIAnalysisType) (*models.AIReport, error) {
	systemPrompt, userPrompt, err := c.promptBuilder.BuildPrompt(analysisType, result)
	if err != nil {
		return nil, fmt.Errorf("failed to build prompt: %w", err)
	}

	fullPrompt := fmt.Sprintf("%s\n\n%s", systemPrompt, userPrompt)
	response, err := c.makeRequest(ctx, fullPrompt)
	if err != nil {
		return nil, fmt.Errorf("failed to make API request: %w", err)
	}

	return c.parseResponse(response, analysisType)
}

// TestConnection tests the connection to the custom API
func (c *CustomClient) TestConnection(ctx context.Context) error {
	testPrompt := "Test connection. Please respond with 'Connection successful'."
	_, err := c.makeRequest(ctx, testPrompt)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	return nil
}

// GetProvider returns the provider type
func (c *CustomClient) GetProvider() models.APIProvider {
	return models.ProviderCustom
}

// GetModel returns the model being used
func (c *CustomClient) GetModel() string {
	return c.model
}

func (c *CustomClient) makeRequest(ctx context.Context, prompt string) (string, error) {
	// Try different common request formats for custom APIs
	requestFormats := []CustomRequest{
		// Format 1: OpenAI-compatible
		{
			Model: c.model,
			Messages: []map[string]interface{}{
				{"role": "user", "content": prompt},
			},
		},
		// Format 2: Simple prompt
		{
			Prompt: prompt,
		},
		// Format 3: Input field
		{
			Input: prompt,
		},
		// Format 4: Query field
		{
			Query: prompt,
		},
	}

	var lastErr error
	for _, reqBody := range requestFormats {
		response, err := c.tryRequest(ctx, reqBody)
		if err == nil {
			return response, nil
		}
		lastErr = err
	}

	return "", fmt.Errorf("all request formats failed, last error: %w", lastErr)
}

func (c *CustomClient) tryRequest(ctx context.Context, reqBody CustomRequest) (string, error) {
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Try common endpoints
	endpoints := []string{
		"/chat/completions",
		"/completions",
		"/generate",
		"/ask",
		"/query",
		"",
	}

	for _, endpoint := range endpoints {
		url := c.baseURL + endpoint
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		if c.apiKey != "" {
			// Try different authentication methods
			req.Header.Set("Authorization", "Bearer "+c.apiKey)
			req.Header.Set("X-API-Key", c.apiKey)
			req.Header.Set("API-Key", c.apiKey)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			return c.extractResponse(respBody)
		}
	}

	return "", fmt.Errorf("no working endpoint found")
}

func (c *CustomClient) extractResponse(respBody []byte) (string, error) {
	var customResp CustomResponse
	if err := json.Unmarshal(respBody, &customResp); err != nil {
		// If JSON parsing fails, try to use the raw response
		return string(respBody), nil
	}

	// Try to extract response from various possible fields
	if customResp.Response != "" {
		return customResp.Response, nil
	}
	if customResp.Text != "" {
		return customResp.Text, nil
	}
	if customResp.Content != "" {
		return customResp.Content, nil
	}
	if customResp.Answer != "" {
		return customResp.Answer, nil
	}
	if customResp.Result != "" {
		return customResp.Result, nil
	}
	if customResp.Output != "" {
		return customResp.Output, nil
	}
	if len(customResp.Choices) > 0 {
		choice := customResp.Choices[0]
		if choice.Text != "" {
			return choice.Text, nil
		}
		if choice.Content != "" {
			return choice.Content, nil
		}
		if choice.Message.Content != "" {
			return choice.Message.Content, nil
		}
	}

	// If no structured response found, return the raw JSON
	return string(respBody), nil
}

func (c *CustomClient) parseResponse(response string, analysisType models.AIAnalysisType) (*models.AIReport, error) {
	aiReport := &models.AIReport{}

	switch analysisType {
	case models.ExecutiveSummary:
		aiReport.ExecutiveSummary = response
	case models.TechnicalAnalysis:
		aiReport.TechnicalAnalysis = response
	case models.RootCauseAnalysis:
		aiReport.RootCauseAnalysis = map[string]string{"general": response}
	case models.BusinessImpactAssessment:
		aiReport.BusinessImpact = models.BusinessRiskAssessment{
			OverallRisk:    "Medium",
			BusinessImpact: response,
		}
	case models.ComplianceAnalysis:
		aiReport.ComplianceGaps = []models.ComplianceIssue{{Framework: "General", Gap: response}}
	case models.EducationalInsights:
		aiReport.EducationalInsights = []models.SecurityLesson{{Topic: "Security Analysis", Explanation: response}}
	default:
		return nil, fmt.Errorf("unsupported analysis type: %v", analysisType)
	}

	return aiReport, nil
}
