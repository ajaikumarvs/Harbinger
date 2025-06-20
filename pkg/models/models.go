package models

import (
	"time"
)

// AIAnalysisType represents different types of AI analysis
type AIAnalysisType int

const (
	ExecutiveSummary AIAnalysisType = iota
	TechnicalAnalysis
	RootCauseAnalysis
	FutureThreatPrediction
	RemediationStrategy
	BusinessImpactAssessment
	ComplianceAnalysis
	EducationalInsights
)

// ScanStatus represents the current status of a scan
type ScanStatus int

const (
	ScanStatusPending ScanStatus = iota
	ScanStatusRunning
	ScanStatusCompleted
	ScanStatusFailed
)

// Technology represents a detected technology
type Technology struct {
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	Category   string            `json:"category"`
	Confidence float64           `json:"confidence"`
	Metadata   map[string]string `json:"metadata"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	CVE             string   `json:"cve"`
	Severity        string   `json:"severity"`
	Score           float64  `json:"score"`
	Description     string   `json:"description"`
	Remediation     string   `json:"remediation"`
	RootCause       string   `json:"root_cause"`       // AI-generated explanation
	AttackVectors   []string `json:"attack_vectors"`   // Possible exploitation methods
	BusinessImpact  string   `json:"business_impact"`  // Impact on business operations
	EducationalNote string   `json:"educational_note"` // Learning explanation
	AffectedTech    []string `json:"affected_tech"`    // Technologies affected
}

// RemediationStep represents a step in the remediation plan
type RemediationStep struct {
	Priority    int    `json:"priority"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Effort      string `json:"effort"`
	Timeline    string `json:"timeline"`
}

// BusinessRiskAssessment represents business impact analysis
type BusinessRiskAssessment struct {
	OverallRisk     string   `json:"overall_risk"`
	CriticalAssets  []string `json:"critical_assets"`
	BusinessImpact  string   `json:"business_impact"`
	ReputationRisk  string   `json:"reputation_risk"`
	FinancialImpact string   `json:"financial_impact"`
}

// ComplianceIssue represents a compliance gap
type ComplianceIssue struct {
	Framework   string `json:"framework"`
	Requirement string `json:"requirement"`
	Gap         string `json:"gap"`
	Remediation string `json:"remediation"`
}

// SecurityLesson represents educational content
type SecurityLesson struct {
	Topic        string   `json:"topic"`
	Explanation  string   `json:"explanation"`
	BestPractice string   `json:"best_practice"`
	References   []string `json:"references"`
}

// EmergingThreat represents future threat predictions
type EmergingThreat struct {
	Description      string   `json:"description"`
	Probability      float64  `json:"probability"`
	TimeFrame        string   `json:"timeframe"`
	Mitigation       string   `json:"mitigation"`
	TechStackRelated []string `json:"tech_stack_related"`
}

// TechRisk represents technology-specific risks
type TechRisk struct {
	Technology  string  `json:"technology"`
	Risk        string  `json:"risk"`
	Probability float64 `json:"probability"`
	Impact      string  `json:"impact"`
}

// UpgradeAdvice represents upgrade recommendations
type UpgradeAdvice struct {
	Technology         string `json:"technology"`
	CurrentVersion     string `json:"current_version"`
	RecommendedVersion string `json:"recommended_version"`
	Reason             string `json:"reason"`
	Priority           string `json:"priority"`
}

// TimelineAlert represents timeline-based warnings
type TimelineAlert struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Date        time.Time `json:"date"`
	Action      string    `json:"action"`
}

// PredictiveAnalysis represents AI-generated predictions
type PredictiveAnalysis struct {
	FutureThreats          []EmergingThreat `json:"future_threats"`
	TechnologyRisks        []TechRisk       `json:"technology_risks"`
	UpgradeRecommendations []UpgradeAdvice  `json:"upgrade_recommendations"`
	TimelineWarnings       []TimelineAlert  `json:"timeline_warnings"`
}

// AIReport represents comprehensive AI analysis
type AIReport struct {
	ExecutiveSummary    string                 `json:"executive_summary"`
	TechnicalAnalysis   string                 `json:"technical_analysis"`
	RootCauseAnalysis   map[string]string      `json:"root_cause_analysis"` // CVE -> Root cause
	RemediationPlan     []RemediationStep      `json:"remediation_plan"`
	BusinessImpact      BusinessRiskAssessment `json:"business_impact"`
	ComplianceGaps      []ComplianceIssue      `json:"compliance_gaps"`
	EducationalInsights []SecurityLesson       `json:"educational_insights"`
}

// ScanResult represents the complete scan result
type ScanResult struct {
	ID                 string             `json:"id"`
	URL                string             `json:"url"`
	Timestamp          time.Time          `json:"timestamp"`
	Status             ScanStatus         `json:"status"`
	TechStack          []Technology       `json:"tech_stack"`
	Vulnerabilities    []Vulnerability    `json:"vulnerabilities"`
	SecurityScore      int                `json:"security_score"`
	AIAnalysis         AIReport           `json:"ai_analysis"`
	PredictiveInsights PredictiveAnalysis `json:"predictive_insights"`
	ScanDuration       time.Duration      `json:"scan_duration"`
	ScannersUsed       []string           `json:"scanners_used"`
	APICallsUsed       map[string]int     `json:"api_calls_used"`
}

// ScanProgress represents the progress of an ongoing scan
type ScanProgress struct {
	ScanID           string        `json:"scan_id"`
	CurrentScanner   string        `json:"current_scanner"`
	CompletedSteps   int           `json:"completed_steps"`
	TotalSteps       int           `json:"total_steps"`
	Progress         float64       `json:"progress"`
	ETA              time.Duration `json:"eta"`
	ActiveScanners   []string      `json:"active_scanners"`
	CurrentOperation string        `json:"current_operation"`
	Logs             []string      `json:"logs"`
}

// APIProvider represents different AI providers
type APIProvider string

const (
	ProviderGemini APIProvider = "gemini"
	ProviderOpenAI APIProvider = "openai"
	ProviderClaude APIProvider = "claude"
	ProviderCustom APIProvider = "custom"
)

// APIKey represents stored API key information
type APIKey struct {
	Provider   APIProvider `json:"provider"`
	Key        string      `json:"key"`
	IsActive   bool        `json:"is_active"`
	LastTested time.Time   `json:"last_tested"`
	TestStatus string      `json:"test_status"`
	Model      string      `json:"model"`
	CustomURL  string      `json:"custom_url,omitempty"`
}

// AppConfig represents application configuration
type AppConfig struct {
	APIKeys           []APIKey    `json:"api_keys"`
	DefaultProvider   APIProvider `json:"default_provider"`
	ScanConcurrency   int         `json:"scan_concurrency"`
	ExportPreferences ExportPrefs `json:"export_preferences"`
	Theme             ThemeConfig `json:"theme"`
}

// ExportPrefs represents export preferences
type ExportPrefs struct {
	DefaultFormat     string `json:"default_format"`
	IncludeCharts     bool   `json:"include_charts"`
	IncludeAIAnalysis bool   `json:"include_ai_analysis"`
	CompanyLogo       string `json:"company_logo"`
	CompanyName       string `json:"company_name"`
}

// ThemeConfig represents theme configuration
type ThemeConfig struct {
	ColorScheme    string `json:"color_scheme"`
	VimBindings    bool   `json:"vim_bindings"`
	ShowProgress   bool   `json:"show_progress"`
	AnimationSpeed string `json:"animation_speed"`
}
