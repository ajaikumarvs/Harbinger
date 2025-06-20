package ai

import (
	"fmt"
	"strings"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// PromptTemplate represents a template for AI prompts
type PromptTemplate struct {
	SystemPrompt string
	UserPrompt   string
	OutputFormat string
}

// PromptBuilder handles building specialized prompts for different analysis types
type PromptBuilder struct {
	templates map[models.AIAnalysisType]PromptTemplate
}

// NewPromptBuilder creates a new prompt builder with pre-defined templates
func NewPromptBuilder() *PromptBuilder {
	pb := &PromptBuilder{
		templates: make(map[models.AIAnalysisType]PromptTemplate),
	}

	pb.initializeTemplates()
	return pb
}

// BuildPrompt builds a prompt for the specified analysis type and scan result
func (pb *PromptBuilder) BuildPrompt(analysisType models.AIAnalysisType, result models.ScanResult) (string, string, error) {
	template, exists := pb.templates[analysisType]
	if !exists {
		return "", "", fmt.Errorf("no template found for analysis type: %v", analysisType)
	}

	// Serialize scan data for the prompt
	scanData, err := pb.serializeScanData(result)
	if err != nil {
		return "", "", fmt.Errorf("failed to serialize scan data: %w", err)
	}

	// Build user prompt with scan data
	userPrompt := fmt.Sprintf(template.UserPrompt, scanData)

	return template.SystemPrompt, userPrompt, nil
}

// serializeScanData converts scan result to a structured string for AI analysis
func (pb *PromptBuilder) serializeScanData(result models.ScanResult) (string, error) {
	var sb strings.Builder

	// Basic scan information
	sb.WriteString(fmt.Sprintf("TARGET: %s\n", result.URL))
	sb.WriteString(fmt.Sprintf("SCAN_DATE: %s\n", result.Timestamp.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("SECURITY_SCORE: %d/100\n", result.SecurityScore))
	sb.WriteString(fmt.Sprintf("SCAN_DURATION: %v\n\n", result.ScanDuration))

	// Technologies detected
	sb.WriteString("TECHNOLOGIES_DETECTED:\n")
	if len(result.TechStack) == 0 {
		sb.WriteString("- None detected\n")
	} else {
		for _, tech := range result.TechStack {
			sb.WriteString(fmt.Sprintf("- %s %s (%s) - %.0f%% confidence\n",
				tech.Name, tech.Version, tech.Category, tech.Confidence*100))
		}
	}
	sb.WriteString("\n")

	// Vulnerabilities found
	sb.WriteString("VULNERABILITIES:\n")
	if len(result.Vulnerabilities) == 0 {
		sb.WriteString("- No vulnerabilities detected\n")
	} else {
		for _, vuln := range result.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("- CVE: %s\n", vuln.CVE))
			sb.WriteString(fmt.Sprintf("  Severity: %s (Score: %.1f)\n", vuln.Severity, vuln.Score))
			sb.WriteString(fmt.Sprintf("  Description: %s\n", vuln.Description))
			if len(vuln.AttackVectors) > 0 {
				sb.WriteString(fmt.Sprintf("  Attack Vectors: %s\n", strings.Join(vuln.AttackVectors, ", ")))
			}
			sb.WriteString(fmt.Sprintf("  Affected Technologies: %s\n", strings.Join(vuln.AffectedTech, ", ")))
			sb.WriteString("\n")
		}
	}

	return sb.String(), nil
}

// initializeTemplates sets up all the prompt templates
func (pb *PromptBuilder) initializeTemplates() {
	// Executive Summary Template
	pb.templates[models.ExecutiveSummary] = PromptTemplate{
		SystemPrompt: `You are a senior cybersecurity consultant providing executive-level security assessments. 
Your role is to translate technical security findings into business-focused insights that executives can understand and act upon.
Focus on business risk, financial impact, and strategic recommendations.`,
		UserPrompt: `Based on the following security scan results, provide an executive summary:

%s

Please provide:
1. Overall security posture assessment (1-2 sentences)
2. Top 3 business risks identified
3. Immediate actions required (prioritized)
4. Estimated effort and timeline for remediation
5. Business impact if issues remain unaddressed

Keep the language business-focused, avoid technical jargon, and emphasize urgency and business value.`,
		OutputFormat: "executive_summary",
	}

	// Technical Analysis Template
	pb.templates[models.TechnicalAnalysis] = PromptTemplate{
		SystemPrompt: `You are a technical security expert providing detailed technical analysis of security vulnerabilities.
Focus on technical details, attack vectors, exploitation methods, and technical remediation steps.`,
		UserPrompt: `Analyze the following security scan results and provide technical analysis:

%s

Provide detailed technical analysis including:
1. Technical severity assessment of each vulnerability
2. Potential attack chains and exploitation scenarios
3. Technical prerequisites for successful attacks
4. Detailed technical remediation steps
5. Technical dependencies and prerequisites for fixes
6. Risk of exploitation in the wild

Use technical terminology and provide specific technical recommendations.`,
		OutputFormat: "technical_analysis",
	}

	// Root Cause Analysis Template
	pb.templates[models.RootCauseAnalysis] = PromptTemplate{
		SystemPrompt: `You are a security architect specializing in root cause analysis.
Your expertise is in identifying underlying systemic issues that lead to security vulnerabilities.`,
		UserPrompt: `Perform root cause analysis on the following security findings:

%s

For each significant vulnerability, provide:
1. Root cause identification (configuration, design, process, or technology issue)
2. Contributing factors that enabled the vulnerability
3. Systemic issues that need to be addressed
4. Process improvements to prevent recurrence
5. Architecture or design changes needed
6. How this relates to broader security posture

Focus on prevention and systemic improvements rather than just fixing individual issues.`,
		OutputFormat: "root_cause_analysis",
	}

	// Future Threat Prediction Template
	pb.templates[models.FutureThreatPrediction] = PromptTemplate{
		SystemPrompt: `You are a threat intelligence analyst and security futurist.
Your expertise is in predicting emerging threats based on current vulnerabilities and technology trends.`,
		UserPrompt: `Based on the current security state shown below, predict future security threats:

%s

Analyze and predict:
1. Emerging threats specific to the detected technology stack
2. Likely evolution of current vulnerabilities
3. New attack vectors that may emerge (6-12 months)
4. Technology upgrade risks and security implications
5. Threat landscape changes that could affect this target
6. Proactive security measures needed

Consider technology lifecycle, threat actor capabilities, and emerging attack techniques.`,
		OutputFormat: "future_threats",
	}

	// Business Impact Assessment Template
	pb.templates[models.BusinessImpactAssessment] = PromptTemplate{
		SystemPrompt: `You are a business risk consultant specializing in cybersecurity business impact analysis.
Focus on quantifiable business risks, operational impact, and financial implications.`,
		UserPrompt: `Assess the business impact of the following security findings:

%s

Provide business impact assessment covering:
1. Operational risk (service disruption, downtime scenarios)
2. Financial impact (direct costs, opportunity costs, compliance fines)
3. Reputational risk and customer trust implications
4. Competitive disadvantage scenarios
5. Regulatory and compliance implications
6. Data breach and privacy impact potential
7. Business continuity risks

Quantify risks where possible and prioritize by business impact severity.`,
		OutputFormat: "business_impact",
	}

	// Compliance Analysis Template
	pb.templates[models.ComplianceAnalysis] = PromptTemplate{
		SystemPrompt: `You are a compliance and regulatory expert specializing in cybersecurity compliance frameworks.
Your expertise covers GDPR, SOX, HIPAA, PCI-DSS, ISO 27001, NIST, and other major frameworks.`,
		UserPrompt: `Analyze compliance implications of the following security findings:

%s

Provide compliance analysis including:
1. Specific compliance frameworks potentially affected
2. Regulatory requirements that may be violated
3. Compliance gaps identified from security findings
4. Mandatory remediation requirements by regulation
5. Reporting obligations and notification requirements
6. Audit implications and findings
7. Compliance timeline requirements

Focus on regulatory requirements and mandatory actions needed for compliance.`,
		OutputFormat: "compliance_analysis",
	}

	// Educational Insights Template
	pb.templates[models.EducationalInsights] = PromptTemplate{
		SystemPrompt: `You are a cybersecurity educator and trainer.
Your role is to provide educational content that helps teams understand security concepts and improve their security knowledge.`,
		UserPrompt: `Based on the following security scan results, provide educational insights:

%s

Create educational content covering:
1. Security concepts illustrated by the findings
2. Best practices that could have prevented these issues
3. Learning opportunities for the development/operations team
4. Security principles demonstrated by the vulnerabilities
5. Training recommendations for different team roles
6. Resources for further learning and improvement
7. Security culture improvements needed

Make the content educational, actionable, and focused on long-term security improvement.`,
		OutputFormat: "educational_insights",
	}
}

// GetAvailableAnalysisTypes returns all available analysis types
func (pb *PromptBuilder) GetAvailableAnalysisTypes() []models.AIAnalysisType {
	types := make([]models.AIAnalysisType, 0, len(pb.templates))
	for analysisType := range pb.templates {
		types = append(types, analysisType)
	}
	return types
}

// GetTemplateInfo returns information about a specific template
func (pb *PromptBuilder) GetTemplateInfo(analysisType models.AIAnalysisType) (PromptTemplate, bool) {
	template, exists := pb.templates[analysisType]
	return template, exists
}
