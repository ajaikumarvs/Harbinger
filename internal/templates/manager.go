package templates

import (
	"bytes"
	"fmt"
	"html/template"
	"time"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// TemplateManager handles report template processing
type TemplateManager struct {
	templates map[string]*template.Template
}

// TemplateData represents the data passed to templates
type TemplateData struct {
	Result    *models.ScanResult `json:"result"`
	Generated time.Time          `json:"generated"`
	Company   string             `json:"company"`
	Version   string             `json:"version"`
}

// NewTemplateManager creates a new template manager
func NewTemplateManager() *TemplateManager {
	tm := &TemplateManager{
		templates: make(map[string]*template.Template),
	}

	// Initialize default templates
	tm.initializeDefaultTemplates()

	return tm
}

// initializeDefaultTemplates creates built-in report templates
func (tm *TemplateManager) initializeDefaultTemplates() {
	// Simple templates
	templates := map[string]string{
		"executive": `Executive Summary Report
Target: {{.Result.URL}}
Generated: {{formatTime .Generated}}
Security Score: {{.Result.SecurityScore}}/100
Vulnerabilities Found: {{len .Result.Vulnerabilities}}
Technologies Detected: {{len .Result.TechStack}}
{{if .Result.AIAnalysis.ExecutiveSummary}}

Executive Summary:
{{.Result.AIAnalysis.ExecutiveSummary}}
{{end}}`,

		"technical": `Technical Security Assessment
Target: {{.Result.URL}}
Scan Date: {{formatTime .Result.Timestamp}}
Security Score: {{.Result.SecurityScore}}/100
Scan Duration: {{formatDuration .Result.ScanDuration}}

Technology Stack:
{{range .Result.TechStack}}
- {{.Name}} {{.Version}} ({{.Category}}) - {{multiply .Confidence 100}}% confidence
{{end}}

Vulnerabilities:
{{if .Result.Vulnerabilities}}
{{range .Result.Vulnerabilities}}
- {{.CVE}} ({{.Severity}}): {{.Description}}
{{end}}
{{else}}
No vulnerabilities detected.
{{end}}`,

		"simple": `Security Report for {{.Result.URL}}
Score: {{.Result.SecurityScore}}/100
Generated: {{formatTime .Generated}}
Vulnerabilities: {{len .Result.Vulnerabilities}}`,
	}

	for id, templateStr := range templates {
		tmpl, err := tm.createTemplate(templateStr)
		if err == nil {
			tm.templates[id] = tmpl
		}
	}
}

// createTemplate creates a template with helper functions
func (tm *TemplateManager) createTemplate(templateStr string) (*template.Template, error) {
	funcMap := template.FuncMap{
		"formatTime":     formatTime,
		"formatDuration": formatDuration,
		"multiply":       multiply,
	}

	return template.New("report").Funcs(funcMap).Parse(templateStr)
}

// GenerateReport generates a report using the specified template
func (tm *TemplateManager) GenerateReport(templateID string, data TemplateData) (string, error) {
	tmpl, exists := tm.templates[templateID]
	if !exists {
		return "", fmt.Errorf("template '%s' not found", templateID)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template '%s': %w", templateID, err)
	}

	return buf.String(), nil
}

// GetAvailableTemplates returns a list of available templates
func (tm *TemplateManager) GetAvailableTemplates() []string {
	var templates []string
	for id := range tm.templates {
		templates = append(templates, id)
	}
	return templates
}

// Helper functions
func formatTime(t time.Time) string {
	return t.Format("January 2, 2006 at 3:04 PM MST")
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1f seconds", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.1f minutes", d.Minutes())
	}
	return fmt.Sprintf("%.1f hours", d.Hours())
}

func multiply(a, b float64) int {
	return int(a * b)
}
