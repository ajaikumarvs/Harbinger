package comparison

import (
	"fmt"
	"strings"
	"time"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// ComparisonEngine handles scan result comparisons
type ComparisonEngine struct {
}

// NewComparisonEngine creates a new comparison engine
func NewComparisonEngine() *ComparisonEngine {
	return &ComparisonEngine{}
}

// ComparisonResult represents the result of comparing two scans
type ComparisonResult struct {
	BaselineScan  *models.ScanResult `json:"baseline_scan"`
	CurrentScan   *models.ScanResult `json:"current_scan"`
	SecurityTrend SecurityTrend      `json:"security_trend"`
	Changes       []Change           `json:"changes"`
	Summary       ComparisonSummary  `json:"summary"`
	Generated     time.Time          `json:"generated"`
}

// SecurityTrend represents the overall security trend
type SecurityTrend string

const (
	TrendImproved SecurityTrend = "improved"
	TrendDegraded SecurityTrend = "degraded"
	TrendStable   SecurityTrend = "stable"
	TrendMixed    SecurityTrend = "mixed"
)

// Change represents a specific change between scans
type Change struct {
	Type        ChangeType             `json:"type"`
	Category    string                 `json:"category"`
	Description string                 `json:"description"`
	Impact      string                 `json:"impact"`
	Severity    string                 `json:"severity"`
	Details     map[string]interface{} `json:"details"`
}

// ChangeType represents the type of change
type ChangeType string

const (
	ChangeVulnerabilityAdded   ChangeType = "vulnerability_added"
	ChangeVulnerabilityRemoved ChangeType = "vulnerability_removed"
	ChangeVulnerabilityChanged ChangeType = "vulnerability_changed"
	ChangeTechnologyAdded      ChangeType = "technology_added"
	ChangeTechnologyRemoved    ChangeType = "technology_removed"
	ChangeTechnologyUpdated    ChangeType = "technology_updated"
	ChangeSecurityScoreChanged ChangeType = "security_score_changed"
	ChangePerformanceChanged   ChangeType = "performance_changed"
)

// ComparisonSummary provides high-level comparison statistics
type ComparisonSummary struct {
	ScoreDifference        int    `json:"score_difference"`
	VulnerabilitiesAdded   int    `json:"vulnerabilities_added"`
	VulnerabilitiesRemoved int    `json:"vulnerabilities_removed"`
	TechnologiesAdded      int    `json:"technologies_added"`
	TechnologiesRemoved    int    `json:"technologies_removed"`
	TechnologiesUpdated    int    `json:"technologies_updated"`
	CriticalChanges        int    `json:"critical_changes"`
	PerformanceDifference  string `json:"performance_difference"`
}

// Compare performs a comprehensive comparison between two scan results
func (ce *ComparisonEngine) Compare(baseline, current *models.ScanResult) (*ComparisonResult, error) {
	if baseline == nil || current == nil {
		return nil, fmt.Errorf("both baseline and current scan results are required")
	}

	result := &ComparisonResult{
		BaselineScan: baseline,
		CurrentScan:  current,
		Generated:    time.Now(),
	}

	// Compare security scores
	result.Changes = append(result.Changes, ce.compareSecurityScores(baseline, current)...)

	// Compare vulnerabilities
	result.Changes = append(result.Changes, ce.compareVulnerabilities(baseline, current)...)

	// Compare technologies
	result.Changes = append(result.Changes, ce.compareTechnologies(baseline, current)...)

	// Compare performance
	result.Changes = append(result.Changes, ce.comparePerformance(baseline, current)...)

	// Generate summary
	result.Summary = ce.generateSummary(baseline, current, result.Changes)

	// Determine overall trend
	result.SecurityTrend = ce.determineTrend(result.Summary)

	return result, nil
}

// compareSecurityScores compares overall security scores
func (ce *ComparisonEngine) compareSecurityScores(baseline, current *models.ScanResult) []Change {
	var changes []Change

	scoreDiff := current.SecurityScore - baseline.SecurityScore
	if scoreDiff != 0 {
		var impact, severity string
		if scoreDiff > 0 {
			impact = "positive"
			severity = "info"
		} else {
			impact = "negative"
			severity = "warning"
			if scoreDiff < -20 {
				severity = "critical"
			} else if scoreDiff < -10 {
				severity = "high"
			}
		}

		changes = append(changes, Change{
			Type:     ChangeSecurityScoreChanged,
			Category: "security_score",
			Description: fmt.Sprintf("Security score changed from %d to %d (%+d points)",
				baseline.SecurityScore, current.SecurityScore, scoreDiff),
			Impact:   impact,
			Severity: severity,
			Details: map[string]interface{}{
				"baseline_score": baseline.SecurityScore,
				"current_score":  current.SecurityScore,
				"difference":     scoreDiff,
			},
		})
	}

	return changes
}

// compareVulnerabilities compares vulnerability lists
func (ce *ComparisonEngine) compareVulnerabilities(baseline, current *models.ScanResult) []Change {
	var changes []Change

	baselineVulns := make(map[string]models.Vulnerability)
	for _, vuln := range baseline.Vulnerabilities {
		baselineVulns[vuln.CVE] = vuln
	}

	currentVulns := make(map[string]models.Vulnerability)
	for _, vuln := range current.Vulnerabilities {
		currentVulns[vuln.CVE] = vuln
	}

	// Find added vulnerabilities
	for cve, vuln := range currentVulns {
		if _, exists := baselineVulns[cve]; !exists {
			changes = append(changes, Change{
				Type:        ChangeVulnerabilityAdded,
				Category:    "vulnerability",
				Description: fmt.Sprintf("New vulnerability detected: %s (%s severity)", cve, vuln.Severity),
				Impact:      "negative",
				Severity:    strings.ToLower(vuln.Severity),
				Details: map[string]interface{}{
					"cve":         cve,
					"severity":    vuln.Severity,
					"score":       vuln.Score,
					"description": vuln.Description,
				},
			})
		}
	}

	// Find removed vulnerabilities
	for cve, vuln := range baselineVulns {
		if _, exists := currentVulns[cve]; !exists {
			changes = append(changes, Change{
				Type:        ChangeVulnerabilityRemoved,
				Category:    "vulnerability",
				Description: fmt.Sprintf("Vulnerability resolved: %s (%s severity)", cve, vuln.Severity),
				Impact:      "positive",
				Severity:    "info",
				Details: map[string]interface{}{
					"cve":         cve,
					"severity":    vuln.Severity,
					"score":       vuln.Score,
					"description": vuln.Description,
				},
			})
		}
	}

	// Find changed vulnerabilities (same CVE, different severity/score)
	for cve, currentVuln := range currentVulns {
		if baselineVuln, exists := baselineVulns[cve]; exists {
			if baselineVuln.Severity != currentVuln.Severity || baselineVuln.Score != currentVuln.Score {
				var impact string
				if currentVuln.Score < baselineVuln.Score {
					impact = "positive"
				} else {
					impact = "negative"
				}

				changes = append(changes, Change{
					Type:     ChangeVulnerabilityChanged,
					Category: "vulnerability",
					Description: fmt.Sprintf("Vulnerability %s changed: %s (%.1f) -> %s (%.1f)",
						cve, baselineVuln.Severity, baselineVuln.Score,
						currentVuln.Severity, currentVuln.Score),
					Impact:   impact,
					Severity: strings.ToLower(currentVuln.Severity),
					Details: map[string]interface{}{
						"cve":               cve,
						"baseline_severity": baselineVuln.Severity,
						"current_severity":  currentVuln.Severity,
						"baseline_score":    baselineVuln.Score,
						"current_score":     currentVuln.Score,
					},
				})
			}
		}
	}

	return changes
}

// compareTechnologies compares technology stacks
func (ce *ComparisonEngine) compareTechnologies(baseline, current *models.ScanResult) []Change {
	var changes []Change

	baselineTech := make(map[string]models.Technology)
	for _, tech := range baseline.TechStack {
		baselineTech[tech.Name] = tech
	}

	currentTech := make(map[string]models.Technology)
	for _, tech := range current.TechStack {
		currentTech[tech.Name] = tech
	}

	// Find added technologies
	for name, tech := range currentTech {
		if _, exists := baselineTech[name]; !exists {
			changes = append(changes, Change{
				Type:        ChangeTechnologyAdded,
				Category:    "technology",
				Description: fmt.Sprintf("New technology detected: %s %s (%s)", name, tech.Version, tech.Category),
				Impact:      "neutral",
				Severity:    "info",
				Details: map[string]interface{}{
					"name":       name,
					"version":    tech.Version,
					"category":   tech.Category,
					"confidence": tech.Confidence,
				},
			})
		}
	}

	// Find removed technologies
	for name, tech := range baselineTech {
		if _, exists := currentTech[name]; !exists {
			changes = append(changes, Change{
				Type:        ChangeTechnologyRemoved,
				Category:    "technology",
				Description: fmt.Sprintf("Technology no longer detected: %s %s", name, tech.Version),
				Impact:      "neutral",
				Severity:    "info",
				Details: map[string]interface{}{
					"name":     name,
					"version":  tech.Version,
					"category": tech.Category,
				},
			})
		}
	}

	// Find updated technologies
	for name, currentTech := range currentTech {
		if baselineTech, exists := baselineTech[name]; exists {
			if baselineTech.Version != currentTech.Version {
				changes = append(changes, Change{
					Type:        ChangeTechnologyUpdated,
					Category:    "technology",
					Description: fmt.Sprintf("Technology updated: %s %s -> %s", name, baselineTech.Version, currentTech.Version),
					Impact:      "positive", // Assume updates are generally good
					Severity:    "info",
					Details: map[string]interface{}{
						"name":             name,
						"baseline_version": baselineTech.Version,
						"current_version":  currentTech.Version,
						"category":         currentTech.Category,
					},
				})
			}
		}
	}

	return changes
}

// comparePerformance compares scan performance metrics
func (ce *ComparisonEngine) comparePerformance(baseline, current *models.ScanResult) []Change {
	var changes []Change

	timeDiff := current.ScanDuration - baseline.ScanDuration
	if timeDiff != 0 {
		var impact, severity string
		var description string

		if timeDiff < 0 {
			impact = "positive"
			severity = "info"
			description = fmt.Sprintf("Scan performance improved: %v faster", -timeDiff)
		} else {
			impact = "negative"
			severity = "warning"
			description = fmt.Sprintf("Scan performance degraded: %v slower", timeDiff)

			// If significantly slower, mark as more severe
			if timeDiff > time.Minute*5 {
				severity = "high"
			}
		}

		changes = append(changes, Change{
			Type:        ChangePerformanceChanged,
			Category:    "performance",
			Description: description,
			Impact:      impact,
			Severity:    severity,
			Details: map[string]interface{}{
				"baseline_duration": baseline.ScanDuration,
				"current_duration":  current.ScanDuration,
				"difference":        timeDiff,
			},
		})
	}

	return changes
}

// generateSummary creates a high-level summary of changes
func (ce *ComparisonEngine) generateSummary(baseline, current *models.ScanResult, changes []Change) ComparisonSummary {
	summary := ComparisonSummary{
		ScoreDifference: current.SecurityScore - baseline.SecurityScore,
	}

	for _, change := range changes {
		switch change.Type {
		case ChangeVulnerabilityAdded:
			summary.VulnerabilitiesAdded++
			if change.Severity == "critical" || change.Severity == "high" {
				summary.CriticalChanges++
			}
		case ChangeVulnerabilityRemoved:
			summary.VulnerabilitiesRemoved++
		case ChangeTechnologyAdded:
			summary.TechnologiesAdded++
		case ChangeTechnologyRemoved:
			summary.TechnologiesRemoved++
		case ChangeTechnologyUpdated:
			summary.TechnologiesUpdated++
		case ChangePerformanceChanged:
			if change.Impact == "positive" {
				summary.PerformanceDifference = "improved"
			} else {
				summary.PerformanceDifference = "degraded"
			}
		}
	}

	return summary
}

// determineTrend determines the overall security trend
func (ce *ComparisonEngine) determineTrend(summary ComparisonSummary) SecurityTrend {
	scoreChange := summary.ScoreDifference
	criticalChanges := summary.CriticalChanges
	vulnChanges := summary.VulnerabilitiesAdded - summary.VulnerabilitiesRemoved

	// If critical vulnerabilities were added, it's degraded regardless of score
	if summary.VulnerabilitiesAdded > 0 && criticalChanges > 0 {
		return TrendDegraded
	}

	// If score improved significantly and no critical issues
	if scoreChange >= 10 && criticalChanges == 0 {
		return TrendImproved
	}

	// If score degraded significantly or many new vulnerabilities
	if scoreChange <= -10 || vulnChanges > 3 {
		return TrendDegraded
	}

	// Mixed changes
	if (scoreChange > 0 && vulnChanges > 0) || (scoreChange < 0 && vulnChanges < 0) {
		return TrendMixed
	}

	// Otherwise stable
	return TrendStable
}

// GenerateComparisonReport creates a human-readable comparison report
func (ce *ComparisonEngine) GenerateComparisonReport(comparison *ComparisonResult) string {
	var report strings.Builder

	report.WriteString(fmt.Sprintf("Scan Comparison Report\n"))
	report.WriteString(fmt.Sprintf("======================\n\n"))

	report.WriteString(fmt.Sprintf("Baseline Scan: %s (Score: %d/100)\n",
		comparison.BaselineScan.Timestamp.Format("2006-01-02 15:04"),
		comparison.BaselineScan.SecurityScore))

	report.WriteString(fmt.Sprintf("Current Scan:  %s (Score: %d/100)\n",
		comparison.CurrentScan.Timestamp.Format("2006-01-02 15:04"),
		comparison.CurrentScan.SecurityScore))

	report.WriteString(fmt.Sprintf("Overall Trend: %s\n\n", strings.ToUpper(string(comparison.SecurityTrend))))

	// Summary
	report.WriteString("Summary:\n")
	report.WriteString(fmt.Sprintf("- Security Score Change: %+d points\n", comparison.Summary.ScoreDifference))
	report.WriteString(fmt.Sprintf("- Vulnerabilities: +%d, -%d\n",
		comparison.Summary.VulnerabilitiesAdded, comparison.Summary.VulnerabilitiesRemoved))
	report.WriteString(fmt.Sprintf("- Technologies: +%d, -%d, ~%d\n",
		comparison.Summary.TechnologiesAdded, comparison.Summary.TechnologiesRemoved, comparison.Summary.TechnologiesUpdated))
	report.WriteString(fmt.Sprintf("- Critical Changes: %d\n\n", comparison.Summary.CriticalChanges))

	// Detailed changes
	if len(comparison.Changes) > 0 {
		report.WriteString("Detailed Changes:\n")
		for i, change := range comparison.Changes {
			report.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, strings.ToUpper(change.Severity), change.Description))
		}
	}

	return report.String()
}
