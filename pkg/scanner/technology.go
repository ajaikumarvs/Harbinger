package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// TechnologyScanner implements technology detection functionality
type TechnologyScanner struct {
	client     *http.Client
	signatures map[string]TechSignature
}

// TechSignature represents a technology detection signature
type TechSignature struct {
	Name     string
	Category string
	Headers  map[string]*regexp.Regexp
	Body     []*regexp.Regexp
	Meta     []*regexp.Regexp
	Scripts  []*regexp.Regexp
	Cookies  []*regexp.Regexp
	Implies  []string
}

// NewTechnologyScanner creates a new technology scanner
func NewTechnologyScanner() *TechnologyScanner {
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	return &TechnologyScanner{
		client:     client,
		signatures: getTechnologySignatures(),
	}
}

// Name returns the scanner name
func (ts *TechnologyScanner) Name() string {
	return "Technology Scanner"
}

// Scan performs technology detection on the target
func (ts *TechnologyScanner) Scan(ctx context.Context, target *Target) (*ScanResult, error) {
	result := &ScanResult{
		Scanner:         ts.Name(),
		Technologies:    []models.Technology{},
		Vulnerabilities: []models.Vulnerability{},
		Metadata:        make(map[string]interface{}),
		Errors:          []error{},
	}

	// Make HTTP request to the target
	req, err := http.NewRequestWithContext(ctx, "GET", target.URL.String(), nil)
	if err != nil {
		return result, fmt.Errorf("failed to create request: %w", err)
	}

	// Set realistic user agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := ts.client.Do(req)
	if err != nil {
		return result, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, fmt.Errorf("failed to read response body: %w", err)
	}

	bodyStr := string(body)
	result.Metadata["response_body_size"] = len(body)
	result.Metadata["status_code"] = resp.StatusCode

	// Detect technologies
	detectedTechs := ts.detectTechnologies(resp.Header, bodyStr)
	result.Technologies = append(result.Technologies, detectedTechs...)

	// Check for technology-specific vulnerabilities
	for _, tech := range detectedTechs {
		vulns := ts.checkTechnologyVulnerabilities(tech)
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}

	return result, nil
}

// detectTechnologies analyzes HTTP response to detect technologies
func (ts *TechnologyScanner) detectTechnologies(headers http.Header, body string) []models.Technology {
	var technologies []models.Technology
	detectedTechs := make(map[string]models.Technology)

	// Check each signature
	for name, sig := range ts.signatures {
		confidence := 0.0
		version := "unknown"

		// Check headers
		for headerName, pattern := range sig.Headers {
			if headerValue := headers.Get(headerName); headerValue != "" {
				if pattern.MatchString(headerValue) {
					confidence += 0.3
					// Try to extract version
					if matches := pattern.FindStringSubmatch(headerValue); len(matches) > 1 {
						version = matches[1]
					}
				}
			}
		}

		// Check body patterns
		for _, pattern := range sig.Body {
			if pattern.MatchString(body) {
				confidence += 0.2
				// Try to extract version
				if matches := pattern.FindStringSubmatch(body); len(matches) > 1 {
					version = matches[1]
				}
			}
		}

		// Check meta tags
		for _, pattern := range sig.Meta {
			if pattern.MatchString(body) {
				confidence += 0.25
			}
		}

		// Check script tags
		for _, pattern := range sig.Scripts {
			if pattern.MatchString(body) {
				confidence += 0.15
			}
		}

		// Check cookies
		for _, pattern := range sig.Cookies {
			if cookies := headers.Get("Set-Cookie"); cookies != "" {
				if pattern.MatchString(cookies) {
					confidence += 0.2
				}
			}
		}

		// If confidence is high enough, add to detected technologies
		if confidence >= 0.1 {
			tech := models.Technology{
				Name:       sig.Name,
				Version:    version,
				Category:   sig.Category,
				Confidence: confidence,
				Metadata: map[string]string{
					"detected_by": "technology_scanner",
				},
			}
			detectedTechs[name] = tech
		}
	}

	// Convert map to slice
	for _, tech := range detectedTechs {
		technologies = append(technologies, tech)
	}

	return technologies
}

// checkTechnologyVulnerabilities checks for known vulnerabilities in detected technologies
func (ts *TechnologyScanner) checkTechnologyVulnerabilities(tech models.Technology) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	// Check for common technology vulnerabilities
	switch strings.ToLower(tech.Name) {
	case "wordpress":
		if tech.Version != "unknown" && ts.isOutdatedWordPress(tech.Version) {
			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				CVE:         "TECH-WORDPRESS-OUTDATED",
				Severity:    "Medium",
				Score:       6.0,
				Description: fmt.Sprintf("Outdated WordPress version detected: %s", tech.Version),
				Remediation: "Update WordPress to the latest version",
				RootCause:   "Running outdated software with known vulnerabilities",
				AttackVectors: []string{
					"Known CVE exploitation",
					"Plugin vulnerabilities",
					"Theme vulnerabilities",
				},
				BusinessImpact:  "Website compromise, data theft",
				EducationalNote: "WordPress should be updated regularly to patch security vulnerabilities",
				AffectedTech:    []string{"WordPress"},
			})
		}
	case "apache":
		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			CVE:         "TECH-APACHE-INFO",
			Severity:    "Low",
			Score:       2.0,
			Description: "Apache web server version disclosure",
			Remediation: "Configure Apache to hide version information",
			RootCause:   "Information disclosure in HTTP headers",
			AttackVectors: []string{
				"Information gathering",
				"Targeted attacks based on version",
			},
			BusinessImpact:  "Information disclosure",
			EducationalNote: "Hiding server version information is a security best practice",
			AffectedTech:    []string{"Apache"},
		})
	case "nginx":
		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			CVE:         "TECH-NGINX-INFO",
			Severity:    "Low",
			Score:       2.0,
			Description: "Nginx web server version disclosure",
			Remediation: "Configure Nginx to hide version information",
			RootCause:   "Information disclosure in HTTP headers",
			AttackVectors: []string{
				"Information gathering",
				"Targeted attacks based on version",
			},
			BusinessImpact:  "Information disclosure",
			EducationalNote: "Hiding server version information is a security best practice",
			AffectedTech:    []string{"Nginx"},
		})
	case "php":
		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			CVE:         "TECH-PHP-INFO",
			Severity:    "Low",
			Score:       3.0,
			Description: "PHP version disclosure detected",
			Remediation: "Configure PHP to hide version information",
			RootCause:   "Information disclosure in HTTP headers",
			AttackVectors: []string{
				"Information gathering",
				"Targeted attacks based on version",
			},
			BusinessImpact:  "Information disclosure",
			EducationalNote: "PHP version disclosure can help attackers target specific vulnerabilities",
			AffectedTech:    []string{"PHP"},
		})
	}

	return vulnerabilities
}

// isOutdatedWordPress checks if a WordPress version is outdated
func (ts *TechnologyScanner) isOutdatedWordPress(version string) bool {
	// This is a simplified check - in a real implementation, you'd check against
	// the latest WordPress version or a database of known vulnerable versions
	outdatedVersions := []string{
		"5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8",
		"4.0", "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8", "4.9",
	}

	for _, outdated := range outdatedVersions {
		if strings.HasPrefix(version, outdated) {
			return true
		}
	}
	return false
}

// getTechnologySignatures returns the technology detection signatures
func getTechnologySignatures() map[string]TechSignature {
	signatures := make(map[string]TechSignature)

	// WordPress
	signatures["wordpress"] = TechSignature{
		Name:     "WordPress",
		Category: "CMS",
		Body: []*regexp.Regexp{
			regexp.MustCompile(`/wp-content/`),
			regexp.MustCompile(`/wp-includes/`),
			regexp.MustCompile(`wp-json`),
		},
		Meta: []*regexp.Regexp{
			regexp.MustCompile(`<meta name="generator" content="WordPress ([0-9.]+)"`),
		},
	}

	// Apache
	signatures["apache"] = TechSignature{
		Name:     "Apache",
		Category: "Web Server",
		Headers: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`Apache/([0-9.]+)`),
		},
	}

	// Nginx
	signatures["nginx"] = TechSignature{
		Name:     "Nginx",
		Category: "Web Server",
		Headers: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`nginx/([0-9.]+)`),
		},
	}

	// PHP
	signatures["php"] = TechSignature{
		Name:     "PHP",
		Category: "Programming Language",
		Headers: map[string]*regexp.Regexp{
			"X-Powered-By": regexp.MustCompile(`PHP/([0-9.]+)`),
		},
		Cookies: []*regexp.Regexp{
			regexp.MustCompile(`PHPSESSID`),
		},
	}

	// React
	signatures["react"] = TechSignature{
		Name:     "React",
		Category: "JavaScript Framework",
		Body: []*regexp.Regexp{
			regexp.MustCompile(`react`),
			regexp.MustCompile(`_react`),
		},
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`react\.js`),
			regexp.MustCompile(`react\.min\.js`),
		},
	}

	// jQuery
	signatures["jquery"] = TechSignature{
		Name:     "jQuery",
		Category: "JavaScript Library",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`jquery-([0-9.]+)\.js`),
			regexp.MustCompile(`jquery\.min\.js`),
		},
		Body: []*regexp.Regexp{
			regexp.MustCompile(`jQuery v([0-9.]+)`),
		},
	}

	// Bootstrap
	signatures["bootstrap"] = TechSignature{
		Name:     "Bootstrap",
		Category: "UI Framework",
		Body: []*regexp.Regexp{
			regexp.MustCompile(`bootstrap`),
		},
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`bootstrap\.js`),
			regexp.MustCompile(`bootstrap\.min\.js`),
		},
	}

	return signatures
}
