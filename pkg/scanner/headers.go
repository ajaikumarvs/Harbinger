package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// HeaderScanner implements security headers analysis functionality
type HeaderScanner struct {
	client *http.Client
}

// NewHeaderScanner creates a new header scanner
func NewHeaderScanner() *HeaderScanner {
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	return &HeaderScanner{
		client: client,
	}
}

// Name returns the scanner name
func (hs *HeaderScanner) Name() string {
	return "Security Headers Scanner"
}

// Scan performs security headers analysis on the target
func (hs *HeaderScanner) Scan(ctx context.Context, target *Target) (*ScanResult, error) {
	result := &ScanResult{
		Scanner:         hs.Name(),
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

	resp, err := hs.client.Do(req)
	if err != nil {
		return result, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Analyze security headers
	hs.analyzeSecurityHeaders(resp.Header, result)

	// Store header information
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}
	result.Metadata["response_headers"] = headers
	result.Metadata["status_code"] = resp.StatusCode

	return result, nil
}

// analyzeSecurityHeaders analyzes HTTP security headers
func (hs *HeaderScanner) analyzeSecurityHeaders(headers http.Header, result *ScanResult) {
	// Check for missing security headers
	hs.checkMissingHeaders(headers, result)

	// Check existing security headers for proper configuration
	hs.checkHeaderConfiguration(headers, result)

	// Check for information disclosure headers
	hs.checkInformationDisclosure(headers, result)
}

// checkMissingHeaders checks for missing security headers
func (hs *HeaderScanner) checkMissingHeaders(headers http.Header, result *ScanResult) {
	criticalHeaders := map[string]string{
		"X-Frame-Options":           "Prevents clickjacking attacks",
		"X-Content-Type-Options":    "Prevents MIME type sniffing",
		"X-XSS-Protection":          "Enables XSS protection in browsers",
		"Strict-Transport-Security": "Enforces HTTPS connections",
		"Content-Security-Policy":   "Prevents XSS and data injection attacks",
	}

	// Check critical headers
	for header, description := range criticalHeaders {
		if headers.Get(header) == "" {
			severity := "Medium"
			score := 5.0

			// HSTS is more critical for HTTPS sites
			if header == "Strict-Transport-Security" {
				severity = "High"
				score = 7.0
			}

			result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
				CVE:             fmt.Sprintf("HEADER-MISSING-%s", strings.ToUpper(strings.ReplaceAll(header, "-", "_"))),
				Severity:        severity,
				Score:           score,
				Description:     fmt.Sprintf("Missing security header: %s", header),
				Remediation:     fmt.Sprintf("Add the %s header to prevent attacks. %s", header, description),
				RootCause:       "Missing security header",
				AttackVectors:   hs.getAttackVectorsForHeader(header),
				BusinessImpact:  "Increased vulnerability to web attacks",
				EducationalNote: description,
				AffectedTech:    []string{"HTTP", "Web Server"},
			})
		}
	}
}

// checkHeaderConfiguration checks existing security headers for proper configuration
func (hs *HeaderScanner) checkHeaderConfiguration(headers http.Header, result *ScanResult) {
	// Check X-Frame-Options
	if xfo := headers.Get("X-Frame-Options"); xfo != "" {
		if strings.ToLower(xfo) == "allowall" {
			result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
				CVE:         "HEADER-XFO-ALLOWALL",
				Severity:    "High",
				Score:       7.0,
				Description: "X-Frame-Options set to ALLOWALL allows clickjacking",
				Remediation: "Set X-Frame-Options to DENY or SAMEORIGIN",
				RootCause:   "Insecure X-Frame-Options configuration",
				AttackVectors: []string{
					"Clickjacking attacks",
					"UI redress attacks",
				},
				BusinessImpact:  "Users can be tricked into performing unintended actions",
				EducationalNote: "ALLOWALL completely disables clickjacking protection",
				AffectedTech:    []string{"HTTP", "Web Server"},
			})
		}
	}

	// Check Content-Security-Policy
	if csp := headers.Get("Content-Security-Policy"); csp != "" {
		if strings.Contains(strings.ToLower(csp), "unsafe-inline") {
			result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
				CVE:         "HEADER-CSP-UNSAFE-INLINE",
				Severity:    "Medium",
				Score:       6.0,
				Description: "Content-Security-Policy allows unsafe-inline",
				Remediation: "Remove 'unsafe-inline' from CSP and use nonce or hash-based CSP",
				RootCause:   "Weak Content-Security-Policy configuration",
				AttackVectors: []string{
					"XSS attacks",
					"Script injection",
				},
				BusinessImpact:  "Reduced XSS protection",
				EducationalNote: "'unsafe-inline' weakens CSP protection against XSS",
				AffectedTech:    []string{"HTTP", "Web Server"},
			})
		}
	}
}

// checkInformationDisclosure checks for information disclosure in headers
func (hs *HeaderScanner) checkInformationDisclosure(headers http.Header, result *ScanResult) {
	disclosureHeaders := []string{
		"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
		"X-Generator", "X-Drupal-Cache", "X-Varnish",
	}

	for _, header := range disclosureHeaders {
		if value := headers.Get(header); value != "" {
			result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
				CVE:         fmt.Sprintf("HEADER-INFO-DISCLOSURE-%s", strings.ToUpper(strings.ReplaceAll(header, "-", "_"))),
				Severity:    "Low",
				Score:       2.0,
				Description: fmt.Sprintf("Information disclosure in %s header: %s", header, value),
				Remediation: fmt.Sprintf("Remove or obfuscate the %s header", header),
				RootCause:   "Information disclosure in HTTP headers",
				AttackVectors: []string{
					"Information gathering",
					"Targeted attacks based on disclosed information",
				},
				BusinessImpact:  "Information disclosure aids attackers",
				EducationalNote: "Hiding version information makes targeted attacks more difficult",
				AffectedTech:    []string{"HTTP", "Web Server"},
			})
		}
	}
}

// getAttackVectorsForHeader returns attack vectors for missing headers
func (hs *HeaderScanner) getAttackVectorsForHeader(header string) []string {
	switch header {
	case "X-Frame-Options":
		return []string{"Clickjacking attacks", "UI redress attacks"}
	case "X-Content-Type-Options":
		return []string{"MIME type sniffing", "Content type confusion"}
	case "X-XSS-Protection":
		return []string{"Cross-site scripting (XSS)", "Script injection"}
	case "Strict-Transport-Security":
		return []string{"Man-in-the-middle attacks", "Protocol downgrade attacks"}
	case "Content-Security-Policy":
		return []string{"XSS attacks", "Data injection", "Resource injection"}
	default:
		return []string{"Web application vulnerabilities"}
	}
}
