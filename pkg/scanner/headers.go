package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/ajaikumarvs/harbinger/internal/models"
)

// securityHeaders defines the security headers we check for
var securityHeaders = map[string]models.HeaderInfo{
	"Strict-Transport-Security": {
		Description:    "Enforces secure HTTPS connections",
		Recommendation: "Add HSTS header with max-age directive",
	},
	"Content-Security-Policy": {
		Description:    "Prevents XSS and code injection attacks",
		Recommendation: "Implement a restrictive CSP policy",
	},
	"X-Frame-Options": {
		Description:    "Prevents clickjacking attacks",
		Recommendation: "Set to DENY or SAMEORIGIN",
	},
	"X-Content-Type-Options": {
		Description:    "Prevents MIME type sniffing",
		Recommendation: "Set to nosniff",
	},
	"Referrer-Policy": {
		Description:    "Controls referrer information sent",
		Recommendation: "Set to strict-origin-when-cross-origin or stricter",
	},
	"Permissions-Policy": {
		Description:    "Controls browser feature access",
		Recommendation: "Restrict unnecessary features",
	},
	"X-XSS-Protection": {
		Description:    "Legacy XSS protection (deprecated but still useful)",
		Recommendation: "Set to 1; mode=block",
	},
}

// analyzeHeaders performs HTTP header security analysis
func (s *Scanner) analyzeHeaders(ctx context.Context, target string) (*models.HeaderAnalysis, error) {
	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set user agent
	req.Header.Set("User-Agent", s.userAgent)

	// Make request
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	// Extract headers
	headers := make(map[string]string)
	for name, values := range resp.Header {
		headers[name] = strings.Join(values, ", ")
	}

	// Analyze security headers
	secHeaders := make(map[string]models.HeaderInfo)
	var missingHeaders []string

	for headerName, info := range securityHeaders {
		headerInfo := info // Copy the base info

		if value, exists := headers[headerName]; exists {
			headerInfo.Present = true
			headerInfo.Value = value
			headerInfo.Secure = evaluateHeaderSecurity(headerName, value)
		} else {
			headerInfo.Present = false
			headerInfo.Secure = false
			missingHeaders = append(missingHeaders, headerName)
		}

		secHeaders[headerName] = headerInfo
	}

	// Calculate grade
	grade := calculateHeaderGrade(secHeaders)

	return &models.HeaderAnalysis{
		ResponseCode:    resp.StatusCode,
		Headers:         headers,
		MissingHeaders:  missingHeaders,
		SecurityHeaders: secHeaders,
		Grade:           grade,
	}, nil
}

// evaluateHeaderSecurity evaluates if a security header value is secure
func evaluateHeaderSecurity(headerName, value string) bool {
	switch headerName {
	case "Strict-Transport-Security":
		// Check for max-age and reasonable value
		return strings.Contains(value, "max-age") &&
			(strings.Contains(value, "31536000") || // 1 year
				strings.Contains(value, "15768000")) // 6 months

	case "Content-Security-Policy":
		// Basic CSP validation - should not contain 'unsafe-inline' or 'unsafe-eval' without restrictions
		return !strings.Contains(value, "'unsafe-inline'") ||
			!strings.Contains(value, "'unsafe-eval'")

	case "X-Frame-Options":
		lowerValue := strings.ToLower(value)
		return lowerValue == "deny" || lowerValue == "sameorigin"

	case "X-Content-Type-Options":
		return strings.ToLower(value) == "nosniff"

	case "Referrer-Policy":
		allowedPolicies := []string{
			"no-referrer",
			"same-origin",
			"strict-origin",
			"strict-origin-when-cross-origin",
		}
		lowerValue := strings.ToLower(value)
		for _, policy := range allowedPolicies {
			if strings.Contains(lowerValue, policy) {
				return true
			}
		}
		return false

	case "X-XSS-Protection":
		return strings.Contains(value, "1") && strings.Contains(value, "mode=block")

	case "Permissions-Policy":
		// If present, it's generally good (proper configuration is complex to validate)
		return len(value) > 0

	default:
		return len(value) > 0
	}
}

// calculateHeaderGrade calculates an overall grade for header security
func calculateHeaderGrade(headers map[string]models.HeaderInfo) string {
	totalHeaders := len(headers)
	presentHeaders := 0
	secureHeaders := 0

	for _, info := range headers {
		if info.Present {
			presentHeaders++
			if info.Secure {
				secureHeaders++
			}
		}
	}

	// Calculate percentage scores
	presenceScore := float64(presentHeaders) / float64(totalHeaders) * 100
	securityScore := float64(secureHeaders) / float64(totalHeaders) * 100

	// Combined score (weighted: 40% presence, 60% security)
	combinedScore := (presenceScore * 0.4) + (securityScore * 0.6)

	// Assign grades
	switch {
	case combinedScore >= 95:
		return "A+"
	case combinedScore >= 90:
		return "A"
	case combinedScore >= 85:
		return "A-"
	case combinedScore >= 80:
		return "B+"
	case combinedScore >= 75:
		return "B"
	case combinedScore >= 70:
		return "B-"
	case combinedScore >= 65:
		return "C+"
	case combinedScore >= 60:
		return "C"
	case combinedScore >= 55:
		return "C-"
	case combinedScore >= 50:
		return "D"
	default:
		return "F"
	}
}
