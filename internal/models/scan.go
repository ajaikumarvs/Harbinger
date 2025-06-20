package models

import (
	"time"
)

// ScanResult represents the complete scan result
type ScanResult struct {
	Target          string           `json:"target"`
	Timestamp       time.Time        `json:"timestamp"`
	Duration        time.Duration    `json:"duration"`
	Headers         *HeaderAnalysis  `json:"headers"`
	SSL             *SSLAnalysis     `json:"ssl"`
	Technology      *TechnologyStack `json:"technology"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
	Subdomains      []string         `json:"subdomains"`
	ArchivedURLs    []string         `json:"archived_urls"`
	AISummary       string           `json:"ai_summary"`
	Score           *SecurityScore   `json:"score"`
}

// HeaderAnalysis represents HTTP header security analysis
type HeaderAnalysis struct {
	ResponseCode    int                   `json:"response_code"`
	Headers         map[string]string     `json:"headers"`
	MissingHeaders  []string              `json:"missing_headers"`
	SecurityHeaders map[string]HeaderInfo `json:"security_headers"`
	Grade           string                `json:"grade"`
}

// HeaderInfo represents information about a specific header
type HeaderInfo struct {
	Present        bool   `json:"present"`
	Value          string `json:"value"`
	Secure         bool   `json:"secure"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

// SSLAnalysis represents SSL/TLS certificate analysis
type SSLAnalysis struct {
	Enabled         bool      `json:"enabled"`
	Version         string    `json:"version"`
	Cipher          string    `json:"cipher"`
	Certificate     *CertInfo `json:"certificate"`
	Grade           string    `json:"grade"`
	Vulnerabilities []string  `json:"vulnerabilities"`
}

// CertInfo represents SSL certificate information
type CertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	SerialNumber       string    `json:"serial_number"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	KeyAlgorithm       string    `json:"key_algorithm"`
	KeySize            int       `json:"key_size"`
	DNSNames           []string  `json:"dns_names"`
	IsExpired          bool      `json:"is_expired"`
	IsWildcard         bool      `json:"is_wildcard"`
}

// TechnologyStack represents detected technologies
type TechnologyStack struct {
	WebServer  []string `json:"web_server"`
	Language   []string `json:"language"`
	Framework  []string `json:"framework"`
	CMS        []string `json:"cms"`
	Database   []string `json:"database"`
	JavaScript []string `json:"javascript"`
	Analytics  []string `json:"analytics"`
	CDN        []string `json:"cdn"`
	Other      []string `json:"other"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Score       float64   `json:"score"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Impact      string    `json:"impact"`
	Solution    string    `json:"solution"`
	References  []string  `json:"references"`
	CVE         string    `json:"cve,omitempty"`
	CVSS        *CVSSInfo `json:"cvss,omitempty"`
	Confidence  string    `json:"confidence"`
	Source      string    `json:"source"`
}

// CVSSInfo represents CVSS scoring information
type CVSSInfo struct {
	Version   string  `json:"version"`
	BaseScore float64 `json:"base_score"`
	Vector    string  `json:"vector"`
	Severity  string  `json:"severity"`
}

// SecurityScore represents overall security scoring
type SecurityScore struct {
	Overall     int            `json:"overall"`
	Headers     int            `json:"headers"`
	SSL         int            `json:"ssl"`
	Technology  int            `json:"technology"`
	Breakdown   map[string]int `json:"breakdown"`
	Grade       string         `json:"grade"`
	Explanation string         `json:"explanation"`
}

// ScanStatus represents the current scan status
type ScanStatus struct {
	Phase       string        `json:"phase"`
	Progress    float64       `json:"progress"`
	Message     string        `json:"message"`
	StartTime   time.Time     `json:"start_time"`
	ElapsedTime time.Duration `json:"elapsed_time"`
	Error       string        `json:"error,omitempty"`
}

// ScanPhase constants
const (
	PhaseInitializing    = "Initializing"
	PhaseHeaders         = "Analyzing Headers"
	PhaseSSL             = "Analyzing SSL/TLS"
	PhaseTechnology      = "Detecting Technology"
	PhaseSubdomains      = "Enumerating Subdomains"
	PhaseArchive         = "Checking Archive"
	PhaseVulnerabilities = "Checking Vulnerabilities"
	PhaseAI              = "Generating AI Summary"
	PhaseComplete        = "Complete"
	PhaseError           = "Error"
)

// Severity levels
const (
	SeverityCritical = "Critical"
	SeverityHigh     = "High"
	SeverityMedium   = "Medium"
	SeverityLow      = "Low"
	SeverityInfo     = "Info"
)
