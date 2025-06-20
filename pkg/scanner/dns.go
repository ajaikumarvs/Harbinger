package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// DNSScanner implements DNS analysis functionality
type DNSScanner struct {
	resolver *net.Resolver
	timeout  time.Duration
}

// NewDNSScanner creates a new DNS scanner
func NewDNSScanner() *DNSScanner {
	return &DNSScanner{
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 3 * time.Second,
				}
				return d.DialContext(ctx, network, address)
			},
		},
		timeout: 10 * time.Second,
	}
}

// Name returns the scanner name
func (ds *DNSScanner) Name() string {
	return "DNS Scanner"
}

// Scan performs DNS analysis on the target
func (ds *DNSScanner) Scan(ctx context.Context, target *Target) (*ScanResult, error) {
	result := &ScanResult{
		Scanner:         ds.Name(),
		Technologies:    []models.Technology{},
		Vulnerabilities: []models.Vulnerability{},
		Metadata:        make(map[string]interface{}),
		Errors:          []error{},
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, ds.timeout)
	defer cancel()

	// Perform DNS lookups
	ds.performDNSLookups(ctx, target.Host, result)

	// Check for common subdomains
	ds.checkCommonSubdomains(ctx, target.Host, result)

	// Analyze DNS configuration for security issues
	ds.analyzeDNSConfiguration(result)

	return result, nil
}

// performDNSLookups performs various DNS record lookups
func (ds *DNSScanner) performDNSLookups(ctx context.Context, host string, result *ScanResult) {
	// A records
	aRecords, err := ds.resolver.LookupIPAddr(ctx, host)
	if err == nil && len(aRecords) > 0 {
		var ips []string
		for _, addr := range aRecords {
			ips = append(ips, addr.IP.String())
		}
		result.Metadata["a_records"] = ips
	}

	// CNAME records
	cname, err := ds.resolver.LookupCNAME(ctx, host)
	if err == nil && cname != host+"." {
		result.Metadata["cname"] = cname
	}

	// MX records
	mxRecords, err := ds.resolver.LookupMX(ctx, host)
	if err == nil && len(mxRecords) > 0 {
		var mxStrings []string
		for _, mx := range mxRecords {
			mxStrings = append(mxStrings, fmt.Sprintf("%s (priority: %d)", mx.Host, mx.Pref))
		}
		result.Metadata["mx_records"] = mxStrings
	}

	// TXT records
	txtRecords, err := ds.resolver.LookupTXT(ctx, host)
	if err == nil && len(txtRecords) > 0 {
		result.Metadata["txt_records"] = txtRecords

		// Analyze TXT records for security configurations
		ds.analyzeTXTRecords(txtRecords, result)
	}

	// NS records
	nsRecords, err := ds.resolver.LookupNS(ctx, host)
	if err == nil && len(nsRecords) > 0 {
		var nsStrings []string
		for _, ns := range nsRecords {
			nsStrings = append(nsStrings, ns.Host)
		}
		result.Metadata["ns_records"] = nsStrings
	}
}

// checkCommonSubdomains checks for common subdomains
func (ds *DNSScanner) checkCommonSubdomains(ctx context.Context, host string, result *ScanResult) {
	commonSubdomains := []string{
		"www", "mail", "ftp", "admin", "test", "dev", "staging", "api", "blog",
		"shop", "store", "app", "mobile", "m", "support", "help", "docs",
		"cdn", "static", "media", "assets", "images", "img", "js", "css",
		"secure", "ssl", "vpn", "remote", "intranet", "internal",
	}

	var foundSubdomains []string
	for _, subdomain := range commonSubdomains {
		fullDomain := subdomain + "." + host

		// Try to resolve the subdomain
		_, err := ds.resolver.LookupIPAddr(ctx, fullDomain)
		if err == nil {
			foundSubdomains = append(foundSubdomains, fullDomain)
		}
	}

	if len(foundSubdomains) > 0 {
		result.Metadata["discovered_subdomains"] = foundSubdomains

		// Create informational finding about subdomains
		result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
			CVE:         "DNS-SUBDOMAIN-ENUMERATION",
			Severity:    "Low",
			Score:       2.0,
			Description: fmt.Sprintf("Discovered %d subdomains through DNS enumeration", len(foundSubdomains)),
			Remediation: "Review subdomain exposure and ensure proper access controls",
			RootCause:   "Discoverable subdomains",
			AttackVectors: []string{
				"Subdomain enumeration",
				"Attack surface expansion",
				"Information gathering",
			},
			BusinessImpact:  "Increased attack surface",
			EducationalNote: "Subdomains can reveal additional services and attack vectors",
			AffectedTech:    []string{"DNS"},
		})
	}
}

// analyzeTXTRecords analyzes TXT records for security configurations
func (ds *DNSScanner) analyzeTXTRecords(txtRecords []string, result *ScanResult) {
	var hasSPF, hasDMARC bool

	for _, record := range txtRecords {
		record = strings.ToLower(record)

		// Check for SPF
		if strings.HasPrefix(record, "v=spf1") {
			hasSPF = true

			// Check for weak SPF configuration
			if strings.Contains(record, "?all") || strings.Contains(record, "+all") {
				result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
					CVE:         "DNS-SPF-WEAK",
					Severity:    "Medium",
					Score:       5.0,
					Description: "Weak SPF configuration detected",
					Remediation: "Use ~all or -all in SPF record instead of +all or ?all",
					RootCause:   "Permissive SPF policy",
					AttackVectors: []string{
						"Email spoofing",
						"Phishing attacks",
					},
					BusinessImpact:  "Increased risk of email-based attacks",
					EducationalNote: "SPF records should use restrictive policies to prevent email spoofing",
					AffectedTech:    []string{"DNS", "Email"},
				})
			}
		}

		// Check for DMARC
		if strings.HasPrefix(record, "v=dmarc1") {
			hasDMARC = true

			// Check for weak DMARC policy
			if strings.Contains(record, "p=none") {
				result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
					CVE:         "DNS-DMARC-WEAK",
					Severity:    "Low",
					Score:       3.0,
					Description: "DMARC policy set to 'none' - emails are not protected",
					Remediation: "Set DMARC policy to 'quarantine' or 'reject'",
					RootCause:   "Weak DMARC policy",
					AttackVectors: []string{
						"Email spoofing",
						"Phishing attacks",
					},
					BusinessImpact:  "Reduced email security",
					EducationalNote: "DMARC policy 'none' only monitors but doesn't protect against spoofing",
					AffectedTech:    []string{"DNS", "Email"},
				})
			}
		}
	}

	// Check for missing email security records
	if !hasSPF {
		result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
			CVE:         "DNS-SPF-MISSING",
			Severity:    "Medium",
			Score:       5.0,
			Description: "Missing SPF record - domain is vulnerable to email spoofing",
			Remediation: "Add an SPF record to prevent email spoofing",
			RootCause:   "Missing SPF DNS record",
			AttackVectors: []string{
				"Email spoofing",
				"Phishing attacks",
				"Domain reputation abuse",
			},
			BusinessImpact:  "Domain can be used for phishing attacks",
			EducationalNote: "SPF records specify which servers are authorized to send email for your domain",
			AffectedTech:    []string{"DNS", "Email"},
		})
	}

	if !hasDMARC {
		result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
			CVE:         "DNS-DMARC-MISSING",
			Severity:    "Medium",
			Score:       4.0,
			Description: "Missing DMARC record - domain lacks email authentication policy",
			Remediation: "Add a DMARC record to establish email authentication policy",
			RootCause:   "Missing DMARC DNS record",
			AttackVectors: []string{
				"Email spoofing",
				"Phishing attacks",
				"Business email compromise",
			},
			BusinessImpact:  "Reduced email security and trust",
			EducationalNote: "DMARC provides policy for handling emails that fail SPF or DKIM checks",
			AffectedTech:    []string{"DNS", "Email"},
		})
	}
}

// analyzeDNSConfiguration analyzes DNS configuration for security issues
func (ds *DNSScanner) analyzeDNSConfiguration(result *ScanResult) {
	// Check if DNS over HTTPS or DNS over TLS is being used
	// This is more of an informational check since we can't easily detect this

	// Add DNS security technology detection
	if nsRecords, exists := result.Metadata["ns_records"]; exists {
		if nsSlice, ok := nsRecords.([]string); ok {
			for _, ns := range nsSlice {
				// Check for well-known secure DNS providers
				if strings.Contains(strings.ToLower(ns), "cloudflare") ||
					strings.Contains(strings.ToLower(ns), "quad9") ||
					strings.Contains(strings.ToLower(ns), "cleanbrowsing") {

					result.Technologies = append(result.Technologies, models.Technology{
						Name:       "Secure DNS Provider",
						Version:    "unknown",
						Category:   "Security",
						Confidence: 0.7,
						Metadata: map[string]string{
							"provider":    ns,
							"detected_by": "dns_scanner",
						},
					})
					break
				}
			}
		}
	}
}
