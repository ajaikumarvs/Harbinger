package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// SSLScanner implements SSL/TLS analysis functionality
type SSLScanner struct {
	timeout time.Duration
}

// NewSSLScanner creates a new SSL scanner
func NewSSLScanner() *SSLScanner {
	return &SSLScanner{
		timeout: 10 * time.Second,
	}
}

// Name returns the scanner name
func (ss *SSLScanner) Name() string {
	return "SSL/TLS Scanner"
}

// Scan performs SSL/TLS analysis on the target
func (ss *SSLScanner) Scan(ctx context.Context, target *Target) (*ScanResult, error) {
	result := &ScanResult{
		Scanner:         ss.Name(),
		Technologies:    []models.Technology{},
		Vulnerabilities: []models.Vulnerability{},
		Metadata:        make(map[string]interface{}),
		Errors:          []error{},
	}

	// Only scan if target uses HTTPS
	if target.Scheme != "https" {
		result.Metadata["skip_reason"] = "Target does not use HTTPS"
		return result, nil
	}

	// Get SSL certificate and connection info
	cert, connState, err := ss.getSSLInfo(target.Host)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("failed to get SSL info: %w", err))
		return result, nil
	}

	// Analyze certificate
	ss.analyzeCertificate(cert, result)

	// Analyze TLS configuration
	ss.analyzeTLSConfig(connState, result)

	// Add SSL/TLS as detected technology
	tlsVersion := ss.getTLSVersionString(connState.Version)
	result.Technologies = append(result.Technologies, models.Technology{
		Name:       "TLS",
		Version:    tlsVersion,
		Category:   "Security",
		Confidence: 1.0,
		Metadata: map[string]string{
			"cipher_suite": tls.CipherSuiteName(connState.CipherSuite),
			"server_name":  connState.ServerName,
		},
	})

	return result, nil
}

// getSSLInfo retrieves SSL certificate and connection information
func (ss *SSLScanner) getSSLInfo(host string) (*x509.Certificate, *tls.ConnectionState, error) {
	dialer := &net.Dialer{
		Timeout: ss.timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
		InsecureSkipVerify: true, // We want to analyze even invalid certificates
	})
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, nil, fmt.Errorf("no peer certificates found")
	}

	return state.PeerCertificates[0], &state, nil
}

// analyzeCertificate analyzes the SSL certificate for vulnerabilities
func (ss *SSLScanner) analyzeCertificate(cert *x509.Certificate, result *ScanResult) {
	// Check certificate expiration
	now := time.Now()
	daysToExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	result.Metadata["certificate_expiry"] = cert.NotAfter
	result.Metadata["days_to_expiry"] = daysToExpiry
	result.Metadata["certificate_subject"] = cert.Subject.String()
	result.Metadata["certificate_issuer"] = cert.Issuer.String()

	// Certificate expiration warnings
	if cert.NotAfter.Before(now) {
		result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
			CVE:         "SSL-CERT-EXPIRED",
			Severity:    "Critical",
			Score:       9.0,
			Description: "SSL certificate has expired",
			Remediation: "Renew the SSL certificate immediately",
			RootCause:   "Expired SSL certificate",
			AttackVectors: []string{
				"Man-in-the-middle attacks",
				"Trust issues with users",
				"Browser warnings",
			},
			BusinessImpact:  "Website inaccessible, loss of customer trust",
			EducationalNote: "Expired certificates break HTTPS encryption and cause browser warnings",
			AffectedTech:    []string{"SSL/TLS"},
		})
	} else if daysToExpiry <= 30 {
		severity := "Medium"
		score := 5.0
		if daysToExpiry <= 7 {
			severity = "High"
			score = 7.0
		}

		result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
			CVE:         "SSL-CERT-EXPIRING",
			Severity:    severity,
			Score:       score,
			Description: fmt.Sprintf("SSL certificate expires in %d days", daysToExpiry),
			Remediation: "Renew the SSL certificate before it expires",
			RootCause:   "SSL certificate approaching expiration",
			AttackVectors: []string{
				"Service interruption",
				"User trust issues",
			},
			BusinessImpact:  "Potential service disruption",
			EducationalNote: "SSL certificates should be renewed well before expiration",
			AffectedTech:    []string{"SSL/TLS"},
		})
	}

	// Check for self-signed certificate
	if cert.Issuer.String() == cert.Subject.String() {
		result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
			CVE:         "SSL-SELF-SIGNED",
			Severity:    "Medium",
			Score:       6.0,
			Description: "Self-signed SSL certificate detected",
			Remediation: "Use a certificate from a trusted Certificate Authority",
			RootCause:   "Self-signed certificate not trusted by browsers",
			AttackVectors: []string{
				"Man-in-the-middle attacks",
				"Trust issues with users",
			},
			BusinessImpact:  "Reduced user trust, browser warnings",
			EducationalNote: "Self-signed certificates trigger browser warnings and reduce user trust",
			AffectedTech:    []string{"SSL/TLS"},
		})
	}

	// Check signature algorithm
	if strings.Contains(cert.SignatureAlgorithm.String(), "SHA1") {
		result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
			CVE:         "SSL-WEAK-SIGNATURE",
			Severity:    "Medium",
			Score:       5.0,
			Description: "Certificate uses weak SHA-1 signature algorithm",
			Remediation: "Replace with a certificate using SHA-256 or stronger",
			RootCause:   "Weak cryptographic signature algorithm",
			AttackVectors: []string{
				"Collision attacks",
				"Certificate forgery",
			},
			BusinessImpact:  "Cryptographic weakness",
			EducationalNote: "SHA-1 is considered cryptographically weak and should not be used",
			AffectedTech:    []string{"SSL/TLS"},
		})
	}

	// Check key size
	if cert.PublicKey != nil {
		switch key := cert.PublicKey.(type) {
		case interface{ Size() int }:
			keySize := key.Size() * 8 // Convert to bits
			if keySize < 2048 {
				result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
					CVE:         "SSL-WEAK-KEY",
					Severity:    "High",
					Score:       7.0,
					Description: fmt.Sprintf("Certificate uses weak key size: %d bits", keySize),
					Remediation: "Use a certificate with at least 2048-bit key size",
					RootCause:   "Insufficient key size for cryptographic security",
					AttackVectors: []string{
						"Brute force attacks",
						"Factorization attacks",
					},
					BusinessImpact:  "Cryptographic vulnerability",
					EducationalNote: "RSA keys smaller than 2048 bits are considered weak",
					AffectedTech:    []string{"SSL/TLS"},
				})
			}
		}
	}

	// Check Subject Alternative Names (SAN)
	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
			CVE:         "SSL-NO-SAN",
			Severity:    "Low",
			Score:       3.0,
			Description: "Certificate has no Subject Alternative Names",
			Remediation: "Use a certificate with proper Subject Alternative Names",
			RootCause:   "Missing Subject Alternative Names in certificate",
			AttackVectors: []string{
				"Hostname verification issues",
			},
			BusinessImpact:  "Potential connection issues",
			EducationalNote: "Modern certificates should include Subject Alternative Names",
			AffectedTech:    []string{"SSL/TLS"},
		})
	}
}

// analyzeTLSConfig analyzes the TLS configuration for vulnerabilities
func (ss *SSLScanner) analyzeTLSConfig(connState *tls.ConnectionState, result *ScanResult) {
	// Check TLS version
	if connState.Version < tls.VersionTLS12 {
		severity := "High"
		score := 8.0
		if connState.Version < tls.VersionTLS11 {
			severity = "Critical"
			score = 9.0
		}

		result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
			CVE:         "TLS-WEAK-VERSION",
			Severity:    severity,
			Score:       score,
			Description: fmt.Sprintf("Weak TLS version in use: %s", ss.getTLSVersionString(connState.Version)),
			Remediation: "Configure server to use TLS 1.2 or higher",
			RootCause:   "Outdated TLS protocol version",
			AttackVectors: []string{
				"Protocol downgrade attacks",
				"Known TLS vulnerabilities",
				"Weak encryption",
			},
			BusinessImpact:  "Data transmission vulnerabilities",
			EducationalNote: "TLS versions below 1.2 have known security vulnerabilities",
			AffectedTech:    []string{"TLS"},
		})
	}

	// Check cipher suite
	cipherName := tls.CipherSuiteName(connState.CipherSuite)
	result.Metadata["cipher_suite"] = cipherName

	// Check for weak cipher suites
	if strings.Contains(strings.ToLower(cipherName), "rc4") {
		result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
			CVE:         "TLS-WEAK-CIPHER-RC4",
			Severity:    "High",
			Score:       7.5,
			Description: "Weak RC4 cipher suite detected",
			Remediation: "Disable RC4 cipher suites on the server",
			RootCause:   "RC4 cipher is cryptographically broken",
			AttackVectors: []string{
				"RC4 bias attacks",
				"Statistical attacks",
			},
			BusinessImpact:  "Encrypted data can be decrypted",
			EducationalNote: "RC4 is a broken cipher and should never be used",
			AffectedTech:    []string{"TLS"},
		})
	}

	if strings.Contains(strings.ToLower(cipherName), "des") {
		result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
			CVE:         "TLS-WEAK-CIPHER-DES",
			Severity:    "High",
			Score:       7.0,
			Description: "Weak DES cipher suite detected",
			Remediation: "Disable DES cipher suites on the server",
			RootCause:   "DES cipher has insufficient key length",
			AttackVectors: []string{
				"Brute force attacks",
				"Known plaintext attacks",
			},
			BusinessImpact:  "Encrypted data can be decrypted",
			EducationalNote: "DES is obsolete and should not be used",
			AffectedTech:    []string{"TLS"},
		})
	}
}

// getTLSVersionString converts TLS version number to string
func (ss *SSLScanner) getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%d)", version)
	}
}
