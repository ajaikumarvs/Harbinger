package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ajaikumarvs/harbinger/internal/models"
)

// analyzeSSL performs SSL/TLS certificate and configuration analysis
func (s *Scanner) analyzeSSL(ctx context.Context, targetURL *url.URL) (*models.SSLAnalysis, error) {
	// Only analyze if HTTPS
	if targetURL.Scheme != "https" {
		return &models.SSLAnalysis{
			Enabled: false,
			Grade:   "F",
		}, nil
	}

	host := targetURL.Hostname()
	port := targetURL.Port()
	if port == "" {
		port = "443"
	}

	// Create TLS connection
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{
		ServerName: host,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Get certificate info
	if len(state.PeerCertificates) == 0 {
		return &models.SSLAnalysis{
			Enabled: true,
			Grade:   "F",
		}, nil
	}

	cert := state.PeerCertificates[0]

	// Analyze certificate
	certInfo := &models.CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SerialNumber:       cert.SerialNumber.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		DNSNames:           cert.DNSNames,
		IsExpired:          time.Now().After(cert.NotAfter),
		IsWildcard:         strings.HasPrefix(cert.Subject.CommonName, "*."),
	}

	// Get key algorithm and size
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		certInfo.KeyAlgorithm = "RSA"
		certInfo.KeySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		certInfo.KeyAlgorithm = "ECDSA"
		certInfo.KeySize = pub.Curve.Params().BitSize
	default:
		certInfo.KeyAlgorithm = "Unknown"
		certInfo.KeySize = 0
	}

	// Get protocol version
	var version string
	switch state.Version {
	case tls.VersionTLS10:
		version = "TLS 1.0"
	case tls.VersionTLS11:
		version = "TLS 1.1"
	case tls.VersionTLS12:
		version = "TLS 1.2"
	case tls.VersionTLS13:
		version = "TLS 1.3"
	default:
		version = "Unknown"
	}

	// Get cipher suite
	cipher := tls.CipherSuiteName(state.CipherSuite)

	// Check for vulnerabilities
	vulnerabilities := checkSSLVulnerabilities(state, cert)

	// Calculate grade
	grade := calculateSSLGrade(state, cert, vulnerabilities)

	return &models.SSLAnalysis{
		Enabled:         true,
		Version:         version,
		Cipher:          cipher,
		Certificate:     certInfo,
		Grade:           grade,
		Vulnerabilities: vulnerabilities,
	}, nil
}

// checkSSLVulnerabilities identifies common SSL/TLS vulnerabilities
func checkSSLVulnerabilities(state tls.ConnectionState, cert *x509.Certificate) []string {
	var vulns []string

	// Check for expired certificate
	if time.Now().After(cert.NotAfter) {
		vulns = append(vulns, "Certificate is expired")
	}

	// Check for certificate expiring soon (within 30 days)
	if time.Until(cert.NotAfter) < 30*24*time.Hour {
		vulns = append(vulns, "Certificate expires within 30 days")
	}

	// Check for weak protocol versions
	switch state.Version {
	case tls.VersionTLS10:
		vulns = append(vulns, "Using deprecated TLS 1.0")
	case tls.VersionTLS11:
		vulns = append(vulns, "Using deprecated TLS 1.1")
	}

	// Check for weak signature algorithms
	switch cert.SignatureAlgorithm.String() {
	case "MD5WithRSA", "SHA1WithRSA":
		vulns = append(vulns, "Weak signature algorithm: "+cert.SignatureAlgorithm.String())
	}

	// Check for weak key sizes
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			vulns = append(vulns, fmt.Sprintf("Weak RSA key size: %d bits", pub.N.BitLen()))
		}
	}

	// Check cipher suite
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	if strings.Contains(cipherName, "RC4") || strings.Contains(cipherName, "DES") {
		vulns = append(vulns, "Weak cipher suite: "+cipherName)
	}

	return vulns
}

// calculateSSLGrade calculates an overall SSL/TLS grade
func calculateSSLGrade(state tls.ConnectionState, cert *x509.Certificate, vulnerabilities []string) string {
	score := 100

	// Deduct points for protocol version
	switch state.Version {
	case tls.VersionTLS10:
		score -= 30
	case tls.VersionTLS11:
		score -= 20
	case tls.VersionTLS12:
		score -= 5
	case tls.VersionTLS13:
		// No deduction for TLS 1.3
	}

	// Deduct points for certificate issues
	if time.Now().After(cert.NotAfter) {
		score -= 50 // Expired certificate is critical
	} else if time.Until(cert.NotAfter) < 30*24*time.Hour {
		score -= 10 // Expiring soon
	}

	// Deduct points for weak algorithms
	switch cert.SignatureAlgorithm.String() {
	case "MD5WithRSA":
		score -= 30
	case "SHA1WithRSA":
		score -= 20
	}

	// Deduct points for weak key sizes
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 1024 {
			score -= 40
		} else if pub.N.BitLen() < 2048 {
			score -= 20
		}
	}

	// Deduct points for weak ciphers
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	if strings.Contains(cipherName, "RC4") || strings.Contains(cipherName, "DES") {
		score -= 30
	}

	// Additional deductions for other vulnerabilities
	score -= len(vulnerabilities) * 5

	// Ensure score doesn't go below 0
	if score < 0 {
		score = 0
	}

	// Assign letter grades
	switch {
	case score >= 95:
		return "A+"
	case score >= 90:
		return "A"
	case score >= 85:
		return "A-"
	case score >= 80:
		return "B+"
	case score >= 75:
		return "B"
	case score >= 70:
		return "B-"
	case score >= 65:
		return "C+"
	case score >= 60:
		return "C"
	case score >= 55:
		return "C-"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}
