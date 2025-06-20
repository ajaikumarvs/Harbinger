package scanner

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// PortScanner implements port scanning functionality
type PortScanner struct {
	timeout     time.Duration
	commonPorts []int
}

// NewPortScanner creates a new port scanner
func NewPortScanner() *PortScanner {
	return &PortScanner{
		timeout: 3 * time.Second,
		commonPorts: []int{
			21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
			1723, 3306, 3389, 5432, 5900, 6000, 6001, 6002, 6003, 6004, 6005, 6006,
			8000, 8001, 8008, 8080, 8443, 8888, 9000, 9001, 9002, 9003, 9004, 9005,
		},
	}
}

// Name returns the scanner name
func (ps *PortScanner) Name() string {
	return "Port Scanner"
}

// Scan performs port scanning on the target
func (ps *PortScanner) Scan(ctx context.Context, target *Target) (*ScanResult, error) {
	result := &ScanResult{
		Scanner:         ps.Name(),
		Technologies:    []models.Technology{},
		Vulnerabilities: []models.Vulnerability{},
		Metadata:        make(map[string]interface{}),
		Errors:          []error{},
	}

	// Scan common ports
	openPorts := ps.scanPorts(ctx, target.Host, ps.commonPorts)
	result.Metadata["open_ports"] = openPorts

	// Detect services and create vulnerabilities/technologies based on findings
	for _, port := range openPorts {
		service := ps.detectService(port)

		// Create technology entry
		if service != "" {
			tech := models.Technology{
				Name:       service,
				Version:    "unknown",
				Category:   "Service",
				Confidence: 0.8,
				Metadata: map[string]string{
					"port":     strconv.Itoa(port),
					"detected": "port_scan",
				},
			}
			result.Technologies = append(result.Technologies, tech)
		}

		// Check for common vulnerabilities
		vuln := ps.checkPortVulnerabilities(port, service)
		if vuln != nil {
			result.Vulnerabilities = append(result.Vulnerabilities, *vuln)
		}
	}

	return result, nil
}

// scanPorts scans the specified ports concurrently
func (ps *PortScanner) scanPorts(ctx context.Context, host string, ports []int) []int {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrency
	semaphore := make(chan struct{}, 50)

	for _, port := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if ps.isPortOpen(ctx, host, port) {
				mu.Lock()
				openPorts = append(openPorts, port)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}

// isPortOpen checks if a specific port is open
func (ps *PortScanner) isPortOpen(ctx context.Context, host string, port int) bool {
	target := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", target, ps.timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

// detectService attempts to identify the service running on a port
func (ps *PortScanner) detectService(port int) string {
	serviceMap := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		111:  "RPC",
		135:  "RPC",
		139:  "NetBIOS",
		143:  "IMAP",
		443:  "HTTPS",
		993:  "IMAPS",
		995:  "POP3S",
		1723: "PPTP",
		3306: "MySQL",
		3389: "RDP",
		5432: "PostgreSQL",
		5900: "VNC",
		8000: "HTTP-Alt",
		8080: "HTTP-Proxy",
		8443: "HTTPS-Alt",
		8888: "HTTP-Alt",
	}

	if service, exists := serviceMap[port]; exists {
		return service
	}
	return "Unknown"
}

// checkPortVulnerabilities checks for common vulnerabilities based on open ports
func (ps *PortScanner) checkPortVulnerabilities(port int, service string) *models.Vulnerability {
	switch port {
	case 21:
		return &models.Vulnerability{
			CVE:         "PORT-21-FTP",
			Severity:    "Medium",
			Score:       5.0,
			Description: "FTP service detected. FTP transmits data in plaintext.",
			Remediation: "Consider using SFTP or FTPS instead of plain FTP",
			RootCause:   "Unencrypted file transfer protocol",
			AttackVectors: []string{
				"Man-in-the-middle attacks",
				"Credential interception",
				"Data interception",
			},
			BusinessImpact:  "Data confidentiality risk",
			EducationalNote: "FTP is an old protocol that doesn't encrypt data during transmission",
			AffectedTech:    []string{"FTP"},
		}
	case 23:
		return &models.Vulnerability{
			CVE:         "PORT-23-TELNET",
			Severity:    "High",
			Score:       7.5,
			Description: "Telnet service detected. Telnet transmits credentials in plaintext.",
			Remediation: "Replace Telnet with SSH for secure remote access",
			RootCause:   "Unencrypted remote access protocol",
			AttackVectors: []string{
				"Credential theft",
				"Session hijacking",
				"Man-in-the-middle attacks",
			},
			BusinessImpact:  "Complete system compromise risk",
			EducationalNote: "Telnet is considered obsolete and should never be used in production",
			AffectedTech:    []string{"Telnet"},
		}
	case 3389:
		return &models.Vulnerability{
			CVE:         "PORT-3389-RDP",
			Severity:    "Medium",
			Score:       6.0,
			Description: "RDP service exposed to the internet. This is a common attack vector.",
			Remediation: "Restrict RDP access to VPN or specific IP ranges, enable NLA",
			RootCause:   "Remote desktop service exposed to public internet",
			AttackVectors: []string{
				"Brute force attacks",
				"RDP exploits",
				"BlueKeep-style vulnerabilities",
			},
			BusinessImpact:  "Unauthorized system access",
			EducationalNote: "RDP should never be exposed directly to the internet",
			AffectedTech:    []string{"RDP", "Windows"},
		}
	}
	return nil
}
