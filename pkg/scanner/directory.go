package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// DirectoryScanner implements directory and file discovery functionality
type DirectoryScanner struct {
	client    *http.Client
	wordlist  []string
	maxChecks int
}

// NewDirectoryScanner creates a new directory scanner
func NewDirectoryScanner() *DirectoryScanner {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	return &DirectoryScanner{
		client:    client,
		wordlist:  getCommonPaths(),
		maxChecks: 50, // Limit to prevent excessive requests
	}
}

// Name returns the scanner name
func (ds *DirectoryScanner) Name() string {
	return "Directory Scanner"
}

// Scan performs directory and file discovery on the target
func (ds *DirectoryScanner) Scan(ctx context.Context, target *Target) (*ScanResult, error) {
	result := &ScanResult{
		Scanner:         ds.Name(),
		Technologies:    []models.Technology{},
		Vulnerabilities: []models.Vulnerability{},
		Metadata:        make(map[string]interface{}),
		Errors:          []error{},
	}

	// Only scan HTTP/HTTPS targets
	if target.Scheme != "http" && target.Scheme != "https" {
		result.Metadata["skip_reason"] = "Target is not HTTP/HTTPS"
		return result, nil
	}

	// Discover interesting files and directories
	discoveredPaths := ds.discoverPaths(ctx, target, result)
	result.Metadata["discovered_paths"] = discoveredPaths

	// Analyze discovered paths for security issues
	ds.analyzeDiscoveredPaths(discoveredPaths, result)

	return result, nil
}

// discoverPaths discovers interesting files and directories
func (ds *DirectoryScanner) discoverPaths(ctx context.Context, target *Target, result *ScanResult) []string {
	var discoveredPaths []string
	baseURL := target.URL.String()

	// Ensure base URL ends with /
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	// Limit the number of checks
	checkCount := 0
	maxChecks := ds.maxChecks
	if len(ds.wordlist) < maxChecks {
		maxChecks = len(ds.wordlist)
	}

	for i := 0; i < maxChecks && checkCount < ds.maxChecks; i++ {
		path := ds.wordlist[i]
		fullURL := baseURL + path

		select {
		case <-ctx.Done():
			return discoveredPaths
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := ds.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		checkCount++

		// Consider 200, 403, and 401 as interesting findings
		if resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 401 || resp.StatusCode == 301 || resp.StatusCode == 302 {
			discoveredPaths = append(discoveredPaths, fmt.Sprintf("%s (%d)", path, resp.StatusCode))
		}
	}

	return discoveredPaths
}

// analyzeDiscoveredPaths analyzes discovered paths for security issues
func (ds *DirectoryScanner) analyzeDiscoveredPaths(discoveredPaths []string, result *ScanResult) {
	if len(discoveredPaths) == 0 {
		return
	}

	// Create informational finding about discovered paths
	result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
		CVE:         "DIR-PATHS-DISCOVERED",
		Severity:    "Low",
		Score:       2.0,
		Description: fmt.Sprintf("Discovered %d interesting paths through directory enumeration", len(discoveredPaths)),
		Remediation: "Review exposed paths and restrict access to sensitive directories",
		RootCause:   "Discoverable files and directories",
		AttackVectors: []string{
			"Directory enumeration",
			"Information gathering",
			"Sensitive file exposure",
		},
		BusinessImpact:  "Information disclosure",
		EducationalNote: "Directory enumeration can reveal sensitive files and administrative interfaces",
		AffectedTech:    []string{"Web Server"},
	})

	// Check for specific sensitive files/directories
	for _, pathInfo := range discoveredPaths {
		path := strings.Split(pathInfo, " ")[0] // Remove status code
		ds.checkSensitivePath(path, pathInfo, result)
	}
}

// checkSensitivePath checks if a discovered path is sensitive
func (ds *DirectoryScanner) checkSensitivePath(path, pathInfo string, result *ScanResult) {
	sensitivePatterns := map[string]struct {
		severity    string
		score       float64
		description string
		remediation string
		vectors     []string
	}{
		"admin": {
			"Medium", 6.0,
			"Administrative interface discovered",
			"Restrict access to admin interfaces and use strong authentication",
			[]string{"Unauthorized admin access", "Privilege escalation"},
		},
		"config": {
			"High", 7.0,
			"Configuration files or directory discovered",
			"Remove or restrict access to configuration files",
			[]string{"Configuration disclosure", "Credential theft"},
		},
		"backup": {
			"High", 7.5,
			"Backup files or directory discovered",
			"Remove backup files from web-accessible locations",
			[]string{"Source code disclosure", "Database backup access"},
		},
		".git": {
			"High", 8.0,
			"Git repository discovered",
			"Remove .git directory from web-accessible location",
			[]string{"Source code disclosure", "Credential theft", "History exposure"},
		},
		".svn": {
			"High", 8.0,
			"SVN repository discovered",
			"Remove .svn directory from web-accessible location",
			[]string{"Source code disclosure", "Credential theft"},
		},
		"phpinfo": {
			"Medium", 6.0,
			"PHP info page discovered",
			"Remove phpinfo() files from production",
			[]string{"Information disclosure", "Configuration exposure"},
		},
		"test": {
			"Low", 4.0,
			"Test files or directory discovered",
			"Remove test files from production environment",
			[]string{"Information disclosure", "Debug information exposure"},
		},
		"robots.txt": {
			"Low", 2.0,
			"Robots.txt file discovered",
			"Review robots.txt for sensitive path disclosure",
			[]string{"Information gathering", "Path disclosure"},
		},
		"sitemap": {
			"Low", 2.0,
			"Sitemap file discovered",
			"Review sitemap for sensitive path disclosure",
			[]string{"Information gathering", "Path enumeration"},
		},
		".env": {
			"Critical", 9.0,
			"Environment file discovered",
			"Remove .env files from web-accessible location immediately",
			[]string{"Credential theft", "API key exposure", "Database access"},
		},
		"database": {
			"Critical", 9.0,
			"Database file or directory discovered",
			"Remove database files from web-accessible location",
			[]string{"Data theft", "Database access", "Credential theft"},
		},
		"wp-config": {
			"High", 8.0,
			"WordPress configuration file discovered",
			"Restrict access to wp-config.php file",
			[]string{"Database credential theft", "WordPress compromise"},
		},
	}

	pathLower := strings.ToLower(path)
	for pattern, details := range sensitivePatterns {
		if strings.Contains(pathLower, pattern) {
			result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
				CVE:             fmt.Sprintf("DIR-SENSITIVE-%s", strings.ToUpper(strings.ReplaceAll(pattern, ".", "_"))),
				Severity:        details.severity,
				Score:           details.score,
				Description:     fmt.Sprintf("%s: %s", details.description, pathInfo),
				Remediation:     details.remediation,
				RootCause:       "Sensitive file or directory accessible via web",
				AttackVectors:   details.vectors,
				BusinessImpact:  "Potential data or credential exposure",
				EducationalNote: "Sensitive files should never be accessible via web requests",
				AffectedTech:    []string{"Web Server"},
			})
			break // Only match the first pattern to avoid duplicates
		}
	}
}

// getCommonPaths returns a list of common paths to check
func getCommonPaths() []string {
	return []string{
		// Administrative
		"admin/", "admin.php", "administrator/", "wp-admin/", "phpmyadmin/",
		"adminer.php", "manager/", "control/", "panel/", "cp/",

		// Configuration
		"config/", "config.php", "configuration.php", "settings.php",
		"wp-config.php", ".env", "config.json", "config.xml",

		// Backup files
		"backup/", "backups/", "backup.zip", "backup.tar.gz", "backup.sql",
		"db_backup.sql", "database.sql", "dump.sql", "site_backup.zip",

		// Version control
		".git/", ".svn/", ".hg/", ".bzr/", "CVS/",

		// Common files
		"robots.txt", "sitemap.xml", "favicon.ico", "crossdomain.xml",
		"phpinfo.php", "info.php", "test.php", "index.php~", "index.html~",

		// Directories
		"includes/", "inc/", "lib/", "libraries/", "vendor/", "node_modules/",
		"uploads/", "files/", "assets/", "static/", "public/",

		// Development/Test
		"test/", "tests/", "testing/", "dev/", "development/", "staging/",
		"debug/", "temp/", "tmp/", "cache/",

		// API endpoints
		"api/", "rest/", "graphql/", "soap/", "xmlrpc.php",

		// Documentation
		"docs/", "documentation/", "manual/", "help/", "readme.txt",
		"changelog.txt", "license.txt",

		// Database
		"database/", "db/", "data/", "sql/", "mysql/", "postgres/",
		"database.sqlite", "db.sqlite3", "app.db",

		// Logs
		"logs/", "log/", "access.log", "error.log", "debug.log",
		"app.log", "application.log",
	}
}
