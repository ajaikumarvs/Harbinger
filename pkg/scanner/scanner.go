package scanner

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// Scanner represents the main scanning interface
type Scanner interface {
	Name() string
	Scan(ctx context.Context, target *Target) (*ScanResult, error)
}

// Target represents the scan target
type Target struct {
	URL        *url.URL
	Host       string
	Port       int
	Scheme     string
	PathPrefix string
}

// ScanResult represents the result from a specific scanner
type ScanResult struct {
	Scanner         string
	Technologies    []models.Technology
	Vulnerabilities []models.Vulnerability
	Metadata        map[string]interface{}
	Errors          []error
}

// Engine represents the main scanning engine
type Engine struct {
	scanners         []Scanner
	maxConcurrency   int
	progressCallback func(models.ScanProgress)
	logger           func(string)
}

// NewEngine creates a new scanning engine
func NewEngine() *Engine {
	return &Engine{
		scanners:         []Scanner{},
		maxConcurrency:   5,
		progressCallback: func(models.ScanProgress) {}, // no-op default
		logger:           func(string) {},              // no-op default
	}
}

// RegisterScanner adds a scanner to the engine
func (e *Engine) RegisterScanner(scanner Scanner) {
	e.scanners = append(e.scanners, scanner)
}

// SetProgressCallback sets the progress callback function
func (e *Engine) SetProgressCallback(callback func(models.ScanProgress)) {
	e.progressCallback = callback
}

// SetLogger sets the logging function
func (e *Engine) SetLogger(logger func(string)) {
	e.logger = logger
}

// Scan performs a comprehensive scan of the target
func (e *Engine) Scan(ctx context.Context, targetURL string) (*models.ScanResult, error) {
	// Parse target URL
	target, err := e.parseTarget(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %w", err)
	}

	// Initialize scan result
	result := &models.ScanResult{
		ID:              fmt.Sprintf("scan_%d", time.Now().Unix()),
		URL:             targetURL,
		Timestamp:       time.Now(),
		Status:          models.ScanStatusRunning,
		TechStack:       []models.Technology{},
		Vulnerabilities: []models.Vulnerability{},
		ScannersUsed:    []string{},
		APICallsUsed:    make(map[string]int),
	}

	startTime := time.Now()
	totalSteps := len(e.scanners)

	// Initialize progress
	progress := models.ScanProgress{
		ScanID:           result.ID,
		TotalSteps:       totalSteps,
		CompletedSteps:   0,
		Progress:         0.0,
		ActiveScanners:   []string{},
		CurrentOperation: "Starting scan...",
		Logs:             []string{fmt.Sprintf("Starting scan of %s", targetURL)},
	}

	e.progressCallback(progress)
	e.logger(fmt.Sprintf("Starting scan of %s with %d scanners", targetURL, len(e.scanners)))

	// Run scanners concurrently
	var wg sync.WaitGroup
	resultsChan := make(chan *ScanResult, len(e.scanners))
	errorsChan := make(chan error, len(e.scanners))

	// Control concurrency
	semaphore := make(chan struct{}, e.maxConcurrency)

	for i, scanner := range e.scanners {
		wg.Add(1)
		go func(i int, scanner Scanner) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Update progress
			progress.CurrentScanner = scanner.Name()
			progress.CurrentOperation = fmt.Sprintf("Running %s...", scanner.Name())
			e.progressCallback(progress)
			e.logger(fmt.Sprintf("Starting %s", scanner.Name()))

			// Run scanner
			scanResult, err := scanner.Scan(ctx, target)
			if err != nil {
				errorsChan <- fmt.Errorf("%s: %w", scanner.Name(), err)
				e.logger(fmt.Sprintf("Error in %s: %v", scanner.Name(), err))
			} else {
				resultsChan <- scanResult
				e.logger(fmt.Sprintf("Completed %s", scanner.Name()))
			}

			// Update progress
			progress.CompletedSteps = i + 1
			progress.Progress = float64(progress.CompletedSteps) / float64(totalSteps)
			e.progressCallback(progress)
		}(i, scanner)
	}

	// Wait for all scanners to complete
	wg.Wait()
	close(resultsChan)
	close(errorsChan)

	// Collect results
	var allErrors []error
	for err := range errorsChan {
		allErrors = append(allErrors, err)
	}

	for scanResult := range resultsChan {
		result.TechStack = append(result.TechStack, scanResult.Technologies...)
		result.Vulnerabilities = append(result.Vulnerabilities, scanResult.Vulnerabilities...)
		result.ScannersUsed = append(result.ScannersUsed, scanResult.Scanner)
	}

	// Calculate security score
	result.SecurityScore = e.calculateSecurityScore(result)
	result.ScanDuration = time.Since(startTime)
	result.Status = models.ScanStatusCompleted

	// Final progress update
	progress.CurrentOperation = "Scan completed!"
	progress.Progress = 1.0
	progress.Logs = append(progress.Logs, fmt.Sprintf("Scan completed in %v", result.ScanDuration))
	e.progressCallback(progress)

	if len(allErrors) > 0 {
		e.logger(fmt.Sprintf("Scan completed with %d errors", len(allErrors)))
	} else {
		e.logger("Scan completed successfully")
	}

	return result, nil
}

// parseTarget parses the target URL into a Target struct
func (e *Engine) parseTarget(targetURL string) (*Target, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if u.Port() != "" {
		port = 0 // Will be handled by net.Dial
	}

	return &Target{
		URL:        u,
		Host:       u.Hostname(),
		Port:       port,
		Scheme:     u.Scheme,
		PathPrefix: u.Path,
	}, nil
}

// calculateSecurityScore calculates the overall security score
func (e *Engine) calculateSecurityScore(result *models.ScanResult) int {
	baseScore := 100

	// Deduct points for vulnerabilities
	for _, vuln := range result.Vulnerabilities {
		switch vuln.Severity {
		case "Critical":
			baseScore -= 25
		case "High":
			baseScore -= 15
		case "Medium":
			baseScore -= 10
		case "Low":
			baseScore -= 5
		}
	}

	// Bonus points for good technologies
	for _, tech := range result.TechStack {
		if tech.Category == "Security" {
			baseScore += 5
		}
	}

	// Ensure score is between 0 and 100
	if baseScore < 0 {
		baseScore = 0
	}
	if baseScore > 100 {
		baseScore = 100
	}

	return baseScore
}

// GetDefaultEngine creates an engine with all default scanners
func GetDefaultEngine() *Engine {
	engine := NewEngine()

	// Register all scanners
	engine.RegisterScanner(NewPortScanner())
	engine.RegisterScanner(NewTechnologyScanner())
	engine.RegisterScanner(NewSSLScanner())
	engine.RegisterScanner(NewHeaderScanner())
	engine.RegisterScanner(NewDNSScanner())
	engine.RegisterScanner(NewDirectoryScanner())

	return engine
}
