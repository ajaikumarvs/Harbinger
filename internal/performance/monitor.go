package performance

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
)

// PerformanceMonitor tracks application performance metrics
type PerformanceMonitor struct {
	metrics   *Metrics
	mutex     sync.RWMutex
	startTime time.Time
	process   *process.Process
	enabled   bool
}

// Metrics represents performance metrics
type Metrics struct {
	// Scan performance
	TotalScans      int64         `json:"total_scans"`
	AverageScanTime time.Duration `json:"average_scan_time"`
	FastestScanTime time.Duration `json:"fastest_scan_time"`
	SlowestScanTime time.Duration `json:"slowest_scan_time"`
	ConcurrentScans int           `json:"concurrent_scans"`

	// System metrics
	CPUUsage         float64 `json:"cpu_usage"`
	MemoryUsage      uint64  `json:"memory_usage"`
	MemoryUsageHuman string  `json:"memory_usage_human"`
	GoroutineCount   int     `json:"goroutine_count"`

	// Application metrics
	Uptime      time.Duration `json:"uptime"`
	UptimeHuman string        `json:"uptime_human"`

	// Scanner specific metrics
	ScannerMetrics map[string]*ScannerMetrics `json:"scanner_metrics"`

	// AI provider metrics
	AIProviderMetrics map[string]*AIMetrics `json:"ai_provider_metrics"`
}

// ScannerMetrics tracks individual scanner performance
type ScannerMetrics struct {
	Name           string        `json:"name"`
	ExecutionCount int64         `json:"execution_count"`
	TotalTime      time.Duration `json:"total_time"`
	AverageTime    time.Duration `json:"average_time"`
	ErrorCount     int64         `json:"error_count"`
	SuccessRate    float64       `json:"success_rate"`
	LastExecution  time.Time     `json:"last_execution"`
}

// AIMetrics tracks AI provider performance
type AIMetrics struct {
	Provider     string        `json:"provider"`
	RequestCount int64         `json:"request_count"`
	TotalTime    time.Duration `json:"total_time"`
	AverageTime  time.Duration `json:"average_time"`
	ErrorCount   int64         `json:"error_count"`
	TokensUsed   int64         `json:"tokens_used"`
	SuccessRate  float64       `json:"success_rate"`
	LastRequest  time.Time     `json:"last_request"`
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor() (*PerformanceMonitor, error) {
	// Get current process
	proc, err := process.NewProcess(int32(runtime.GOMAXPROCS(0)))
	if err != nil {
		// Fallback to getting by PID
		proc = nil
	}

	return &PerformanceMonitor{
		metrics: &Metrics{
			ScannerMetrics:    make(map[string]*ScannerMetrics),
			AIProviderMetrics: make(map[string]*AIMetrics),
			FastestScanTime:   time.Hour * 24, // Initialize to high value
		},
		startTime: time.Now(),
		process:   proc,
		enabled:   true,
	}, nil
}

// Start begins performance monitoring
func (pm *PerformanceMonitor) Start(ctx context.Context) {
	if !pm.enabled {
		return
	}

	// Update metrics every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pm.updateSystemMetrics()
		}
	}
}

// RecordScanStart records the beginning of a scan
func (pm *PerformanceMonitor) RecordScanStart(scanID string) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.metrics.ConcurrentScans++
}

// RecordScanEnd records the completion of a scan
func (pm *PerformanceMonitor) RecordScanEnd(scanID string, duration time.Duration, success bool) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.metrics.TotalScans++
	pm.metrics.ConcurrentScans--

	// Update scan time statistics
	if pm.metrics.TotalScans == 1 {
		pm.metrics.AverageScanTime = duration
	} else {
		pm.metrics.AverageScanTime = time.Duration(
			(int64(pm.metrics.AverageScanTime)*(pm.metrics.TotalScans-1) + int64(duration)) / pm.metrics.TotalScans,
		)
	}

	if duration < pm.metrics.FastestScanTime {
		pm.metrics.FastestScanTime = duration
	}

	if duration > pm.metrics.SlowestScanTime {
		pm.metrics.SlowestScanTime = duration
	}
}

// RecordScannerExecution records scanner-specific performance
func (pm *PerformanceMonitor) RecordScannerExecution(scannerName string, duration time.Duration, success bool) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	metric, exists := pm.metrics.ScannerMetrics[scannerName]
	if !exists {
		metric = &ScannerMetrics{
			Name: scannerName,
		}
		pm.metrics.ScannerMetrics[scannerName] = metric
	}

	metric.ExecutionCount++
	metric.TotalTime += duration
	metric.AverageTime = time.Duration(int64(metric.TotalTime) / metric.ExecutionCount)
	metric.LastExecution = time.Now()

	if !success {
		metric.ErrorCount++
	}

	metric.SuccessRate = float64(metric.ExecutionCount-metric.ErrorCount) / float64(metric.ExecutionCount) * 100
}

// RecordAIRequest records AI provider performance
func (pm *PerformanceMonitor) RecordAIRequest(provider string, duration time.Duration, tokensUsed int64, success bool) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	metric, exists := pm.metrics.AIProviderMetrics[provider]
	if !exists {
		metric = &AIMetrics{
			Provider: provider,
		}
		pm.metrics.AIProviderMetrics[provider] = metric
	}

	metric.RequestCount++
	metric.TotalTime += duration
	metric.AverageTime = time.Duration(int64(metric.TotalTime) / metric.RequestCount)
	metric.TokensUsed += tokensUsed
	metric.LastRequest = time.Now()

	if !success {
		metric.ErrorCount++
	}

	metric.SuccessRate = float64(metric.RequestCount-metric.ErrorCount) / float64(metric.RequestCount) * 100
}

// updateSystemMetrics updates system-level performance metrics
func (pm *PerformanceMonitor) updateSystemMetrics() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// CPU usage
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err == nil && len(cpuPercent) > 0 {
		pm.metrics.CPUUsage = cpuPercent[0]
	}

	// Memory usage
	memInfo, err := mem.VirtualMemory()
	if err == nil {
		pm.metrics.MemoryUsage = memInfo.Used
		pm.metrics.MemoryUsageHuman = humanize.Bytes(memInfo.Used)
	}

	// Goroutine count
	pm.metrics.GoroutineCount = runtime.NumGoroutine()

	// Uptime
	pm.metrics.Uptime = time.Since(pm.startTime)
	pm.metrics.UptimeHuman = humanize.Time(pm.startTime)
}

// GetMetrics returns current performance metrics
func (pm *PerformanceMonitor) GetMetrics() *Metrics {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	// Update real-time metrics
	pm.updateSystemMetrics()

	// Create a copy to avoid race conditions
	metricsCopy := *pm.metrics

	// Deep copy maps
	metricsCopy.ScannerMetrics = make(map[string]*ScannerMetrics)
	for k, v := range pm.metrics.ScannerMetrics {
		scannerCopy := *v
		metricsCopy.ScannerMetrics[k] = &scannerCopy
	}

	metricsCopy.AIProviderMetrics = make(map[string]*AIMetrics)
	for k, v := range pm.metrics.AIProviderMetrics {
		aiCopy := *v
		metricsCopy.AIProviderMetrics[k] = &aiCopy
	}

	return &metricsCopy
}

// GetSummary returns a human-readable performance summary
func (pm *PerformanceMonitor) GetSummary() string {
	metrics := pm.GetMetrics()

	summary := fmt.Sprintf(`Performance Summary:
Uptime: %s
Total Scans: %d
Average Scan Time: %v
Fastest Scan: %v
Slowest Scan: %v
Concurrent Scans: %d
CPU Usage: %.1f%%
Memory Usage: %s
Goroutines: %d

Scanner Performance:`,
		metrics.UptimeHuman,
		metrics.TotalScans,
		metrics.AverageScanTime.Round(time.Millisecond),
		metrics.FastestScanTime.Round(time.Millisecond),
		metrics.SlowestScanTime.Round(time.Millisecond),
		metrics.ConcurrentScans,
		metrics.CPUUsage,
		metrics.MemoryUsageHuman,
		metrics.GoroutineCount,
	)

	for _, scanner := range metrics.ScannerMetrics {
		summary += fmt.Sprintf(`
  %s: %d executions, %.1f%% success rate, avg: %v`,
			scanner.Name,
			scanner.ExecutionCount,
			scanner.SuccessRate,
			scanner.AverageTime.Round(time.Millisecond),
		)
	}

	if len(metrics.AIProviderMetrics) > 0 {
		summary += "\n\nAI Provider Performance:"
		for _, ai := range metrics.AIProviderMetrics {
			summary += fmt.Sprintf(`
  %s: %d requests, %.1f%% success rate, avg: %v, tokens: %s`,
				ai.Provider,
				ai.RequestCount,
				ai.SuccessRate,
				ai.AverageTime.Round(time.Millisecond),
				humanize.Comma(ai.TokensUsed),
			)
		}
	}

	return summary
}

// ResetMetrics resets all performance metrics
func (pm *PerformanceMonitor) ResetMetrics() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.metrics = &Metrics{
		ScannerMetrics:    make(map[string]*ScannerMetrics),
		AIProviderMetrics: make(map[string]*AIMetrics),
		FastestScanTime:   time.Hour * 24,
	}
	pm.startTime = time.Now()
}

// Enable enables performance monitoring
func (pm *PerformanceMonitor) Enable() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	pm.enabled = true
}

// Disable disables performance monitoring
func (pm *PerformanceMonitor) Disable() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	pm.enabled = false
}

// IsEnabled returns whether performance monitoring is enabled
func (pm *PerformanceMonitor) IsEnabled() bool {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return pm.enabled
}

// GetResourceUsage returns current resource usage
func (pm *PerformanceMonitor) GetResourceUsage() ResourceUsage {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return ResourceUsage{
		CPUUsage:       pm.metrics.CPUUsage,
		MemoryUsage:    pm.metrics.MemoryUsage,
		HeapSize:       memStats.HeapAlloc,
		HeapObjects:    memStats.HeapObjects,
		GoroutineCount: pm.metrics.GoroutineCount,
		GCPauses:       memStats.NumGC,
		LastGCTime:     time.Unix(0, int64(memStats.LastGC)),
	}
}

// ResourceUsage represents current resource usage
type ResourceUsage struct {
	CPUUsage       float64   `json:"cpu_usage"`
	MemoryUsage    uint64    `json:"memory_usage"`
	HeapSize       uint64    `json:"heap_size"`
	HeapObjects    uint64    `json:"heap_objects"`
	GoroutineCount int       `json:"goroutine_count"`
	GCPauses       uint32    `json:"gc_pauses"`
	LastGCTime     time.Time `json:"last_gc_time"`
}

// OptimizationSuggestion represents a performance optimization suggestion
type OptimizationSuggestion struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Impact      string  `json:"impact"`
	Priority    int     `json:"priority"`
	MetricValue float64 `json:"metric_value"`
}

// GetOptimizationSuggestions analyzes metrics and provides optimization suggestions
func (pm *PerformanceMonitor) GetOptimizationSuggestions() []OptimizationSuggestion {
	metrics := pm.GetMetrics()
	var suggestions []OptimizationSuggestion

	// High CPU usage
	if metrics.CPUUsage > 80 {
		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "CPU",
			Description: "CPU usage is high. Consider reducing scan concurrency or optimizing scanner algorithms.",
			Impact:      "High",
			Priority:    1,
			MetricValue: metrics.CPUUsage,
		})
	}

	// High memory usage
	if metrics.MemoryUsage > 1024*1024*1024 { // 1GB
		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "Memory",
			Description: "Memory usage is high. Consider implementing result streaming or garbage collection optimization.",
			Impact:      "Medium",
			Priority:    2,
			MetricValue: float64(metrics.MemoryUsage),
		})
	}

	// Slow scanners
	for _, scanner := range metrics.ScannerMetrics {
		if scanner.AverageTime > 30*time.Second {
			suggestions = append(suggestions, OptimizationSuggestion{
				Type:        "Scanner",
				Description: fmt.Sprintf("Scanner '%s' is slow. Consider optimizing timeouts or algorithm.", scanner.Name),
				Impact:      "Medium",
				Priority:    3,
				MetricValue: float64(scanner.AverageTime.Milliseconds()),
			})
		}
	}

	// Low success rates
	for _, scanner := range metrics.ScannerMetrics {
		if scanner.SuccessRate < 90 && scanner.ExecutionCount > 10 {
			suggestions = append(suggestions, OptimizationSuggestion{
				Type:        "Reliability",
				Description: fmt.Sprintf("Scanner '%s' has low success rate. Check error handling and retry logic.", scanner.Name),
				Impact:      "High",
				Priority:    1,
				MetricValue: scanner.SuccessRate,
			})
		}
	}

	// High goroutine count
	if metrics.GoroutineCount > 1000 {
		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "Concurrency",
			Description: "High goroutine count detected. Check for goroutine leaks or excessive concurrency.",
			Impact:      "Medium",
			Priority:    2,
			MetricValue: float64(metrics.GoroutineCount),
		})
	}

	return suggestions
}
