package storage

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// StorageManager handles persistent storage of scan results using JSON files
type StorageManager struct {
	dataPath string
}

// NewStorageManager creates a new storage manager
func NewStorageManager() (*StorageManager, error) {
	// Create data directory in user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	dataPath := filepath.Join(homeDir, ".harbinger", "data")
	if err := os.MkdirAll(dataPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	return &StorageManager{
		dataPath: dataPath,
	}, nil
}

// Close is a no-op for file-based storage but maintains interface compatibility
func (sm *StorageManager) Close() error {
	return nil
}

// SaveScanResult saves a scan result to a JSON file
func (sm *StorageManager) SaveScanResult(result *models.ScanResult) error {
	// Save the full scan result
	scanFile := filepath.Join(sm.dataPath, fmt.Sprintf("scan_%s.json", result.ID))
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal scan result: %w", err)
	}

	if err := ioutil.WriteFile(scanFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write scan file: %w", err)
	}

	// Update the index file
	return sm.updateIndex()
}

// ScanIndex represents a lightweight scan record for indexing
type ScanIndex struct {
	ID            string            `json:"id"`
	URL           string            `json:"url"`
	Timestamp     time.Time         `json:"timestamp"`
	SecurityScore int               `json:"security_score"`
	Status        models.ScanStatus `json:"status"`
}

// updateIndex rebuilds the index file with all current scans
func (sm *StorageManager) updateIndex() error {
	var indices []ScanIndex

	// Read all scan files
	files, err := ioutil.ReadDir(sm.dataPath)
	if err != nil {
		return fmt.Errorf("failed to read data directory: %w", err)
	}

	for _, file := range files {
		if !strings.HasPrefix(file.Name(), "scan_") || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		scanPath := filepath.Join(sm.dataPath, file.Name())
		data, err := ioutil.ReadFile(scanPath)
		if err != nil {
			continue // Skip unreadable files
		}

		var result models.ScanResult
		if err := json.Unmarshal(data, &result); err != nil {
			continue // Skip malformed files
		}

		indices = append(indices, ScanIndex{
			ID:            result.ID,
			URL:           result.URL,
			Timestamp:     result.Timestamp,
			SecurityScore: result.SecurityScore,
			Status:        result.Status,
		})
	}

	// Sort by timestamp (newest first)
	sort.Slice(indices, func(i, j int) bool {
		return indices[i].Timestamp.After(indices[j].Timestamp)
	})

	// Write index file
	indexPath := filepath.Join(sm.dataPath, "index.json")
	indexData, err := json.MarshalIndent(indices, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal index: %w", err)
	}

	return ioutil.WriteFile(indexPath, indexData, 0644)
}

// GetScanResult retrieves a scan result by ID
func (sm *StorageManager) GetScanResult(id string) (*models.ScanResult, error) {
	scanFile := filepath.Join(sm.dataPath, fmt.Sprintf("scan_%s.json", id))

	data, err := ioutil.ReadFile(scanFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("scan result not found: %s", id)
		}
		return nil, fmt.Errorf("failed to read scan file: %w", err)
	}

	var result models.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scan result: %w", err)
	}

	return &result, nil
}

// ListScanResults returns a list of all scan results, optionally filtered
func (sm *StorageManager) ListScanResults(limit int, offset int) ([]ScanIndex, error) {
	indexPath := filepath.Join(sm.dataPath, "index.json")

	// If index doesn't exist, create it
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		if err := sm.updateIndex(); err != nil {
			return nil, fmt.Errorf("failed to create index: %w", err)
		}
	}

	data, err := ioutil.ReadFile(indexPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read index file: %w", err)
	}

	var results []ScanIndex
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("failed to unmarshal index: %w", err)
	}

	// Apply pagination
	if offset >= len(results) {
		return []ScanIndex{}, nil
	}

	end := offset + limit
	if end > len(results) {
		end = len(results)
	}

	return results[offset:end], nil
}

// DeleteScanResult removes a scan result from storage
func (sm *StorageManager) DeleteScanResult(id string) error {
	scanFile := filepath.Join(sm.dataPath, fmt.Sprintf("scan_%s.json", id))

	if err := os.Remove(scanFile); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("scan result not found: %s", id)
		}
		return fmt.Errorf("failed to delete scan file: %w", err)
	}

	// Update the index
	return sm.updateIndex()
}

// StorageStats represents storage statistics
type StorageStats struct {
	TotalScans   int    `json:"total_scans"`
	TotalSize    int64  `json:"total_size"`
	DatabasePath string `json:"database_path"`
}

// GetStorageStats returns statistics about the storage
func (sm *StorageManager) GetStorageStats() (*StorageStats, error) {
	files, err := ioutil.ReadDir(sm.dataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read data directory: %w", err)
	}

	var totalSize int64
	scanCount := 0

	for _, file := range files {
		if strings.HasPrefix(file.Name(), "scan_") && strings.HasSuffix(file.Name(), ".json") {
			scanCount++
		}
		totalSize += file.Size()
	}

	return &StorageStats{
		TotalScans:   scanCount,
		TotalSize:    totalSize,
		DatabasePath: sm.dataPath,
	}, nil
}

// CompactDatabase is a no-op for file-based storage but maintains interface compatibility
func (sm *StorageManager) CompactDatabase() error {
	// For file-based storage, we can clean up and rebuild the index
	return sm.updateIndex()
}

// ExportData exports all scan data to a JSON file
func (sm *StorageManager) ExportData(outputPath string) error {
	indices, err := sm.ListScanResults(1000, 0) // Get all scans
	if err != nil {
		return fmt.Errorf("failed to list scans: %w", err)
	}

	var allScans []models.ScanResult
	for _, index := range indices {
		result, err := sm.GetScanResult(index.ID)
		if err != nil {
			continue // Skip failed reads
		}
		allScans = append(allScans, *result)
	}

	data, err := json.MarshalIndent(allScans, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal export data: %w", err)
	}

	return ioutil.WriteFile(outputPath, data, 0644)
}

// ImportData imports scan data from a JSON file
func (sm *StorageManager) ImportData(inputPath string) error {
	data, err := ioutil.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read import file: %w", err)
	}

	var scans []models.ScanResult
	if err := json.Unmarshal(data, &scans); err != nil {
		return fmt.Errorf("failed to unmarshal import data: %w", err)
	}

	for _, scan := range scans {
		if err := sm.SaveScanResult(&scan); err != nil {
			return fmt.Errorf("failed to save imported scan %s: %w", scan.ID, err)
		}
	}

	return nil
}

// SearchScans searches for scans matching a pattern
func (sm *StorageManager) SearchScans(pattern string) ([]ScanIndex, error) {
	indices, err := sm.ListScanResults(1000, 0) // Get all scans
	if err != nil {
		return nil, err
	}

	var matches []ScanIndex
	pattern = strings.ToLower(pattern)

	for _, index := range indices {
		if strings.Contains(strings.ToLower(index.URL), pattern) ||
			strings.Contains(strings.ToLower(index.ID), pattern) {
			matches = append(matches, index)
		}
	}

	return matches, nil
}
