package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// StorageManager handles persistent storage of scan results
type StorageManager struct {
	db       *leveldb.DB
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

	// Open LevelDB with optimized settings
	opts := &opt.Options{
		Filter:             filter.NewBloomFilter(10),
		Compression:        opt.SnappyCompression,
		BlockCacheCapacity: 16 * 1024 * 1024, // 16MB cache
		WriteBuffer:        4 * 1024 * 1024,  // 4MB write buffer
	}

	dbPath := filepath.Join(dataPath, "scans.db")
	db, err := leveldb.OpenFile(dbPath, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	return &StorageManager{
		db:       db,
		dataPath: dataPath,
	}, nil
}

// Close closes the database connection
func (sm *StorageManager) Close() error {
	if sm.db != nil {
		return sm.db.Close()
	}
	return nil
}

// SaveScanResult saves a scan result to persistent storage
func (sm *StorageManager) SaveScanResult(result *models.ScanResult) error {
	key := fmt.Sprintf("scan:%s", result.ID)

	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal scan result: %w", err)
	}

	if err := sm.db.Put([]byte(key), data, nil); err != nil {
		return fmt.Errorf("failed to save scan result: %w", err)
	}

	// Also save to index for quick retrieval
	indexKey := fmt.Sprintf("index:%d:%s", result.Timestamp.Unix(), result.ID)
	indexData, err := json.Marshal(ScanIndex{
		ID:            result.ID,
		URL:           result.URL,
		Timestamp:     result.Timestamp,
		SecurityScore: result.SecurityScore,
		Status:        result.Status,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal scan index: %w", err)
	}

	if err := sm.db.Put([]byte(indexKey), indexData, nil); err != nil {
		return fmt.Errorf("failed to save scan index: %w", err)
	}

	return nil
}

// ScanIndex represents a lightweight scan record for indexing
type ScanIndex struct {
	ID            string            `json:"id"`
	URL           string            `json:"url"`
	Timestamp     time.Time         `json:"timestamp"`
	SecurityScore int               `json:"security_score"`
	Status        models.ScanStatus `json:"status"`
}

// GetScanResult retrieves a scan result by ID
func (sm *StorageManager) GetScanResult(id string) (*models.ScanResult, error) {
	key := fmt.Sprintf("scan:%s", id)

	data, err := sm.db.Get([]byte(key), nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			return nil, fmt.Errorf("scan result not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get scan result: %w", err)
	}

	var result models.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scan result: %w", err)
	}

	return &result, nil
}

// ListScanResults returns a list of all scan results, optionally filtered
func (sm *StorageManager) ListScanResults(limit int, offset int) ([]ScanIndex, error) {
	var results []ScanIndex

	iter := sm.db.NewIterator(nil, nil)
	defer iter.Release()

	// Iterate through index entries
	for iter.Next() {
		key := string(iter.Key())
		if !strings.HasPrefix(key, "index:") {
			continue
		}

		var index ScanIndex
		if err := json.Unmarshal(iter.Value(), &index); err != nil {
			continue // Skip malformed entries
		}

		results = append(results, index)
	}

	// Sort by timestamp (newest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.After(results[j].Timestamp)
	})

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
	// Get the scan to find its timestamp for index deletion
	result, err := sm.GetScanResult(id)
	if err != nil {
		return err
	}

	// Delete main record
	scanKey := fmt.Sprintf("scan:%s", id)
	if err := sm.db.Delete([]byte(scanKey), nil); err != nil {
		return fmt.Errorf("failed to delete scan result: %w", err)
	}

	// Delete index entry
	indexKey := fmt.Sprintf("index:%d:%s", result.Timestamp.Unix(), id)
	if err := sm.db.Delete([]byte(indexKey), nil); err != nil {
		return fmt.Errorf("failed to delete scan index: %w", err)
	}

	return nil
}

// GetStorageStats returns statistics about the storage
func (sm *StorageManager) GetStorageStats() (*StorageStats, error) {
	stats := &StorageStats{}

	iter := sm.db.NewIterator(nil, nil)
	defer iter.Release()

	var totalSize int64
	scanCount := 0

	for iter.Next() {
		key := string(iter.Key())
		if strings.HasPrefix(key, "scan:") {
			scanCount++
			totalSize += int64(len(iter.Value()))
		}
	}

	stats.TotalScans = scanCount
	stats.TotalSize = totalSize
	stats.DatabasePath = sm.dataPath

	return stats, nil
}

// StorageStats represents storage statistics
type StorageStats struct {
	TotalScans   int    `json:"total_scans"`
	TotalSize    int64  `json:"total_size"`
	DatabasePath string `json:"database_path"`
}

// CompactDatabase optimizes the database by removing dead entries
func (sm *StorageManager) CompactDatabase() error {
	// Trigger manual compaction for entire database
	return sm.db.CompactRange(util.Range{})
}

// ExportData exports all scan data to a JSON file
func (sm *StorageManager) ExportData(outputPath string) error {
	var allScans []models.ScanResult

	iter := sm.db.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		key := string(iter.Key())
		if !strings.HasPrefix(key, "scan:") {
			continue
		}

		var result models.ScanResult
		if err := json.Unmarshal(iter.Value(), &result); err != nil {
			continue // Skip malformed entries
		}

		allScans = append(allScans, result)
	}

	// Sort by timestamp
	sort.Slice(allScans, func(i, j int) bool {
		return allScans[i].Timestamp.Before(allScans[j].Timestamp)
	})

	data, err := json.MarshalIndent(allScans, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal export data: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write export file: %w", err)
	}

	return nil
}

// ImportData imports scan data from a JSON file
func (sm *StorageManager) ImportData(inputPath string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read import file: %w", err)
	}

	var scans []models.ScanResult
	if err := json.Unmarshal(data, &scans); err != nil {
		return fmt.Errorf("failed to unmarshal import data: %w", err)
	}

	// Save each scan
	for _, scan := range scans {
		if err := sm.SaveScanResult(&scan); err != nil {
			return fmt.Errorf("failed to import scan %s: %w", scan.ID, err)
		}
	}

	return nil
}

// SearchScans searches for scans by URL pattern
func (sm *StorageManager) SearchScans(pattern string) ([]ScanIndex, error) {
	var results []ScanIndex

	iter := sm.db.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		key := string(iter.Key())
		if !strings.HasPrefix(key, "index:") {
			continue
		}

		var index ScanIndex
		if err := json.Unmarshal(iter.Value(), &index); err != nil {
			continue
		}

		if strings.Contains(strings.ToLower(index.URL), strings.ToLower(pattern)) {
			results = append(results, index)
		}
	}

	// Sort by timestamp (newest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.After(results[j].Timestamp)
	})

	return results, nil
}
