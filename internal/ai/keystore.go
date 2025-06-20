package ai

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/ajaikumarvs/harbinger/pkg/models"
)

// KeyStore manages secure storage of API keys
type KeyStore struct {
	configDir  string
	configFile string
	masterKey  []byte
}

// EncryptedAPIKey represents an encrypted API key
type EncryptedAPIKey struct {
	Provider     models.APIProvider `json:"provider"`
	EncryptedKey string             `json:"encrypted_key"`
	Salt         string             `json:"salt"`
	Nonce        string             `json:"nonce"`
	IsActive     bool               `json:"is_active"`
	LastTested   time.Time          `json:"last_tested"`
	TestStatus   string             `json:"test_status"`
	Model        string             `json:"model"`
	CustomURL    string             `json:"custom_url,omitempty"`
	CreatedAt    time.Time          `json:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at"`
}

// KeyStoreData represents the encrypted key store file
type KeyStoreData struct {
	Version int               `json:"version"`
	Keys    []EncryptedAPIKey `json:"keys"`
}

// NewKeyStore creates a new key store
func NewKeyStore() (*KeyStore, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(homeDir, ".harbinger")
	configFile := filepath.Join(configDir, "keystore.json")

	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Generate or load master key
	masterKey, err := loadOrGenerateMasterKey(configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize master key: %w", err)
	}

	return &KeyStore{
		configDir:  configDir,
		configFile: configFile,
		masterKey:  masterKey,
	}, nil
}

// StoreAPIKey stores an API key securely
func (ks *KeyStore) StoreAPIKey(apiKey models.APIKey) error {
	// Load existing keys
	data, err := ks.loadKeyStore()
	if err != nil {
		return fmt.Errorf("failed to load key store: %w", err)
	}

	// Encrypt the API key
	encryptedKey, err := ks.encryptAPIKey(apiKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt API key: %w", err)
	}

	// Update or add the key
	found := false
	for i, key := range data.Keys {
		if key.Provider == apiKey.Provider {
			data.Keys[i] = encryptedKey
			found = true
			break
		}
	}

	if !found {
		data.Keys = append(data.Keys, encryptedKey)
	}

	// Save the key store
	if err := ks.saveKeyStore(data); err != nil {
		return fmt.Errorf("failed to save key store: %w", err)
	}

	return nil
}

// GetAPIKey retrieves and decrypts an API key
func (ks *KeyStore) GetAPIKey(provider models.APIProvider) (*models.APIKey, error) {
	// Load key store
	data, err := ks.loadKeyStore()
	if err != nil {
		return nil, fmt.Errorf("failed to load key store: %w", err)
	}

	// Find the key
	for _, encKey := range data.Keys {
		if encKey.Provider == provider {
			apiKey, err := ks.decryptAPIKey(encKey)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt API key: %w", err)
			}
			return apiKey, nil
		}
	}

	return nil, fmt.Errorf("API key not found for provider: %s", provider)
}

// GetAllAPIKeys retrieves all stored API keys (decrypted)
func (ks *KeyStore) GetAllAPIKeys() ([]models.APIKey, error) {
	// Load key store
	data, err := ks.loadKeyStore()
	if err != nil {
		return nil, fmt.Errorf("failed to load key store: %w", err)
	}

	var apiKeys []models.APIKey
	for _, encKey := range data.Keys {
		apiKey, err := ks.decryptAPIKey(encKey)
		if err != nil {
			// Log error but continue with other keys
			continue
		}
		apiKeys = append(apiKeys, *apiKey)
	}

	return apiKeys, nil
}

// UpdateAPIKeyStatus updates the test status of an API key
func (ks *KeyStore) UpdateAPIKeyStatus(provider models.APIProvider, status string, isActive bool) error {
	// Load key store
	data, err := ks.loadKeyStore()
	if err != nil {
		return fmt.Errorf("failed to load key store: %w", err)
	}

	// Find and update the key
	found := false
	for i, key := range data.Keys {
		if key.Provider == provider {
			data.Keys[i].TestStatus = status
			data.Keys[i].IsActive = isActive
			data.Keys[i].LastTested = time.Now()
			data.Keys[i].UpdatedAt = time.Now()
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("API key not found for provider: %s", provider)
	}

	// Save the key store
	if err := ks.saveKeyStore(data); err != nil {
		return fmt.Errorf("failed to save key store: %w", err)
	}

	return nil
}

// DeleteAPIKey removes an API key
func (ks *KeyStore) DeleteAPIKey(provider models.APIProvider) error {
	// Load key store
	data, err := ks.loadKeyStore()
	if err != nil {
		return fmt.Errorf("failed to load key store: %w", err)
	}

	// Remove the key
	for i, key := range data.Keys {
		if key.Provider == provider {
			data.Keys = append(data.Keys[:i], data.Keys[i+1:]...)
			break
		}
	}

	// Save the key store
	if err := ks.saveKeyStore(data); err != nil {
		return fmt.Errorf("failed to save key store: %w", err)
	}

	return nil
}

// encryptAPIKey encrypts an API key using AES-GCM
func (ks *KeyStore) encryptAPIKey(apiKey models.APIKey) (EncryptedAPIKey, error) {
	// Generate salt for key derivation
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return EncryptedAPIKey{}, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive encryption key
	key := pbkdf2.Key(ks.masterKey, salt, 100000, 32, sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedAPIKey{}, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedAPIKey{}, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedAPIKey{}, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the API key
	plaintext := []byte(apiKey.Key)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	now := time.Now()
	return EncryptedAPIKey{
		Provider:     apiKey.Provider,
		EncryptedKey: hex.EncodeToString(ciphertext),
		Salt:         hex.EncodeToString(salt),
		Nonce:        hex.EncodeToString(nonce),
		IsActive:     apiKey.IsActive,
		LastTested:   apiKey.LastTested,
		TestStatus:   apiKey.TestStatus,
		Model:        apiKey.Model,
		CustomURL:    apiKey.CustomURL,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// decryptAPIKey decrypts an encrypted API key
func (ks *KeyStore) decryptAPIKey(encKey EncryptedAPIKey) (*models.APIKey, error) {
	// Decode salt and nonce
	salt, err := hex.DecodeString(encKey.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	nonce, err := hex.DecodeString(encKey.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	ciphertext, err := hex.DecodeString(encKey.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Derive decryption key
	key := pbkdf2.Key(ks.masterKey, salt, 100000, 32, sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the API key
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt API key: %w", err)
	}

	return &models.APIKey{
		Provider:   encKey.Provider,
		Key:        string(plaintext),
		IsActive:   encKey.IsActive,
		LastTested: encKey.LastTested,
		TestStatus: encKey.TestStatus,
		Model:      encKey.Model,
		CustomURL:  encKey.CustomURL,
	}, nil
}

// loadKeyStore loads the key store from disk
func (ks *KeyStore) loadKeyStore() (*KeyStoreData, error) {
	if _, err := os.Stat(ks.configFile); os.IsNotExist(err) {
		// Return empty key store if file doesn't exist
		return &KeyStoreData{
			Version: 1,
			Keys:    []EncryptedAPIKey{},
		}, nil
	}

	data, err := os.ReadFile(ks.configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key store file: %w", err)
	}

	var keyStore KeyStoreData
	if err := json.Unmarshal(data, &keyStore); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key store: %w", err)
	}

	return &keyStore, nil
}

// saveKeyStore saves the key store to disk
func (ks *KeyStore) saveKeyStore(data *KeyStoreData) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key store: %w", err)
	}

	// Write to temporary file first, then rename (atomic operation)
	tempFile := ks.configFile + ".tmp"
	if err := os.WriteFile(tempFile, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write temporary key store file: %w", err)
	}

	if err := os.Rename(tempFile, ks.configFile); err != nil {
		os.Remove(tempFile) // Clean up temp file
		return fmt.Errorf("failed to rename key store file: %w", err)
	}

	return nil
}

// loadOrGenerateMasterKey loads or generates the master key for encryption
func loadOrGenerateMasterKey(configDir string) ([]byte, error) {
	keyFile := filepath.Join(configDir, ".master.key")

	// Try to load existing key
	if data, err := os.ReadFile(keyFile); err == nil {
		key, err := hex.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("failed to decode master key: %w", err)
		}
		return key, nil
	}

	// Generate new master key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	// Save the key
	keyData := hex.EncodeToString(key)
	if err := os.WriteFile(keyFile, []byte(keyData), 0600); err != nil {
		return nil, fmt.Errorf("failed to save master key: %w", err)
	}

	return key, nil
}
