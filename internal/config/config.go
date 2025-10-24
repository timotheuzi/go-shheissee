package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/boboTheFoff/shheissee-go/internal/models"
)

// LoadConfig loads configuration from file or returns defaults
func LoadConfig(configPath string) (*models.AttackDetectorConfig, error) {
	config := models.DefaultConfig()

	if configPath == "" {
		return config, nil
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Save default config to file
		if err := SaveConfig(config, configPath); err != nil {
			return config, err
		}
		return config, nil
	}

	// Load config from file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return config, err
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return config, err
	}

	return config, nil
}

// SaveConfig saves configuration to file
func SaveConfig(config *models.AttackDetectorConfig, configPath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}

// EnsureDirectories creates necessary directories for the application
func EnsureDirectories(config *models.AttackDetectorConfig) error {
	dirs := []string{
		filepath.Dir(config.KnownDevicesFile),
		filepath.Dir(config.BluetoothDevicesFile),
		filepath.Dir(config.LogFile),
		"web/templates",
		"web/static",
		"scripts",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	return nil
}
