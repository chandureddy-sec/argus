package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// ProviderConfig represents configuration for a specific OSINT source.
type ProviderConfig struct {
	Enabled   bool          `yaml:"enabled"`
	APIKey    string        `yaml:"api_key"`
	Timeout   time.Duration `yaml:"timeout"`
	RateLimit time.Duration `yaml:"rate_limit"`
}

// Config represents the global configuration structure.
type Config struct {
	Timeout     time.Duration              `yaml:"timeout"`
	Concurrency int                        `yaml:"concurrency"`
	PassiveOnly bool                       `yaml:"passive_only"`
	Verbose     bool                       `yaml:"verbose"`
	Resolvers   []string                   `yaml:"resolvers"`
	Providers   map[string]ProviderConfig  `yaml:"providers"`
}

var envRegex = regexp.MustCompile(`\$\{([^}]+)\}`)

// DefaultConfig returns safe default settings.
func DefaultConfig() *Config {
	return &Config{
		Timeout:     15 * time.Second,
		Concurrency: 10,
		PassiveOnly: true,
		Verbose:     false,
		Resolvers: []string{
			"1.1.1.1:53",
			"8.8.8.8:53",
			"9.9.9.9:53",
		},
		Providers: map[string]ProviderConfig{
			"crtsh": {
				Enabled: true,
				Timeout: 20 * time.Second,
			},
			"hackertarget": {
				Enabled:   true,
				RateLimit: 2 * time.Second,
			},
		},
	}
}

// Load reads and parses a YAML configuration file, expanding environment variables.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		// Try default locations
		candidates := []string{"./config.yaml", "./configs/config.yaml"}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				path = c
				break
			}
		}
	}

	if path == "" {
		// Use defaults if no configuration file exists
		return cfg, nil
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	// Expand environment variables like ${VT_API_KEY}
	expanded := envRegex.ReplaceAllStringFunc(string(data), func(match string) string {
		varName := match[2 : len(match)-1]
		if val, ok := os.LookupEnv(varName); ok {
			return val
		}
		return match
	})

	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML configuration: %w", err)
	}

	return cfg, nil
}
