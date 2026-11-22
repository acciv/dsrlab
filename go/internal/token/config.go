// Package token implements a local, deterministic scanner for synthetic
// Discord-style token patterns. Its reports never contain full secret values.
package token

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// Pattern is one detection rule from the shared lab configuration.
// The compiled regular expression is kept unexported: only fingerprints and
// lengths are ever exposed by the scanner.
type Pattern struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	Regex          string `json:"regex"`
	ValueGroup     int    `json:"value_group"`
	RiskWeight     int    `json:"risk_weight"`
	ExpectedLength int    `json:"expected_length"`

	re *regexp.Regexp
}

// Config is the part of the shared lab configuration consumed by dstoken.
// Unknown configuration keys are intentionally ignored.
type Config struct {
	Version              string         `json:"version"`
	ExcludeDirs          []string       `json:"exclude_dirs"`
	ExcludeExtensions    []string       `json:"exclude_extensions"`
	MaxFileBytes         int64          `json:"max_file_bytes"`
	MaxLineBytes         int64          `json:"max_line_bytes"`
	Workers              int            `json:"workers"`
	Patterns             []Pattern      `json:"patterns"`
	FalsePositiveMarkers []string       `json:"false_positive_markers"`
	RiskLevels           map[string]int `json:"risk_levels"`
}

// LoadConfig reads, parses, compiles and validates a JSON configuration file.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read token config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse token config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// validate checks all fields and caches the compiled regexps in cfg.patterns.
func (cfg *Config) validate() error {
	if cfg.MaxFileBytes <= 0 {
		return fmt.Errorf("max_file_bytes must be positive, got %d", cfg.MaxFileBytes)
	}
	if cfg.MaxLineBytes <= 0 {
		return fmt.Errorf("max_line_bytes must be positive, got %d", cfg.MaxLineBytes)
	}
	if cfg.Workers < 0 {
		return fmt.Errorf("workers must not be negative, got %d", cfg.Workers)
	}

	for i := range cfg.Patterns {
		p := &cfg.Patterns[i]
		if p.ID == "" {
			return fmt.Errorf("patterns[%d]: id must not be empty", i)
		}
		if p.Type == "" {
			return fmt.Errorf("patterns[%d] (%s): type must not be empty", i, p.ID)
		}
		if p.Regex == "" {
			return fmt.Errorf("patterns[%d] (%s): regex must not be empty", i, p.ID)
		}
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return fmt.Errorf("patterns[%d] (%s): invalid regex: %w", i, p.ID, err)
		}
		if p.ValueGroup < 1 || p.ValueGroup > re.NumSubexp() {
			return fmt.Errorf("patterns[%d] (%s): value_group %d outside 1..%d",
				i, p.ID, p.ValueGroup, re.NumSubexp())
		}
		if p.RiskWeight < 0 {
			return fmt.Errorf("patterns[%d] (%s): risk_weight must not be negative", i, p.ID)
		}
		if p.ExpectedLength < 0 {
			return fmt.Errorf("patterns[%d] (%s): expected_length must not be negative", i, p.ID)
		}
		p.re = re
	}
	return nil
}
