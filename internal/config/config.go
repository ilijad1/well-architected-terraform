// Package config handles suppression configuration loading and application.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the .wat.yaml configuration file.
type Config struct {
	Version      string        `yaml:"version"`
	Suppressions []Suppression `yaml:"suppressions"`
}

// Suppression defines a rule+resource combination that should be excluded from findings.
type Suppression struct {
	RuleID   string `yaml:"rule_id"`  // e.g. "S3-001" or "*" for all rules
	Resource string `yaml:"resource"` // full Terraform address or "*" for all resources
	Reason   string `yaml:"reason"`   // required justification
	Expires  string `yaml:"expires"`  // required expiry date in YYYY-MM-DD format
}

// Load reads and parses a .wat.yaml configuration file.
// Returns an empty Config (not an error) if the file does not exist.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is a CLI argument supplied by the operator
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config file %s: %w", path, err)
	}

	return &cfg, nil
}

func validate(cfg *Config) error {
	for i, s := range cfg.Suppressions {
		if s.RuleID == "" {
			return fmt.Errorf("suppression[%d]: rule_id is required", i)
		}
		if s.Resource == "" {
			return fmt.Errorf("suppression[%d]: resource is required", i)
		}
		if s.Reason == "" {
			return fmt.Errorf("suppression[%d]: reason is required", i)
		}
		if s.Expires == "" {
			return fmt.Errorf("suppression[%d]: expires is required", i)
		}
	}
	return nil
}
