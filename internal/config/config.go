package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Workers int    `yaml:"workers"`
	Timeout string `yaml:"timeout"`

	Audit  AuditConfig  `yaml:"audit"`
	Scan   ScanConfig   `yaml:"scan"`
	Attack AttackConfig `yaml:"attack"`
	Output OutputConfig `yaml:"output"`
}

type AuditConfig struct {
	Exclude     []string `yaml:"exclude"`
	SeverityMin string   `yaml:"severity_min"`
}

type ScanConfig struct {
	Timeout        string `yaml:"timeout"`
	MaxConnections int    `yaml:"max_connections"`
}

type AttackConfig struct {
	Intensity string `yaml:"intensity"`
	Delay     string `yaml:"delay"`
}

type OutputConfig struct {
	Format  string `yaml:"format"`
	NoColor bool   `yaml:"no_color"`
}

func Default() *Config {
	return &Config{}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
