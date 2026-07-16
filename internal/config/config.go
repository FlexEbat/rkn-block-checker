// Package config holds the scanner's tunable parameters: the port list,
// timeouts for network checks, and block sizes for the block-transfer test.
// Defaults are baked into the code; if config.json exists in the working
// directory its values override them (a partial config is fine — missing
// fields keep their defaults).
package config

import (
	"encoding/json"
	"os"
	"time"
)

type Config struct {
	Ports         []int `json:"ports"`
	DialTimeoutMS int   `json:"dial_timeout_ms"`
	TLSTimeoutMS  int   `json:"tls_timeout_ms"`
	QUICTimeoutMS int   `json:"quic_timeout_ms"`
	ScanTimeoutMS int   `json:"scan_timeout_ms"`
	BlockSmallKB  int   `json:"block_small_kb"`
	BlockLargeKB  int   `json:"block_large_kb"`
}

func Default() Config {
	return Config{
		Ports:         []int{21, 22, 80, 443, 3306, 3389},
		DialTimeoutMS: 2000,
		TLSTimeoutMS:  10000,
		QUICTimeoutMS: 5000,
		ScanTimeoutMS: 500,
		BlockSmallKB:  8,
		BlockLargeKB:  16,
	}
}

// Load reads config.json from the given path. If the file doesn't exist, it
// silently returns the default configuration (that's not an error — the
// config file is optional). If the file exists but is malformed, it returns
// an explicit error rather than silently running with unexpected ports/timeouts.
func Load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}

	// Unmarshal into a separate struct so fields absent from the file don't
	// overwrite the defaults with zero values.
	var override Config
	if err := json.Unmarshal(data, &override); err != nil {
		return cfg, err
	}

	if len(override.Ports) > 0 {
		cfg.Ports = override.Ports
	}
	if override.DialTimeoutMS > 0 {
		cfg.DialTimeoutMS = override.DialTimeoutMS
	}
	if override.TLSTimeoutMS > 0 {
		cfg.TLSTimeoutMS = override.TLSTimeoutMS
	}
	if override.QUICTimeoutMS > 0 {
		cfg.QUICTimeoutMS = override.QUICTimeoutMS
	}
	if override.ScanTimeoutMS > 0 {
		cfg.ScanTimeoutMS = override.ScanTimeoutMS
	}
	if override.BlockSmallKB > 0 {
		cfg.BlockSmallKB = override.BlockSmallKB
	}
	if override.BlockLargeKB > 0 {
		cfg.BlockLargeKB = override.BlockLargeKB
	}

	return cfg, nil
}

func (c Config) DialTimeout() time.Duration { return time.Duration(c.DialTimeoutMS) * time.Millisecond }
func (c Config) TLSTimeout() time.Duration  { return time.Duration(c.TLSTimeoutMS) * time.Millisecond }
func (c Config) QUICTimeout() time.Duration { return time.Duration(c.QUICTimeoutMS) * time.Millisecond }
func (c Config) ScanTimeout() time.Duration { return time.Duration(c.ScanTimeoutMS) * time.Millisecond }
