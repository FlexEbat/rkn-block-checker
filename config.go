// Package config хранит настраиваемые параметры сканера: список портов,
// таймауты для сетевых проверок и размеры блоков для block-теста.
// Значения по умолчанию зашиты в коде; при наличии config.json в рабочей
// директории они переопределяются из файла (частичный конфиг допустим —
// отсутствующие поля остаются дефолтными).
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

// Load читает config.json из указанного пути. Если файла нет — тихо
// возвращает дефолтную конфигурацию (это не ошибка, конфиг опционален).
// Если файл есть, но повреждён — возвращает ошибку явно, чтобы не работать
// с неожиданными портами/таймаутами.
func Load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}

	// Разбираем в отдельную структуру с указателями/пустыми срезами,
	// чтобы не затирать дефолты полями, отсутствующими в файле.
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
