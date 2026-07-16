package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"

	"rkn-checker/internal/logger"
)

// rttCheck — упрощённый аналог метода SNITCH из раздела 10.1: измеряет RTT
// TCP-подключения к цели и показывает разброс задержек.
//
// ВАЖНО: полноценный SNITCH сопоставляет измеренный RTT с ожидаемой
// задержкой для заявленной GeoIP-локации через сеть "контрольных точек"
// (landmarks) — у этого инструмента такой базы нет, поэтому здесь только
// сырые измерения. Разброс/аномалии придётся сопоставлять с результатом
// GeoIP-проверки (пункт "GeoIP / ASN / Hosting") вручную.
func rttCheck(ctx context.Context, target string) {
	logger.Info("Измерение RTT до %s:443 (5 попыток)...", target)

	const attempts = 5
	var samples []time.Duration

	for i := 0; i < attempts; i++ {
		start := time.Now()
		dialer := &net.Dialer{Timeout: cfg.DialTimeout()}
		conn, err := dialer.DialContext(ctx, "tcp", target+":443")
		if err != nil {
			logger.Warn("Попытка %d/%d: %v", i+1, attempts, err)
			continue
		}
		samples = append(samples, time.Since(start))
		conn.Close()
	}

	if len(samples) == 0 {
		logger.Error("Не удалось получить ни одного успешного измерения")
		return
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	min, max := samples[0], samples[len(samples)-1]
	var sum time.Duration
	for _, s := range samples {
		sum += s
	}
	avg := sum / time.Duration(len(samples))

	fmt.Printf(" %s • Успешных измерений: %d/%d\n", white(""), len(samples), attempts)
	fmt.Printf(" %s • Min RTT:  %v\n", white(""), min)
	fmt.Printf(" %s • Avg RTT:  %v\n", white(""), avg)
	fmt.Printf(" %s • Max RTT:  %v\n", white(""), max)

	spread := max - min
	if spread > 100*time.Millisecond {
		logger.Warn("Большой разброс RTT (%v) — может указывать на нестабильный/туннелированный маршрут", spread)
	} else {
		logger.Success("Разброс RTT в пределах нормы (%v)", spread)
	}
	logger.Info("Сравните Avg RTT с ожидаемой задержкой для страны из GeoIP-проверки — аномально высокая задержка для заявленной локации является косвенным признаком туннелирования (разд. 10.1)")
}
