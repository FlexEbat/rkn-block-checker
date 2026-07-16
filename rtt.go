package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"

	"rkn-checker/internal/logger"
)

// rttCheck is a simplified latency-timing analysis: it measures TCP connect
// RTT to the target and shows the spread.
//
// IMPORTANT: a full timing-based analysis compares measured RTT against the
// expected latency for a claimed GeoIP location using a network of reference
// "landmarks" — this tool has no such database, so it only reports raw
// measurements here. Anomalies/spread need to be cross-checked manually
// against the GeoIP check result ("GeoIP / ASN / Hosting").
func rttCheck(ctx context.Context, target string) {
	logger.Info("Measuring RTT to %s:443 (5 attempts)...", target)

	const attempts = 5
	var samples []time.Duration

	for i := 0; i < attempts; i++ {
		start := time.Now()
		dialer := &net.Dialer{Timeout: cfg.DialTimeout()}
		conn, err := dialer.DialContext(ctx, "tcp", target+":443")
		if err != nil {
			logger.Warn("Attempt %d/%d: %v", i+1, attempts, err)
			continue
		}
		samples = append(samples, time.Since(start))
		conn.Close()
	}

	if len(samples) == 0 {
		logger.Error("No successful measurements were obtained")
		return
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	min, max := samples[0], samples[len(samples)-1]
	var sum time.Duration
	for _, s := range samples {
		sum += s
	}
	avg := sum / time.Duration(len(samples))

	fmt.Printf(" %s • Successful measurements: %d/%d\n", white(""), len(samples), attempts)
	fmt.Printf(" %s • Min RTT:  %v\n", white(""), min)
	fmt.Printf(" %s • Avg RTT:  %v\n", white(""), avg)
	fmt.Printf(" %s • Max RTT:  %v\n", white(""), max)

	spread := max - min
	if spread > 100*time.Millisecond {
		logger.Warn("Large RTT spread (%v) — may indicate an unstable/tunneled path", spread)
	} else {
		logger.Success("RTT spread is within normal range (%v)", spread)
	}
	logger.Info("Compare the Avg RTT against the expected latency for the country from the GeoIP check — abnormally high latency for the claimed location is an indirect sign of tunneling")
}
