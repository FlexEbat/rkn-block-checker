package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"rkn-checker/internal/logger"
)

// scannerLookupCheck checks a single entered IP/domain against the built-in
// list of known scanning infrastructure ranges. Handy for quickly checking an
// IP found in your own access logs.
func scannerLookupCheck(ctx context.Context, target string) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", target)
	if err != nil || len(ips) == 0 {
		// Might already be a bare IP rather than a domain — try parsing directly.
		if ip := net.ParseIP(target); ip != nil {
			ips = []net.IP{ip}
		} else {
			logger.Error("Failed to resolve %s: %v", target, err)
			return
		}
	}

	found := false
	for _, ip := range ips {
		if rng, ok := matchScanner(ip); ok {
			logger.Warn("%s → %s MATCHES the known scanner list (range %s)", target, ip, rng)
			found = true
		} else {
			fmt.Printf(" %s • %s → %s — not found in the scanner list\n", white(""), target, ip)
		}
	}
	if !found {
		logger.Success("No matches against the known scanner list")
	}
}

// remoteIPPortRegex pulls an IP:port (IPv4) pair out of ss/netstat-style
// output regardless of locale or exact column formatting.
var remoteIPPortRegex = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b`)

// listEstablishedConnections returns the raw output of the platform's
// established-TCP-connections utility.
func listEstablishedConnections(ctx context.Context) (string, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "netstat", "-an")
	case "darwin":
		cmd = exec.CommandContext(ctx, "netstat", "-an", "-p", "tcp")
	default: // linux
		cmd = exec.CommandContext(ctx, "ss", "-tn", "state", "established")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// localMachineIPs collects every IP address assigned to this machine's local
// interfaces, so the "local" side of a connection can be told apart from the
// "remote" side when parsing ss/netstat output (both addresses look the same
// there).
func localMachineIPs() map[string]bool {
	result := map[string]bool{"127.0.0.1": true, "0.0.0.0": true}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return result
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		result[ipNet.IP.String()] = true
	}
	return result
}

// remoteIPsFromConnections extracts the unique set of remote (non-local) IPs
// present in the given ss/netstat-style output.
func remoteIPsFromConnections(out string, localIPs map[string]bool) []string {
	seen := map[string]bool{}
	var result []string

	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		pairs := remoteIPPortRegex.FindAllStringSubmatch(sc.Text(), -1)
		for _, p := range pairs {
			ipStr := p[1]
			if localIPs[ipStr] || seen[ipStr] {
				continue
			}
			seen[ipStr] = true
			result = append(result, ipStr)
		}
	}
	return result
}

// connectionMonitorMenu is the entry point for menu item 20. It lets the
// operator choose between a one-off snapshot of current connections and a
// continuous monitor that polls periodically for a chosen duration (or
// indefinitely, until Ctrl+C).
func connectionMonitorMenu(ctx context.Context, _ string) {
	fmt.Printf("\n %sMode:\n", white(""))
	fmt.Printf("  1) Single snapshot (check current connections once)\n")
	fmt.Printf("  2) Continuous monitoring (poll repeatedly for a chosen duration)\n")
	fmt.Printf(" %s>> ", cyan(""))
	choice := readInput()

	switch choice {
	case "2":
		fmt.Printf("\n Monitoring duration — examples: 30s, 5m, 1h, 1d, 2h30m\n")
		fmt.Printf(" Enter 0 or inf for unlimited (stop anytime with Ctrl+C)\n")
		fmt.Printf(" %s>> ", cyan(""))
		durStr := readInput()

		duration, unlimited, err := parseFlexDuration(durStr)
		if err != nil {
			logger.Error("Invalid duration %q: %v", durStr, err)
			return
		}

		var monitorCtx context.Context
		var cancel context.CancelFunc
		if unlimited {
			monitorCtx, cancel = context.WithCancel(ctx)
		} else {
			monitorCtx, cancel = context.WithTimeout(ctx, duration)
		}
		defer cancel()

		runConnectionMonitor(monitorCtx, duration, unlimited)
	default:
		connectionSnapshot(ctx)
	}
}

// parseFlexDuration parses a duration string with a few conveniences on top
// of time.ParseDuration: a bare "0"/"inf"/"unlimited"/"infinite" means run
// forever (until Ctrl+C or an external timeout), and a numeric value with a
// trailing "d" is treated as whole days (time.ParseDuration itself has no
// day unit).
func parseFlexDuration(input string) (d time.Duration, unlimited bool, err error) {
	s := strings.ToLower(strings.TrimSpace(input))
	switch s {
	case "", "0", "inf", "unlimited", "infinite", "forever":
		return 0, true, nil
	}

	if strings.HasSuffix(s, "d") {
		numPart := strings.TrimSuffix(s, "d")
		days, perr := strconv.ParseFloat(numPart, 64)
		if perr != nil {
			return 0, false, fmt.Errorf("could not parse %q as a number of days: %w", numPart, perr)
		}
		return time.Duration(days * float64(24*time.Hour)), false, nil
	}

	d, err = time.ParseDuration(s)
	if err != nil {
		return 0, false, err
	}
	return d, false, nil
}

// connectionSnapshot looks at the CURRENTLY established TCP connections to
// this machine (via ss/netstat) and checks the remote addresses against the
// known scanner list. Meant to be run on the VPN server itself, to see
// whether it is being probed from a known range right now.
//
// Limitation: this only shows connections established AT THE MOMENT the
// check runs — it's a one-off snapshot, not continuous monitoring. For that,
// use the "Continuous monitoring" mode instead.
func connectionSnapshot(ctx context.Context) {
	logger.Info("Checking active incoming connections against the scanner list (%s)...", runtime.GOOS)

	out, err := listEstablishedConnections(ctx)
	if err != nil {
		logger.Error("Failed to list connections: %v", err)
		return
	}

	localIPs := localMachineIPs()
	remoteIPs := remoteIPsFromConnections(out, localIPs)

	matches := 0
	for _, ipStr := range remoteIPs {
		ip := net.ParseIP(ipStr)
		if rng, ok := matchScanner(ip); ok {
			logger.Warn("Connection from %s — MATCH against the known scanner list (range %s)", ipStr, rng)
			matches++
		}
	}

	fmt.Printf(" %s • Unique remote addresses in this snapshot: %d\n", white(""), len(remoteIPs))
	if matches > 0 {
		logger.Warn("Matches against the scanner list: %d", matches)
	} else {
		logger.Success("No matches against the known scanner list")
	}
}

// runConnectionMonitor polls the list of established connections at a fixed
// interval, reporting only NEW matches against the known scanner list (so a
// long-lived matching connection isn't reported over and over). It stops
// when the context is done (timeout reached) or the operator presses Ctrl+C.
func runConnectionMonitor(ctx context.Context, duration time.Duration, unlimited bool) {
	const pollInterval = 5 * time.Second

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	if unlimited {
		logger.Info("Monitoring started, polling every %v, no time limit. Press Ctrl+C to stop.", pollInterval)
	} else {
		logger.Info("Monitoring started, polling every %v, for %v. Press Ctrl+C to stop early.", pollInterval, duration)
	}

	seen := map[string]bool{}
	startedAt := time.Now()
	totalMatches := 0
	cycles := 0

	for {
		select {
		case <-ctx.Done():
			if !unlimited {
				logger.Info("Configured monitoring duration elapsed")
			}
			printMonitorSummary(startedAt, cycles, totalMatches)
			return
		case <-sigCh:
			fmt.Println()
			logger.Info("Interrupt received, stopping monitor...")
			printMonitorSummary(startedAt, cycles, totalMatches)
			return
		case <-ticker.C:
			cycles++
			totalMatches += pollOnceForNewMatches(ctx, seen)
		}
	}
}

// pollOnceForNewMatches runs a single polling cycle: lists current
// connections, and for every remote IP not seen before in this monitoring
// session, checks it against the scanner list. Already-seen IPs are skipped
// so a persistent connection is only reported once. Returns how many new
// matches were found this cycle.
func pollOnceForNewMatches(ctx context.Context, seen map[string]bool) int {
	out, err := listEstablishedConnections(ctx)
	if err != nil {
		logger.Error("Failed to list connections: %v", err)
		return 0
	}

	localIPs := localMachineIPs()
	newMatches := 0

	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		pairs := remoteIPPortRegex.FindAllStringSubmatch(sc.Text(), -1)
		for _, p := range pairs {
			ipStr := p[1]
			if localIPs[ipStr] || seen[ipStr] {
				continue
			}
			seen[ipStr] = true

			ip := net.ParseIP(ipStr)
			if rng, ok := matchScanner(ip); ok {
				logger.Warn("[%s] Connection from %s — MATCH against the known scanner list (range %s)", time.Now().Format("15:04:05"), ipStr, rng)
				newMatches++
			}
		}
	}
	return newMatches
}

func printMonitorSummary(startedAt time.Time, cycles, totalMatches int) {
	elapsed := time.Since(startedAt).Round(time.Second)
	fmt.Printf(" %s • Monitoring duration: %v\n", white(""), elapsed)
	fmt.Printf(" %s • Polling cycles:      %d\n", white(""), cycles)
	if totalMatches > 0 {
		logger.Warn("Total new matches during this session: %d", totalMatches)
	} else {
		logger.Success("No matches against the known scanner list during this session")
	}
}
