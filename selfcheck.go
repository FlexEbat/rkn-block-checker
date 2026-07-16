package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"rkn-checker/internal/logger"
)

// vpnIfacePattern — characteristic tunnel interface names (tun/tap/wg/utun/ppp)
// plus common Windows VPN adapter names (wintun, openvpn, wireguard,
// tap-windows) that detection methodologies flag as VPN indicators.
var vpnIfacePattern = regexp.MustCompile(`(?i)^(tun|tap|wg|utun|ppp|wintun|ipsec|ovpn|nordlynx|wireguard)`)

// privateOrLoopback roughly checks whether an IP looks like a private/loopback
// address — local DNS server addresses are flagged as an anomaly by
// detection methodologies.
func privateOrLoopback(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// localInterfaceCheck self-checks this device's local network interfaces,
// cross-platform via net.Interfaces(). Shows what a VPN-signature scan would
// see: active (UP) interfaces named tun/tap/wg/ppp with an unusually low MTU
// (tunnels are typically 1350/1400 vs ~1500 for plain Ethernet).
func localInterfaceCheck(ctx context.Context, _ string) {
	logger.Info("Self-checking local network interfaces (%s)...", runtime.GOOS)

	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Error("Failed to list interfaces: %v", err)
		return
	}

	found := false
	for _, iface := range ifaces {
		isUp := iface.Flags&net.FlagUp != 0
		looksLikeVPN := vpnIfacePattern.MatchString(iface.Name)

		addrs, _ := iface.Addrs()
		var ips []string
		for _, a := range addrs {
			ips = append(ips, a.String())
		}

		if !looksLikeVPN && !(isUp && len(ips) > 0 && iface.Name != "lo" && iface.Name != "lo0") {
			continue // only show potentially interesting interfaces, not all the noise
		}

		status := "DOWN"
		if isUp {
			status = "UP"
		}

		if looksLikeVPN && isUp {
			found = true
			logger.Warn("%-12s status=%-4s MTU=%-5d addrs=%v — name looks like a tunnel interface (VPN/WireGuard)", iface.Name, status, iface.MTU, ips)
			if iface.MTU > 0 && iface.MTU < 1450 {
				logger.Warn("  → MTU=%d is below standard Ethernet (~1500) — typical for a VPN tunnel", iface.MTU)
			}
		} else if looksLikeVPN {
			logger.Info("%-12s status=%-4s (inactive) — name looks like a VPN interface, but it's down", iface.Name, status)
		}
	}

	if !found {
		logger.Success("No active interfaces with VPN/tunnel-like names (tun/tap/wg/ppp) were found")
	}
}

// localRouteCheck prints this device's routing table via the standard system
// utility and flags multiple default routes as an additional signal.
func localRouteCheck(ctx context.Context, _ string) {
	logger.Info("Self-checking the routing table (%s)...", runtime.GOOS)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "route", "print", "-4")
	case "darwin":
		cmd = exec.CommandContext(ctx, "netstat", "-rn", "-f", "inet")
	default: // linux and other unix
		cmd = exec.CommandContext(ctx, "ip", "route")
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to get the routing table: %v", err)
		return
	}

	text := string(out)
	fmt.Print(text)

	defaultCount := 0
	for _, line := range strings.Split(text, "\n") {
		low := strings.ToLower(line)
		if strings.Contains(low, "default") || strings.HasPrefix(strings.TrimSpace(low), "0.0.0.0") {
			defaultCount++
		}
	}

	if defaultCount > 1 {
		logger.Warn("Found %d default routes — multiple default routes can indicate an active VPN tunnel", defaultCount)
	} else {
		logger.Success("Found %d default route(s) — no anomalies detected", defaultCount)
	}
}

// localDNSCheck checks this device's DNS configuration for local/loopback DNS
// servers, or resolving being redirected through a virtual interface.
func localDNSCheck(ctx context.Context, _ string) {
	logger.Info("Self-checking DNS configuration (%s)...", runtime.GOOS)

	var nameservers []string

	if runtime.GOOS == "windows" {
		cmd := exec.CommandContext(ctx, "ipconfig", "/all")
		out, err := cmd.CombinedOutput()
		if err != nil {
			logger.Error("Failed to run ipconfig: %v", err)
			return
		}
		nameservers = extractIPv4(string(out))
	} else {
		data, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			logger.Error("Failed to read /etc/resolv.conf: %v", err)
			return
		}
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "nameserver") {
				fields := strings.Fields(line)
				if len(fields) == 2 {
					nameservers = append(nameservers, fields[1])
				}
			}
		}
	}

	if len(nameservers) == 0 {
		logger.Warn("No DNS servers found/recognized")
		return
	}

	anomaly := false
	for _, ns := range nameservers {
		ip := net.ParseIP(ns)
		if ip == nil {
			continue
		}
		if privateOrLoopback(ip) {
			logger.Warn("DNS server %s — private/loopback address (possible sign of resolving being redirected into a VPN interface)", ns)
			anomaly = true
		} else {
			fmt.Printf(" %s • DNS server: %s\n", white(""), ns)
		}
	}

	if !anomaly {
		logger.Success("DNS servers look like normal public/ISP addresses")
	}
}

// extractIPv4 pulls all IPv4 addresses out of arbitrary text — used for
// rough parsing of Windows `ipconfig /all` output, whose exact format
// depends heavily on OS localization and doesn't lend itself to reliable
// line-by-line keyword parsing.
func extractIPv4(text string) []string {
	re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	return re.FindAllString(text, -1)
}
