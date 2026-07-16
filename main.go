package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/pkg/browser"
	"github.com/quic-go/quic-go"

	"rkn-checker/internal/config"
	"rkn-checker/internal/logger"
)

var (
	cyan    = color.New(color.FgCyan).SprintFunc()
	white   = color.New(color.FgWhite).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	reset   = color.New(color.Reset).SprintFunc()
	scanner = bufio.NewScanner(os.Stdin)
	cfg     config.Config
)

func readInput() string {
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}

func clear() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func drawHeader() {
	clear()
	fmt.Printf("%s\n", cyan("╔══════════════════════════════════════════════════════════════════╗"))
	fmt.Printf("%s %s %s\n", cyan("║"), white("   RKN BLOCK CHECKER - HOSTING BLOCK ANALYSIS   "), cyan("   ║"))
	fmt.Printf("%s\n", cyan("╚══════════════════════════════════════════════════════════════════╝"))
}

func drawBox(title string, options []string) {
	fmt.Printf("\n %s\n", yellow(title))
	fmt.Printf(" %s┌──────────────────────────────┬───────────────────────────────┐\n", white(""))
	for i := 0; i < len(options); i += 2 {
		left := options[i]
		right := ""
		if i+1 < len(options) {
			right = options[i+1]
		}
		fmt.Printf(" %s│ %-28s │ %-29s %s│\n", white(""), left, right, white(""))
	}
	fmt.Printf(" %s└──────────────────────────────┴───────────────────────────────┘\n", white(""))
}

// parseTarget normalizes user input into a clean hostname/IP.
//
// This used to be done with plain string Replace("http://", "") calls, which
// broke on HTTPS:// (case), stray whitespace, a URL with a port or path, and
// bracketed IPv6. net/url.Parse handles all of that out of the box, but it
// needs a scheme to correctly split host:port — so if the user typed a bare
// domain/IP with no scheme, we add one on the fly before parsing.
func parseTarget(input string) string {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return ""
	}

	candidate := raw
	if !strings.Contains(candidate, "://") {
		candidate = "//" + candidate // url.Parse treats //host as scheme-relative
	}

	if u, err := url.Parse(candidate); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}

	// Fallback for exotic input net/url couldn't parse (e.g. a bare IPv6
	// address without brackets and without a path).
	return strings.Trim(raw, "[]/ ")
}

func getTarget() string {
	fmt.Printf("\n %s >> %sEnter an IP or domain to analyze\n", cyan(""), white(""))
	fmt.Printf(" %s >> ", cyan(""))
	return parseTarget(readInput())
}

func sslChecker(ctx context.Context, target string) {
	logger.Info("Deep SSL analysis for %s...", target)

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: cfg.TLSTimeout()},
		Config:    insecureTLSConfig(),
	}
	rawConn, err := dialer.DialContext(ctx, "tcp", target+":443")
	if err != nil {
		logger.Error("SSL error: %v", err)
		return
	}
	defer rawConn.Close()
	conn := rawConn.(*tls.Conn)

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		logger.Error("Certificate chain is empty")
		return
	}
	cert := certs[0]
	logger.Success("CERTIFICATE DETAILS:")
	fmt.Printf(" %s • Subject:      %s\n", white(""), cert.Subject.CommonName)
	fmt.Printf(" %s • Issued by:    %s (%s)\n", white(""), cert.Issuer.Organization, cert.Issuer.CommonName)
	fmt.Printf(" %s • Protocol:     %s\n", white(""), tlsProtocolName(conn.ConnectionState().Version))
	fmt.Printf(" %s • Cipher:       %s\n", white(""), tls.CipherSuiteName(conn.ConnectionState().CipherSuite))
	fmt.Printf(" %s • Issued on:    %s\n", cyan(""), cert.NotBefore.Format("2006-01-02"))
	fmt.Printf(" %s • Valid until:  %s\n", cyan(""), cert.NotAfter.Format("2006-01-02"))

	now := time.Now()
	if now.Before(cert.NotAfter) && now.After(cert.NotBefore) {
		logger.Success("Status: ACTIVE")
	} else {
		logger.Error("Status: EXPIRED/INACTIVE")
	}
}

func tlsProtocolName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

func checkTCPRst(ctx context.Context, target string, port int) {
	logger.Info("Checking TCP RST on %s:%d...", target, port)
	address := fmt.Sprintf("%s:%d", target, port)

	dialer := &net.Dialer{Timeout: cfg.DialTimeout()}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		if strings.Contains(err.Error(), "connection reset") || strings.Contains(err.Error(), "reset by peer") {
			logger.Error("%s:%d - RST received (Connection Reset)", target, port)
		} else {
			logger.Error("%s:%d - Error: %v", target, port, err)
		}
		return
	}
	defer conn.Close()
	logger.Success("%s:%d - Connection established", target, port)
}

func checkQUIC(ctx context.Context, target string, port int) {
	logger.Info("Checking QUIC on %s:%d...", target, port)
	address := fmt.Sprintf("%s:%d", target, port)

	tlsConf := insecureTLSConfig("h3", "h2", "http/1.1")

	ctx, cancel := context.WithTimeout(ctx, cfg.QUICTimeout())
	defer cancel()

	conn, err := quic.DialAddr(ctx, address, tlsConf, nil)
	if err != nil {
		logger.Error("%s:%d - QUIC unavailable: %v", target, port, err)
		return
	}
	defer conn.CloseWithError(0, "")
	logger.Success("%s:%d - QUIC available", target, port)
}

func checkBlockTransfer(ctx context.Context, target string, port int, sizeKB int) {
	logger.Info("Testing %dKB block transfer to %s:%d...", sizeKB, target, port)
	address := fmt.Sprintf("%s:%d", target, port)
	data := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Sentinel\r\n", target))
	padding := strings.Repeat("A", sizeKB*1024-len(data)-4)
	data = append(data, []byte("X-Data: "+padding+"\r\n\r\n")...)

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: cfg.TLSTimeout()},
		Config:    insecureTLSConfig(),
	}
	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		logger.Error("%s:%d - TLS error while sending %dKB block: %v", target, port, sizeKB, err)
		return
	}
	defer rawConn.Close()
	conn := rawConn.(*tls.Conn)

	if _, err = conn.Write(data); err != nil {
		logger.Error("Send error: %v", err)
		return
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	if _, err = conn.Read(buf); err != nil {
		logger.Warn("%s:%d - %dKB block sent, but no response received (Timeout/Err: %v)", target, port, sizeKB, err)
	} else {
		logger.Success("%s:%d - %dKB block accepted by the server, response received", target, port, sizeKB)
	}
}

func securityAudit(ctx context.Context, target string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+target, nil)
	if err != nil {
		logger.Error("Failed to build request: %v", err)
		return
	}
	client := &http.Client{Timeout: cfg.TLSTimeout()}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Site unreachable: %v", err)
		return
	}
	defer resp.Body.Close()

	hsts := "MISSING"
	if _, ok := resp.Header["Strict-Transport-Security"]; ok {
		hsts = "OK"
	}
	csp := "MISSING"
	if _, ok := resp.Header["Content-Security-Policy"]; ok {
		csp = "OK"
	}
	fmt.Printf("HSTS: %s\n", hsts)
	fmt.Printf("CSP:  %s\n", csp)

	// A methodology section on proxy detection notes that X-Forwarded-For /
	// Forwarded / Via in the response can indicate an intermediate proxy on
	// the path. Relevant for self-checking behind your own reverse
	// proxy/CDN — a legitimate CDN can add these headers too, so this is not
	// a hard signal on its own.
	proxyHeaders := []string{"X-Forwarded-For", "Forwarded", "Via"}
	anyFound := false
	for _, h := range proxyHeaders {
		if v := resp.Header.Get(h); v != "" {
			logger.Warn("Header %s is present: %s (possible sign of an intermediate proxy; a legitimate CDN can add it too)", h, v)
			anyFound = true
		}
	}
	if !anyFound {
		logger.Success("No proxy headers found (X-Forwarded-For/Forwarded/Via)")
	}
}

func portScanner(ctx context.Context, target string) {
	logger.Info("Asynchronous port scan for %s...", target)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, p := range cfg.Ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			dialer := &net.Dialer{Timeout: cfg.ScanTimeout()}
			address := fmt.Sprintf("%s:%d", target, port)
			conn, err := dialer.DialContext(ctx, "tcp", address)
			if err == nil {
				conn.Close()
				mu.Lock()
				logger.Success("Port %d: OPEN", port)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
}

func tracertTest(ctx context.Context, target string) {
	cmdName := "traceroute"
	if runtime.GOOS == "windows" {
		cmdName = "tracert"
	}
	cmd := exec.CommandContext(ctx, cmdName, target)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		logger.Error("%s exited with an error: %v", cmdName, err)
	}
}

func pingTest(ctx context.Context, target string, sizeBytes string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-l", sizeBytes, "-n", "4", target)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-s", sizeBytes, "-c", "4", target)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		logger.Error("ping exited with an error: %v", err)
	}
}

func openExternal(target, tmpl string) {
	if err := browser.OpenURL(tmpl + target); err != nil {
		logger.Error("Failed to open browser: %v", err)
	}
}

// menuItem describes a single menu entry: its on-screen label and what it
// does when selected. The dispatcher used to be one big switch over strings
// like "10", "11" — now a single list of items both draws the menu and wires
// up the handler, so a "menu shows one thing, switch does another" mismatch
// is structurally impossible.
type menuItem struct {
	key         string
	label       string
	section     string
	needsTarget bool // false for checks that look at this device rather than a target
	longRunning bool // true if the handler manages its own context/duration (skips the default 30s timeout)
	handler     func(ctx context.Context, target string)
}

func buildMenu() []menuItem {
	basic := "BASIC CONNECTIVITY CHECKS"
	osint := "EXTERNAL ANALYSIS SERVICES"
	block := "BLOCKING METHOD ANALYSIS (RKN)"
	// The "SELF-CHECK" section runs a VPN/Proxy detection methodology in
	// reverse: not to find other people's users, but so the operator of
	// their own VPN service can see the same signals on THEIR OWN server
	// and THEIR OWN device that the detecting side would see — and fix them.
	selfcheck := "VPN/PROXY SIGNAL SELF-CHECK"

	return []menuItem{
		{key: "1", label: "Security Audit", section: basic, needsTarget: true, handler: securityAudit},
		{key: "2", label: "SSL Deep Checker", section: basic, needsTarget: true, handler: sslChecker},
		{key: "3", label: "Port Scanner", section: basic, needsTarget: true, handler: portScanner},
		{key: "4", label: "Tracert Test", section: basic, needsTarget: true, handler: tracertTest},
		{key: "5", label: "Ping (8KB)", section: basic, needsTarget: true, handler: func(ctx context.Context, t string) { pingTest(ctx, t, "8192") }},
		{key: "6", label: "Ping (16KB)", section: basic, needsTarget: true, handler: func(ctx context.Context, t string) { pingTest(ctx, t, "16384") }},

		{key: "7", label: "BGP.he.net", section: osint, needsTarget: true, handler: func(ctx context.Context, t string) { openExternal(t, "https://bgp.he.net/dns/") }},
		{key: "8", label: "Censys.io", section: osint, needsTarget: true, handler: func(ctx context.Context, t string) { openExternal(t, "https://censys.io/ipv4?q=") }},
		{key: "9", label: "BGP.tools", section: osint, needsTarget: true, handler: func(ctx context.Context, t string) { openExternal(t, "https://bgp.tools/search?q=") }},

		{key: "10", label: "TCP RST Check", section: block, needsTarget: true, handler: func(ctx context.Context, t string) {
			checkTCPRst(ctx, t, 443)
			checkTCPRst(ctx, t, 80)
		}},
		{key: "11", label: "QUIC Check", section: block, needsTarget: true, handler: func(ctx context.Context, t string) { checkQUIC(ctx, t, 443) }},
		{key: "12", label: fmt.Sprintf("Block (%dKB)", config.Default().BlockSmallKB), section: block, needsTarget: true, handler: func(ctx context.Context, t string) {
			checkBlockTransfer(ctx, t, 443, cfg.BlockSmallKB)
		}},
		{key: "13", label: fmt.Sprintf("Block (%dKB)", config.Default().BlockLargeKB), section: block, needsTarget: true, handler: func(ctx context.Context, t string) {
			checkBlockTransfer(ctx, t, 443, cfg.BlockLargeKB)
		}},

		{key: "14", label: "GeoIP/ASN/Hosting (target)", section: selfcheck, needsTarget: true, handler: geoipCheck},
		{key: "15", label: "RTT / latency (target)", section: selfcheck, needsTarget: true, handler: rttCheck},
		{key: "16", label: "Interfaces (this device)", section: selfcheck, needsTarget: false, handler: localInterfaceCheck},
		{key: "17", label: "Routes (this device)", section: selfcheck, needsTarget: false, handler: localRouteCheck},
		{key: "18", label: "DNS (this device)", section: selfcheck, needsTarget: false, handler: localDNSCheck},
		{key: "19", label: "Check IP against scanner list", section: selfcheck, needsTarget: true, handler: scannerLookupCheck},
		{key: "20", label: "Connections vs scanner list (server)", section: selfcheck, needsTarget: false, longRunning: true, handler: connectionMonitorMenu},
	}
}

func drawMenu(items []menuItem) {
	sections := []string{}
	bySection := map[string][]string{}
	for _, it := range items {
		if _, seen := bySection[it.section]; !seen {
			sections = append(sections, it.section)
		}
		bySection[it.section] = append(bySection[it.section], fmt.Sprintf("%s. %s", it.key, it.label))
	}
	for _, s := range sections {
		drawBox(s, bySection[s])
	}
	drawBox("EXIT", []string{"0. Quit"})
}

func main() {
	loaded, err := config.Load("config.json")
	if err != nil {
		logger.Warn("Failed to read config.json (%v), using default values", err)
		loaded = config.Default()
	}
	cfg = loaded

	menu := buildMenu()
	dispatch := make(map[string]menuItem, len(menu))
	for _, it := range menu {
		dispatch[it.key] = it
	}

	for {
		drawHeader()
		drawMenu(menu)

		fmt.Printf("\n %sRKN_CHECKER_# ", cyan(""))
		choice := readInput()

		if choice == "0" {
			break
		}

		item, ok := dispatch[choice]
		if !ok {
			logger.Error("Unknown menu item: %s", choice)
			continue
		}

		target := ""
		if item.needsTarget {
			target = getTarget()
			if target == "" {
				continue
			}
		}

		fmt.Printf("\n%s\n", strings.Repeat("—", 64))

		if item.longRunning {
			// The handler manages its own context, duration, and Ctrl+C
			// handling — it may legitimately run far longer than the default
			// 30s budget given to every other check.
			item.handler(context.Background(), target)
		} else {
			// A shared timeout for every other check — traceroute/ping/browser
			// used to have no context at all and could hang indefinitely.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			item.handler(ctx, target)
			cancel()
		}

		fmt.Printf("\n%s[ Press Enter to continue ]%s", yellow(""), reset(""))
		readInput()
	}
}
