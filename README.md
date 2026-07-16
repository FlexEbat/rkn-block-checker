# RKN Block Checker

A command-line utility written in Go for network diagnostics and website reachability analysis. Its main purpose is identifying why a server is being restricted, testing network paths, and detecting blocking patterns applied by deep packet inspection (DPI) systems, including Russia's technical countermeasures against threats (TSPU).

The tool also includes a self-check mode: it shows which VPN/Proxy detection signals are visible on **your own** server and **your own** device — the same signals such detection is normally based on — so you can evaluate and fix them.

## Architecture and check methods

The program runs interactively and is split into four logical sections. Checks that work against a remote target accept an IP address or domain name. Input is parsed via `net/url`, so protocol prefixes in any case (`http://`, `HTTPS://`), paths after the host, a port in the address, and bracketed IPv6 are all handled correctly. Checks that work against the local device don't prompt for a target.

Every check runs with an overall 30-second timeout (via `context.Context`) — a hung `traceroute`, `ping`, or network call no longer blocks the program indefinitely. The connection monitor (menu item 20) is the one exception: it manages its own duration and Ctrl+C handling, since it's meant to run far longer than 30 seconds.

### 1. Basic connectivity checks

Standard reachability and security diagnostics for the target host.

*   **Security Audit**: Sends a test HTTP request to the host. Checks the response headers for security mechanisms — Strict-Transport-Security (HSTS) and Content-Security-Policy (CSP) — and for signs of an intermediate proxy: `X-Forwarded-For`, `Forwarded`, `Via`.
*   **SSL Deep Checker**: Opens a TLS connection (port 443) with certificate verification forcibly disabled for debugging purposes. Extracts and prints:
    *   Common Name (subject).
    *   Issuer organization and Common Name (certificate authority).
    *   Negotiated protocol version (TLS 1.0 through TLS 1.3).
    *   Cipher suite in use.
    *   Validity start/end dates with a computed current status.
*   **Port Scanner**: Asynchronously opens TCP connections to the port list from the config (default: 21 (FTP), 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL), 3389 (RDP)). Per-connection timeout is set in `config.json` (500ms by default).
*   **Tracert Test**: Runs the system's route-tracing utility (`tracert` on Windows, `traceroute` on UNIX) and streams its output to stdout.
*   **Ping (8KB / 16KB)**: Sends four ICMP echo requests with an unusually large packet size (8192 or 16384 bytes), using `-l` on Windows and `-s` on UNIX. Helps surface MTU fragmentation issues and dropped large packets at the network/transport layer.

### 2. External analysis services (OSINT)

Builds search queries from the given host and opens them in the system's default browser via `github.com/pkg/browser`.

*   **BGP.he.net**: DNS record, IP, and routing analysis.
*   **Censys.io**: IP history, open ports, and associated SSL certificates.
*   **BGP.tools**: Autonomous system (ASN) and peering data.

### 3. Blocking method analysis (RKN)

A specialized section for detecting characteristic signs of traffic-filtering interference in the connection.

*   **TCP RST Check**: Opens a TCP connection to ports 80 and 443. Catches socket errors and inspects their text — if it contains `connection reset` or `reset by peer`, a forced connection drop is flagged, a standard SNI/IP blocking method used by TSPU.
*   **QUIC Check**: Checks UDP reachability using HTTP/3 (QUIC) on port 443, sending ALPN tokens `h3`, `h2`, and `http/1.1`. Lets you check whether QUIC is fully blocked, which providers often do to force traffic onto TCP for SNI-based inspection.
*   **Block Transfer (8KB / 16KB)**: Detects blocking based on transferred data volume. Opens a TLS connection on port 443, builds an HTTP GET request with a custom `X-Data` header padded with "A" characters so the total sent size is exactly 8 or 16 kilobytes (sizes are configurable). Waits 3 seconds for a response. Reveals whether a DPI system drops the session after a certain byte threshold.

### 4. VPN/Proxy signal self-check

Shows the same signals commonly used to detect VPN/Proxy usage — but applied to **your own** infrastructure and device, not to someone else's users.

*   **GeoIP/ASN/Hosting**: Queries a public GeoIP service (`ip-api.com`, free tier) for the given IP/domain and shows country, ASN, organization, and two key reputation flags — `hosting` (data-center range) and `proxy` (listed in public VPN/Proxy/TOR node databases).
*   **RTT / latency**: Measures 5 TCP connections to the target's port 443, showing min/avg/max and spread. A simplified method — there's no "reference landmark" database, so anomalies need to be cross-checked manually against the GeoIP result.
*   **Interfaces (this device)**: Lists this machine's network interfaces (cross-platform, via `net.Interfaces()`), highlighting active interfaces named `tun`/`tap`/`wg`/`utun`/`ppp`/`wintun` with an unusually low MTU (a typical VPN tunnel signature).
*   **Routes (this device)**: Prints the routing table (`ip route` / `netstat -rn` / `route print`, depending on OS) and warns if multiple default routes are found.
*   **DNS (this device)**: Checks the device's DNS servers (`/etc/resolv.conf` or `ipconfig /all`) for private/loopback addresses — a possible sign of resolving being redirected through a virtual interface.
*   **Check IP against scanner list**: Checks a given IP/domain against a built-in list of known scanning-infrastructure ranges (see `scanlist.go`).
*   **Connections vs scanner list (server)**: Lets you choose between a one-off snapshot of current established TCP connections and continuous monitoring (see below) that polls repeatedly and checks remote addresses against the same list.

Items 16–18 and 20 look at the local machine and don't prompt for a target.

The scanner list (`scanlist.go`) is maintained by hand and can go stale — use it alongside other defenses (firewall, fail2ban, etc.), not as your only barrier.

## Live connection monitoring (menu item 20)

Selecting item 20 first asks how you want to run the check:

```
Mode:
  1) Single snapshot (check current connections once)
  2) Continuous monitoring (poll repeatedly for a chosen duration)
```

**Single snapshot** behaves like before: one look at currently established connections, checked against the scanner list.

**Continuous monitoring** then asks for a duration:

```
Monitoring duration — examples: 30s, 5m, 1h, 1d, 2h30m
Enter 0 or inf for unlimited (stop anytime with Ctrl+C)
```

Accepted formats:

| Input | Meaning |
|---|---|
| `30s`, `5m`, `1h`, `2h30m` | Any value `time.ParseDuration` understands (s/m/h, combinable) |
| `1d`, `2d` | Whole days (a unit Go's standard duration parser doesn't support natively) |
| `0`, `inf`, `unlimited`, `infinite`, `forever`, empty input | Run indefinitely until you press Ctrl+C |

Once running, the monitor polls established connections every 5 seconds and prints a timestamped warning only the **first** time a given remote IP matches the scanner list during that session — a long-lived matching connection won't spam the same warning every cycle. It stops when:

* the configured duration elapses, or
* you press Ctrl+C, or
* it's running unlimited and you interrupt it.

On exit it prints a short summary: how long it ran, how many polling cycles completed, and the total number of new matches found.

## Menu

| # | Check | Section | Needs a target |
|---|---|---|---|
| 1 | Security Audit | Basic connectivity checks | yes |
| 2 | SSL Deep Checker | Basic connectivity checks | yes |
| 3 | Port Scanner | Basic connectivity checks | yes |
| 4 | Tracert Test | Basic connectivity checks | yes |
| 5 | Ping (8KB) | Basic connectivity checks | yes |
| 6 | Ping (16KB) | Basic connectivity checks | yes |
| 7 | BGP.he.net | External analysis services | yes |
| 8 | Censys.io | External analysis services | yes |
| 9 | BGP.tools | External analysis services | yes |
| 10 | TCP RST Check | Blocking method analysis (RKN) | yes |
| 11 | QUIC Check | Blocking method analysis (RKN) | yes |
| 12 | Block (8KB) | Blocking method analysis (RKN) | yes |
| 13 | Block (16KB) | Blocking method analysis (RKN) | yes |
| 14 | GeoIP/ASN/Hosting | VPN/Proxy signal self-check | yes |
| 15 | RTT / latency | VPN/Proxy signal self-check | yes |
| 16 | Interfaces (this device) | VPN/Proxy signal self-check | no |
| 17 | Routes (this device) | VPN/Proxy signal self-check | no |
| 18 | DNS (this device) | VPN/Proxy signal self-check | no |
| 19 | Check IP against scanner list | VPN/Proxy signal self-check | yes |
| 20 | Connections vs scanner list (server) | VPN/Proxy signal self-check | no |
| 0 | Quit | — | — |

## Project structure

```
rkn-checker/
├── main.go                    # entry point, menu, check dispatcher
├── tlsconfig.go                # single TLS config for blocking-analysis purposes
├── geoip.go                    # GeoIP/ASN/Hosting/Proxy reputation (ip-api.com)
├── rtt.go                       # simplified RTT/latency analysis
├── selfcheck.go                 # this device's local interfaces/routes/DNS
├── scanlist.go                  # built-in list of known scanning-infrastructure ranges
├── scancheck.go                 # IP/active-connection checks against the scanner list + live monitor
├── internal/
│   ├── logger/                 # colored output: Info / Success / Warn / Error
│   │   └── logger.go
│   └── config/                 # loads settings from config.json + defaults
│       └── config.go
├── config.example.json         # example config file
├── go.mod
└── README.md
```

## Configuration

Scan ports and timeouts are pulled out of the code into `config.json`, which the program looks for in the working directory at startup. The file is optional — if absent, built-in defaults are used; if present, only the fields it sets are overridden.

Copy the example and edit as needed:

```bash
cp config.example.json config.json
```

```json
{
  "ports": [21, 22, 80, 443, 3306, 3389],
  "dial_timeout_ms": 2000,
  "tls_timeout_ms": 10000,
  "quic_timeout_ms": 5000,
  "scan_timeout_ms": 500,
  "block_small_kb": 8,
  "block_large_kb": 16
}
```

| Field              | Purpose                                              |
|--------------------|--------------------------------------------------------|
| `ports`            | Port list for Port Scanner                             |
| `dial_timeout_ms`  | TCP connect timeout (TCP RST Check, RTT check)          |
| `tls_timeout_ms`   | TLS connect timeout (SSL Checker, Security Audit, Block Transfer, GeoIP) |
| `quic_timeout_ms`  | QUIC connect timeout                                    |
| `scan_timeout_ms`  | Per-connection timeout during port scanning             |
| `block_small_kb`   | Block size for the "Block (small)" test                 |
| `block_large_kb`   | Block size for the "Block (large)" test                 |

If `config.json` is malformed (invalid JSON), the program prints an error at startup and continues with default values.

## System requirements

*   Runtime: Go 1.21 or newer.
*   OS: Windows, Linux, or macOS.
*   Privileges: `Tracert Test` and `Ping` may require superuser (root) privileges or the `CAP_NET_RAW` capability on some operating systems (especially Linux) to create ICMP sockets.
*   Network: "GeoIP/ASN/Hosting" and the OSINT section need outbound access to `ip-api.com`, `bgp.he.net`, `censys.io`, and `bgp.tools` respectively.

## Installation and usage

1. Clone the repository:
```bash
git clone https://github.com/FlexEbat/rkn-block-checker.git
cd rkn-block-checker
```

2. Fetch dependencies (fatih/color, pkg/browser, quic-go):
```bash
go mod tidy
```
If go.mod is missing from your copy, initialize it and install packages manually:
```bash
go mod init rkn-checker
go get github.com/fatih/color
go get github.com/pkg/browser
go get github.com/quic-go/quic-go
```

3. (Optional) create `config.json` from the example to override ports and timeouts:
```bash
cp config.example.json config.json
```

4. Run the tool:
```bash
go run .
```

To build a binary, use `go build -o rkn_checker .`.

## License

Distributed under the MIT License. This program is provided solely for network diagnostics, testing, and learning about how network protocols work. No endorsement is given for using this tool for destructive purposes.
