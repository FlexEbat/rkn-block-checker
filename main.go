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
	fmt.Printf("%s %s %s\n", cyan("║"), white("   RKN BLOCK CHECKER - АНАЛИЗ БЛОКИРОВОК ХОСТИНГА   "), cyan("   ║"))
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

// parseTarget нормализует ввод пользователя в чистый hostname/IP.
//
// Раньше это делалось строковыми Replace("http://", "") — что ломалось на
// HTTPS:// (регистр), пробелах, URL с портом или путём, и на IPv6 в скобках.
// net/url.Parse умеет всё это из коробки, но требует схему для корректного
// разбора host:port — поэтому если пользователь ввёл голый домен/IP без
// схемы, мы её на лету подставляем перед парсингом.
func parseTarget(input string) string {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return ""
	}

	candidate := raw
	if !strings.Contains(candidate, "://") {
		candidate = "//" + candidate // url.Parse трактует //host как scheme-relative
	}

	if u, err := url.Parse(candidate); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}

	// Фоллбэк на случай совсем экзотического ввода, который net/url не смог
	// разобрать (например, голый IPv6 без скобок и без пути).
	return strings.Trim(raw, "[]/ ")
}

func getTarget() string {
	fmt.Printf("\n %s >> %sВведите IP или Домен для анализа\n", cyan(""), white(""))
	fmt.Printf(" %s >> ", cyan(""))
	return parseTarget(readInput())
}

func sslChecker(ctx context.Context, target string) {
	logger.Info("Глубокий анализ SSL для %s...", target)

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: cfg.TLSTimeout()},
		Config:    insecureTLSConfig(),
	}
	rawConn, err := dialer.DialContext(ctx, "tcp", target+":443")
	if err != nil {
		logger.Error("Ошибка SSL: %v", err)
		return
	}
	defer rawConn.Close()
	conn := rawConn.(*tls.Conn)

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		logger.Error("Цепочка сертификатов пуста")
		return
	}
	cert := certs[0]
	logger.Success("ДЕТАЛИ СЕРТИФИКАТА:")
	fmt.Printf(" %s • Владелец:    %s\n", white(""), cert.Subject.CommonName)
	fmt.Printf(" %s • Кем выдан:   %s (%s)\n", white(""), cert.Issuer.Organization, cert.Issuer.CommonName)
	fmt.Printf(" %s • Протокол:    %s\n", white(""), tlsProtocolName(conn.ConnectionState().Version))
	fmt.Printf(" %s • Шифрование:  %s\n", white(""), tls.CipherSuiteName(conn.ConnectionState().CipherSuite))
	fmt.Printf(" %s • Выдан:       %s\n", cyan(""), cert.NotBefore.Format("2006-01-02"))
	fmt.Printf(" %s • Срок до:     %s\n", cyan(""), cert.NotAfter.Format("2006-01-02"))

	now := time.Now()
	if now.Before(cert.NotAfter) && now.After(cert.NotBefore) {
		logger.Success("Статус: АКТИВЕН")
	} else {
		logger.Error("Статус: ПРОСРОЧЕН/НЕАКТИВЕН")
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
	logger.Info("Проверка TCP RST на %s:%d...", target, port)
	address := fmt.Sprintf("%s:%d", target, port)

	dialer := &net.Dialer{Timeout: cfg.DialTimeout()}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		if strings.Contains(err.Error(), "connection reset") || strings.Contains(err.Error(), "reset by peer") {
			logger.Error("%s:%d - Получен RST (Connection Reset)", target, port)
		} else {
			logger.Error("%s:%d - Ошибка: %v", target, port, err)
		}
		return
	}
	defer conn.Close()
	logger.Success("%s:%d - Соединение установлено", target, port)
}

func checkQUIC(ctx context.Context, target string, port int) {
	logger.Info("Проверка QUIC на %s:%d...", target, port)
	address := fmt.Sprintf("%s:%d", target, port)

	tlsConf := insecureTLSConfig("h3", "h2", "http/1.1")

	ctx, cancel := context.WithTimeout(ctx, cfg.QUICTimeout())
	defer cancel()

	conn, err := quic.DialAddr(ctx, address, tlsConf, nil)
	if err != nil {
		logger.Error("%s:%d - QUIC недоступен: %v", target, port, err)
		return
	}
	defer conn.CloseWithError(0, "")
	logger.Success("%s:%d - QUIC доступен", target, port)
}

func checkBlockTransfer(ctx context.Context, target string, port int, sizeKB int) {
	logger.Info("Тестирование передачи блока %dKB на %s:%d...", sizeKB, target, port)
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
		logger.Error("%s:%d - Ошибка TLS при отправке блока %dKB: %v", target, port, sizeKB, err)
		return
	}
	defer rawConn.Close()
	conn := rawConn.(*tls.Conn)

	if _, err = conn.Write(data); err != nil {
		logger.Error("Ошибка отправки: %v", err)
		return
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	if _, err = conn.Read(buf); err != nil {
		logger.Warn("%s:%d - Блок %dKB отправлен, но ответ не получен (Timeout/Err: %v)", target, port, sizeKB, err)
	} else {
		logger.Success("%s:%d - Блок %dKB принят сервером, получен ответ", target, port, sizeKB)
	}
}

func securityAudit(ctx context.Context, target string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+target, nil)
	if err != nil {
		logger.Error("Не удалось собрать запрос: %v", err)
		return
	}
	client := &http.Client{Timeout: cfg.TLSTimeout()}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Сайт недоступен: %v", err)
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
}

func portScanner(ctx context.Context, target string) {
	logger.Info("Асинхронное сканирование портов для %s...", target)
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
		logger.Error("%s завершился с ошибкой: %v", cmdName, err)
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
		logger.Error("ping завершился с ошибкой: %v", err)
	}
}

func openExternal(target, tmpl string) {
	if err := browser.OpenURL(tmpl + target); err != nil {
		logger.Error("Не удалось открыть браузер: %v", err)
	}
}

// menuItem описывает один пункт меню: как он подписан на экране и что
// делает при выборе. Раньше диспетчер был большим switch по строкам "10",
// "11" и т.д. — теперь список пунктов одновременно и рисует меню, и
// прокидывает обработчик, так что рассинхронизация "меню показывает одно,
// switch делает другое" структурно невозможна.
type menuItem struct {
	key     string
	label   string
	section string
	handler func(ctx context.Context, target string)
}

func buildMenu() []menuItem {
	return []menuItem{
		{"1", "Security Audit", "БАЗОВЫЕ ПРОВЕРКИ СВЯЗИ", func(ctx context.Context, t string) { securityAudit(ctx, t) }},
		{"2", "SSL Deep Checker", "БАЗОВЫЕ ПРОВЕРКИ СВЯЗИ", sslChecker},
		{"3", "Port Scanner", "БАЗОВЫЕ ПРОВЕРКИ СВЯЗИ", portScanner},
		{"4", "Tracert Test", "БАЗОВЫЕ ПРОВЕРКИ СВЯЗИ", tracertTest},
		{"5", "Ping (8KB)", "БАЗОВЫЕ ПРОВЕРКИ СВЯЗИ", func(ctx context.Context, t string) { pingTest(ctx, t, "8192") }},
		{"6", "Ping (16KB)", "БАЗОВЫЕ ПРОВЕРКИ СВЯЗИ", func(ctx context.Context, t string) { pingTest(ctx, t, "16384") }},

		{"7", "BGP.he.net", "ВНЕШНИЕ СЕРВИСЫ АНАЛИЗА", func(ctx context.Context, t string) { openExternal(t, "https://bgp.he.net/dns/") }},
		{"8", "Censys.io", "ВНЕШНИЕ СЕРВИСЫ АНАЛИЗА", func(ctx context.Context, t string) { openExternal(t, "https://censys.io/ipv4?q=") }},
		{"9", "BGP.tools", "ВНЕШНИЕ СЕРВИСЫ АНАЛИЗА", func(ctx context.Context, t string) { openExternal(t, "https://bgp.tools/search?q=") }},

		{"10", "TCP RST Check", "АНАЛИЗ МЕТОДОВ БЛОКИРОВКИ (РКН)", func(ctx context.Context, t string) {
			checkTCPRst(ctx, t, 443)
			checkTCPRst(ctx, t, 80)
		}},
		{"11", "QUIC Check", "АНАЛИЗ МЕТОДОВ БЛОКИРОВКИ (РКН)", func(ctx context.Context, t string) { checkQUIC(ctx, t, 443) }},
		{"12", fmt.Sprintf("Block (%dKB)", config.Default().BlockSmallKB), "АНАЛИЗ МЕТОДОВ БЛОКИРОВКИ (РКН)", func(ctx context.Context, t string) {
			checkBlockTransfer(ctx, t, 443, cfg.BlockSmallKB)
		}},
		{"13", fmt.Sprintf("Block (%dKB)", config.Default().BlockLargeKB), "АНАЛИЗ МЕТОДОВ БЛОКИРОВКИ (РКН)", func(ctx context.Context, t string) {
			checkBlockTransfer(ctx, t, 443, cfg.BlockLargeKB)
		}},
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
	drawBox("ВЫХОД", []string{"0. Завершить работу"})
}

func main() {
	loaded, err := config.Load("config.json")
	if err != nil {
		logger.Warn("Не удалось прочитать config.json (%v), использую значения по умолчанию", err)
		loaded = config.Default()
	}
	cfg = loaded

	menu := buildMenu()
	dispatch := make(map[string]func(ctx context.Context, target string), len(menu))
	for _, it := range menu {
		dispatch[it.key] = it.handler
	}

	for {
		drawHeader()
		drawMenu(menu)

		fmt.Printf("\n %sRKN_CHECKER_# ", cyan(""))
		choice := readInput()

		if choice == "0" {
			break
		}

		handler, ok := dispatch[choice]
		if !ok {
			logger.Error("Неизвестный пункт меню: %s", choice)
			continue
		}

		target := getTarget()
		if target == "" {
			continue
		}

		fmt.Printf("\n%s\n", strings.Repeat("—", 64))

		// Общий таймаут на всю проверку — раньше traceroute/ping/browser
		// не имели контекста и могли зависнуть на неопределённое время.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		handler(ctx, target)
		cancel()

		fmt.Printf("\n%s[ Нажмите Enter для продолжения ]%s", yellow(""), reset(""))
		readInput()
	}
}
