package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/pkg/browser"
	"github.com/quic-go/quic-go"
)

var (
	cyan   = color.New(color.FgCyan).SprintFunc()
	white  = color.New(color.FgWhite).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	reset  = color.New(color.Reset).SprintFunc()
)

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

func getTarget() string {
	fmt.Printf("\n %s >> %sВведите IP или Домен для анализа\n", cyan(""), white(""))
	fmt.Printf(" %s >> ", cyan(""))
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	target := strings.TrimSpace(input)
	target = strings.Replace(target, "http://", "", -1)
	target = strings.Replace(target, "https://", "", -1)
	return strings.Split(target, "/")[0]
}

func sslChecker(t string) {
	fmt.Printf("\n%s Глубокий анализ SSL для %s...\n", yellow("[*]"), t)
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", t+":443", conf)
	if err != nil {
		fmt.Printf("%s Ошибка SSL: %v\n", red("[!]"), err)
		return
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	fmt.Printf("\n%s ДЕТАЛИ СЕРТИФИКАТА:\n", green("[+]"))
	fmt.Printf(" %s • Владелец:    %s\n", white(""), cert.Subject.CommonName)
	fmt.Printf(" %s • Кем выдан:   %s (%s)\n", white(""), cert.Issuer.Organization, cert.Issuer.CommonName)
	fmt.Printf(" %s • Протокол:    %s\n", white(""), tlsProtocolName(conn.ConnectionState().Version))
	fmt.Printf(" %s • Шифрование:  %s\n", white(""), tls.CipherSuiteName(conn.ConnectionState().CipherSuite))
	fmt.Printf(" %s • Выдан:       %s\n", cyan(""), cert.NotBefore.Format("2006-01-02"))
	fmt.Printf(" %s • Срок до:     %s\n", cyan(""), cert.NotAfter.Format("2006-01-02"))

	if time.Now().Before(cert.NotAfter) && time.Now().After(cert.NotBefore) {
		fmt.Printf(" %s [!] Статус:      АКТИВЕН\n", green(""))
	} else {
		fmt.Printf(" %s [!] Статус:      ПРОСРОЧЕН/НЕАКТИВЕН\n", red(""))
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

func checkTCPRst(target string, port int) {
	fmt.Printf("%s Проверка TCP RST на %s:%d...\n", yellow("[*]"), target, port)
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		if strings.Contains(err.Error(), "connection reset") || strings.Contains(err.Error(), "reset by peer") {
			fmt.Printf("%s %s:%d - Получен RST (Connection Reset)\n", red("[-]"), target, port)
		} else {
			fmt.Printf("%s %s:%d - Ошибка: %v\n", red("[-]"), target, port, err)
		}
		return
	}
	defer conn.Close()
	fmt.Printf("%s %s:%d - Соединение установлено\n", green("[+]"), target, port)
}

func checkQUIC(target string, port int) {
	fmt.Printf("%s Проверка QUIC на %s:%d...\n", yellow("[*]"), target, port)
	address := fmt.Sprintf("%s:%d", target, port)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3", "h2", "http/1.1"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := quic.DialAddr(ctx, address, tlsConf, nil)
	if err != nil {
		fmt.Printf("%s %s:%d - QUIC недоступен: %v\n", red("[-]"), target, port, err)
		return
	}
	fmt.Printf("%s %s:%d - QUIC доступен\n", green("[+]"), target, port)
}

func checkBlockTransfer(target string, port int, sizeKB int) {
	fmt.Printf("%s Тестирование передачи блока %dKB на %s:%d...\n", yellow("[*]"), sizeKB, target, port)
	address := fmt.Sprintf("%s:%d", target, port)
	data := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Sentinel\r\n", target))
	padding := strings.Repeat("A", sizeKB*1024-len(data)-4)
	data = append(data, []byte("X-Data: "+padding+"\r\n\r\n")...)

	conf := &tls.Config{InsecureSkipVerify: true}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, conf)
	if err != nil {
		fmt.Printf("%s %s:%d - Ошибка TLS при отправке блока %dKB: %v\n", red("[-]"), target, port, sizeKB, err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		fmt.Printf("%s Ошибка отправки: %v\n", red("[-]"), err)
		return
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		fmt.Printf("%s %s:%d - Блок %dKB отправлен, но ответ не получен (Timeout/Err: %v)\n", yellow("[!]"), target, port, sizeKB, err)
	} else {
		fmt.Printf("%s %s:%d - Блок %dKB принят сервером, получен ответ\n", green("[+]"), target, port, sizeKB)
	}
}

func main() {
	for {
		drawHeader()

		drawBox("БАЗОВЫЕ ПРОВЕРКИ СВЯЗИ", []string{
			"1. Security Audit", "2. SSL Deep Checker",
			"3. Port Scanner", "4. Tracert Test",
			"5. Ping (8KB)", "6. Ping (16KB)",
		})

		drawBox("ВНЕШНИЕ СЕРВИСЫ АНАЛИЗА", []string{
			"7. BGP.he.net", "8. Censys.io",
			"9. BGP.tools", "0. ВЫХОД",
		})

		drawBox("АНАЛИЗ МЕТОДОВ БЛОКИРОВКИ (РКН)", []string{
			"10. TCP RST Check", "11. QUIC Check",
			"12. Block (8KB)", "13. Block (16KB)",
		})

		fmt.Printf("\n %sRKN_CHECKER_# ", cyan(""))
		var choice string
		fmt.Scanln(&choice)

		if choice == "0" {
			break
		}

		target := getTarget()
		if target == "" {
			continue
		}

		fmt.Printf("\n%s\n", strings.Repeat("—", 64))

		switch choice {
		case "1":
			resp, err := http.Get("http://" + target)
			if err == nil {
				h := resp.Header
				hsts := "MISSING"
				if _, ok := h["Strict-Transport-Security"]; ok {
					hsts = "OK"
				}
				csp := "MISSING"
				if _, ok := h["Content-Security-Policy"]; ok {
					csp = "OK"
				}
				fmt.Printf("HSTS: %s\n", hsts)
				fmt.Printf("CSP:  %s\n", csp)
				resp.Body.Close()
			} else {
				fmt.Println("Сайт недоступен")
			}
		case "2":
			sslChecker(target)
		case "3":
			ports := []int{21, 22, 80, 443, 3306, 3389}
			for _, p := range ports {
				address := fmt.Sprintf("%s:%d", target, p)
				conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
				if err == nil {
					fmt.Printf("Port %d: OPEN\n", p)
					conn.Close()
				}
			}
		case "4":
			cmdName := "traceroute"
			if runtime.GOOS == "windows" {
				cmdName = "tracert"
			}
			cmd := exec.Command(cmdName, target)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
		case "5", "6":
			size := "8192"
			if choice == "6" {
				size = "16384"
			}
			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				cmd = exec.Command("ping", "-l", size, "-n", "4", target)
			} else {
				cmd = exec.Command("ping", "-s", size, "-c", "4", target)
			}
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
		case "7", "8", "9":
			urls := map[string]string{
				"7": "https://bgp.he.net/dns/" + target,
				"8": "https://censys.io/ipv4?q=" + target,
				"9": "https://bgp.tools/search?q=" + target,
			}
			browser.OpenURL(urls[choice])
		case "10":
			checkTCPRst(target, 443)
			checkTCPRst(target, 80)
		case "11":
			checkQUIC(target, 443)
		case "12":
			checkBlockTransfer(target, 443, 8)
		case "13":
			checkBlockTransfer(target, 443, 16)
		}

		fmt.Printf("\n%s[ Нажмите Enter для продолжения ]%s", yellow(""), reset(""))
		bufio.NewReader(os.Stdin).ReadBytes('\n')
	}
}
