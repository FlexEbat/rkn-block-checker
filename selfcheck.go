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

// vpnIfacePattern — характерные имена туннельных интерфейсов из раздела 8.5
// методики (tun/tap/wg/utun/ppp) плюс распространённые Windows-имена VPN-
// адаптеров (wintun, openvpn, wireguard, tap-windows).
var vpnIfacePattern = regexp.MustCompile(`(?i)^(tun|tap|wg|utun|ppp|wintun|ipsec|ovpn|nordlynx|wireguard)`)

// privateOrLoopback grubo проверяет, похож ли IP на частный/loopback-адрес —
// раздел 7.7 указывает на «локальные адреса DNS-серверов» как аномалию.
func privateOrLoopback(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// localInterfaceCheck — самопроверка локальных сетевых интерфейсов этого
// устройства (раздел 8.5/8.4/8.6 методики, кроссплатформенно через net.Interfaces).
// Показывает, что увидел бы анализ клиентских интерфейсов, если бы искал
// признаки VPN: активные (UP) интерфейсы с именами tun/tap/wg/ppp и
// заниженным MTU (методика упоминает типичные значения 1350/1400 для
// туннелей VPN против ~1500 у обычного Ethernet).
func localInterfaceCheck(ctx context.Context, _ string) {
	logger.Info("Самопроверка локальных сетевых интерфейсов (%s)...", runtime.GOOS)

	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Error("Не удалось получить список интерфейсов: %v", err)
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
			continue // показываем только потенциально интересные интерфейсы, не весь шум
		}

		status := "DOWN"
		if isUp {
			status = "UP"
		}

		if looksLikeVPN && isUp {
			found = true
			logger.Warn("%-12s статус=%-4s MTU=%-5d адреса=%v — имя похоже на туннельный интерфейс (VPN/WireGuard)", iface.Name, status, iface.MTU, ips)
			if iface.MTU > 0 && iface.MTU < 1450 {
				logger.Warn("  → MTU=%d ниже стандартного Ethernet (~1500) — типично для VPN-туннеля (методика, разд. 8.5)", iface.MTU)
			}
		} else if looksLikeVPN {
			logger.Info("%-12s статус=%-4s (не активен) — по имени похож на VPN-интерфейс, но выключен", iface.Name, status)
		}
	}

	if !found {
		logger.Success("Активных интерфейсов с признаками VPN/туннеля (tun/tap/wg/ppp) не обнаружено")
	}
}

// localRouteCheck выводит таблицу маршрутизации этого устройства через
// штатные системные утилиты и подсвечивает наличие нескольких маршрутов по
// умолчанию — раздел 8.5 отмечает это как дополнительный признак.
func localRouteCheck(ctx context.Context, _ string) {
	logger.Info("Самопроверка таблицы маршрутизации (%s)...", runtime.GOOS)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "route", "print", "-4")
	case "darwin":
		cmd = exec.CommandContext(ctx, "netstat", "-rn", "-f", "inet")
	default: // linux и прочие unix
		cmd = exec.CommandContext(ctx, "ip", "route")
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Не удалось получить таблицу маршрутизации: %v", err)
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
		logger.Warn("Найдено маршрутов по умолчанию: %d — несколько default-маршрутов может указывать на активный VPN-туннель (разд. 8.5)", defaultCount)
	} else {
		logger.Success("Найдено маршрутов по умолчанию: %d — аномалий не обнаружено", defaultCount)
	}
}

// localDNSCheck проверяет DNS-конфигурацию устройства на признаки из
// раздела 7.7: локальные/loopback DNS-серверы или направление резолвинга в
// виртуальный интерфейс.
func localDNSCheck(ctx context.Context, _ string) {
	logger.Info("Самопроверка DNS-конфигурации (%s)...", runtime.GOOS)

	var nameservers []string

	if runtime.GOOS == "windows" {
		cmd := exec.CommandContext(ctx, "ipconfig", "/all")
		out, err := cmd.CombinedOutput()
		if err != nil {
			logger.Error("Не удалось выполнить ipconfig: %v", err)
			return
		}
		nameservers = extractIPv4(string(out))
	} else {
		data, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			logger.Error("Не удалось прочитать /etc/resolv.conf: %v", err)
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
		logger.Warn("DNS-серверы не найдены/не распознаны")
		return
	}

	anomaly := false
	for _, ns := range nameservers {
		ip := net.ParseIP(ns)
		if ip == nil {
			continue
		}
		if privateOrLoopback(ip) {
			logger.Warn("DNS-сервер %s — частный/loopback адрес (разд. 7.7: возможный признак перенаправления в VPN-интерфейс)", ns)
			anomaly = true
		} else {
			fmt.Printf(" %s • DNS-сервер: %s\n", white(""), ns)
		}
	}

	if !anomaly {
		logger.Success("DNS-серверы выглядят как обычные публичные/провайдерские адреса")
	}
}

// extractIPv4 достаёт все IPv4-адреса из произвольного текста — используется
// для грубого парсинга вывода ipconfig /all на Windows, где формат вывода
// сильно зависит от локализации ОС и не поддаётся надёжному построчному
// разбору по ключевым словам.
func extractIPv4(text string) []string {
	re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	return re.FindAllString(text, -1)
}
