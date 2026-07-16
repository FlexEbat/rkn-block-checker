package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"rkn-checker/internal/logger"
)

// scannerLookupCheck проверяет один введённый IP/домен на вхождение в список
// известных диапазонов сканирующей инфраструктуры. Удобно, например, чтобы
// быстро пробить IP из своих логов доступа.
func scannerLookupCheck(ctx context.Context, target string) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", target)
	if err != nil || len(ips) == 0 {
		// Возможно, это уже голый IP, а не домен — пробуем распарсить напрямую.
		if ip := net.ParseIP(target); ip != nil {
			ips = []net.IP{ip}
		} else {
			logger.Error("Не удалось разрешить %s: %v", target, err)
			return
		}
	}

	found := false
	for _, ip := range ips {
		if rng, ok := matchScanner(ip); ok {
			logger.Warn("%s → %s ПОПАДАЕТ в список известных сканеров (диапазон %s)", target, ip, rng)
			found = true
		} else {
			fmt.Printf(" %s • %s → %s — в списке сканеров не найден\n", white(""), target, ip)
		}
	}
	if !found {
		logger.Success("Совпадений со списком известных сканеров не найдено")
	}
}

// remoteIPPortRegex вытаскивает IP:port (IPv4) из вывода ss/netstat/route-подобных
// утилит независимо от локали и точного формата колонок.
var remoteIPPortRegex = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b`)

// serverScanCheck смотрит на ТЕКУЩИЕ входящие TCP-подключения к этой машине
// (через ss/netstat) и сверяет удалённые адреса со списком известных
// сканеров. Предназначено для запуска на самом VPN-сервере, чтобы увидеть,
// не идёт ли по нему прямо сейчас зондирование с известных диапазонов.
//
// Ограничение: показывает только соединения, установленные НА МОМЕНТ запуска
// проверки — это не постоянный мониторинг, а разовый снимок.
func serverScanCheck(ctx context.Context, _ string) {
	logger.Info("Проверка активных входящих подключений на IP из списка сканеров (%s)...", runtime.GOOS)

	out, err := listEstablishedConnections(ctx)
	if err != nil {
		logger.Error("Не удалось получить список подключений: %v", err)
		return
	}

	localIPs := localMachineIPs()

	seen := map[string]bool{}
	matches := 0
	total := 0

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		pairs := remoteIPPortRegex.FindAllStringSubmatch(line, -1)
		if len(pairs) == 0 {
			continue
		}
		// В строке обычно два адреса: локальный и удалённый. Берём те, что не
		// совпадают с локальными IP этой машины — это и есть "удалённая сторона".
		for _, p := range pairs {
			ipStr := p[1]
			if localIPs[ipStr] {
				continue
			}
			if seen[ipStr] {
				continue
			}
			seen[ipStr] = true
			total++

			ip := net.ParseIP(ipStr)
			if rng, ok := matchScanner(ip); ok {
				logger.Warn("Подключение от %s — СОВПАДЕНИЕ со списком известных сканеров (диапазон %s)", ipStr, rng)
				matches++
			}
		}
	}

	fmt.Printf(" %s • Уникальных удалённых адресов в снимке: %d\n", white(""), total)
	if matches > 0 {
		logger.Warn("Найдено совпадений со списком сканеров: %d", matches)
	} else {
		logger.Success("Совпадений со списком известных сканеров не найдено")
	}
}

// listEstablishedConnections возвращает сырой вывод системной утилиты со
// списком установленных TCP-соединений, платформо-зависимо.
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

// localMachineIPs собирает все IP-адреса, назначенные локальным интерфейсам
// этой машины, чтобы отличить "локальную" сторону соединения от "удалённой"
// при разборе вывода ss/netstat (там оба адреса выглядят одинаково).
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
