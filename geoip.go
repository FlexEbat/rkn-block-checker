package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"rkn-checker/internal/logger"
)

// geoipResponse — поля ответа ip-api.com (бесплатный тариф, без ключа).
// hosting/proxy/mobile — ровно те признаки, что раздел 5.4 методики описывает
// как "определение ASN и типа сети" и "проверка в репутационных списках".
type geoipResponse struct {
	Status     string `json:"status"`
	Message    string `json:"message"`
	Country    string `json:"country"`
	RegionName string `json:"regionName"`
	City       string `json:"city"`
	ISP        string `json:"isp"`
	Org        string `json:"org"`
	AS         string `json:"as"`
	Hosting    bool   `json:"hosting"`
	Proxy      bool   `json:"proxy"`
	Mobile     bool   `json:"mobile"`
	Query      string `json:"query"`
}

// geoipCheck запрашивает публичный GeoIP/ASN сервис и показывает те же
// признаки, по которым раздел 5 методики предлагает классифицировать IP:
// страну, ASN/организацию, принадлежность к хостингу и репутационный флаг
// VPN/Proxy/TOR. Полезно как самопроверка: именно так будет выглядеть ваш
// собственный exit-IP для стороны, применяющей методику.
//
// Источник — ip-api.com, бесплатный тариф (без ключа, до 45 запросов/мин,
// без HTTPS на бесплатном плане). Для продакшн-использования по методике
// заявлен «РАНР», а до его ввода — MaxMind/IP2Location; здесь используется
// доступный публичный источник для быстрой самопроверки.
func geoipCheck(ctx context.Context, target string) {
	logger.Info("GeoIP / ASN / Hosting анализ для %s (ip-api.com)...", target)

	url := fmt.Sprintf(
		"http://ip-api.com/json/%s?fields=status,message,country,regionName,city,isp,org,as,hosting,proxy,mobile,query",
		target,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		logger.Error("Не удалось собрать запрос: %v", err)
		return
	}

	client := &http.Client{Timeout: cfg.TLSTimeout()}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Запрос к ip-api.com не удался: %v", err)
		return
	}
	defer resp.Body.Close()

	var data geoipResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		logger.Error("Не удалось разобрать ответ ip-api.com: %v", err)
		return
	}
	if data.Status != "success" {
		logger.Error("ip-api.com: %s", data.Message)
		return
	}

	fmt.Printf(" %s • Резолвится в:   %s\n", white(""), data.Query)
	fmt.Printf(" %s • Страна/регион:  %s, %s (%s)\n", white(""), data.Country, data.RegionName, data.City)
	fmt.Printf(" %s • ISP:            %s\n", white(""), data.ISP)
	fmt.Printf(" %s • Организация:    %s\n", white(""), data.Org)
	fmt.Printf(" %s • ASN:            %s\n", white(""), data.AS)

	if data.Hosting {
		logger.Warn("Hosting: ДА — диапазон принадлежит дата-центру/хостеру (типичный признак VPN/Proxy-инфраструктуры, п.5.4)")
	} else {
		logger.Success("Hosting: нет — диапазон не размечен как дата-центр")
	}
	if data.Proxy {
		logger.Warn("Reputation: IP числится в базе публичных VPN/Proxy/TOR-узлов (п.5.4)")
	} else {
		logger.Success("Reputation: в репутационных списках VPN/Proxy/TOR не значится")
	}
	if data.Mobile {
		fmt.Printf(" %s • Сеть определена как мобильная (сотовый оператор)\n", cyan(""))
	}
}
