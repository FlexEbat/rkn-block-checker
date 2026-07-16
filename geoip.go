package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"rkn-checker/internal/logger"
)

// geoipResponse — fields returned by ip-api.com (free tier, no key required).
// hosting/proxy/mobile are exactly the signals a GeoIP/ASN classification
// section of the detection methodology describes as "network type
// determination" and "reputation list lookup".
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

// geoipCheck queries a public GeoIP/ASN service and shows the same signals
// the methodology uses to classify an IP: country, ASN/organization,
// hosting-provider membership, and a reputation flag for known VPN/Proxy/TOR
// nodes. Useful as a self-check: this is exactly how your own exit IP would
// look to a party applying the methodology.
//
// Source: ip-api.com, free tier (no key, up to 45 requests/min, no HTTPS on
// the free plan). A production deployment of the methodology would use a
// dedicated national registry or MaxMind/IP2Location; this uses a readily
// available public source for a quick self-check.
func geoipCheck(ctx context.Context, target string) {
	logger.Info("GeoIP / ASN / Hosting analysis for %s (ip-api.com)...", target)

	url := fmt.Sprintf(
		"http://ip-api.com/json/%s?fields=status,message,country,regionName,city,isp,org,as,hosting,proxy,mobile,query",
		target,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		logger.Error("Failed to build request: %v", err)
		return
	}

	client := &http.Client{Timeout: cfg.TLSTimeout()}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Request to ip-api.com failed: %v", err)
		return
	}
	defer resp.Body.Close()

	var data geoipResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		logger.Error("Failed to parse ip-api.com response: %v", err)
		return
	}
	if data.Status != "success" {
		logger.Error("ip-api.com: %s", data.Message)
		return
	}

	fmt.Printf(" %s • Resolves to:      %s\n", white(""), data.Query)
	fmt.Printf(" %s • Country/region:   %s, %s (%s)\n", white(""), data.Country, data.RegionName, data.City)
	fmt.Printf(" %s • ISP:              %s\n", white(""), data.ISP)
	fmt.Printf(" %s • Organization:     %s\n", white(""), data.Org)
	fmt.Printf(" %s • ASN:              %s\n", white(""), data.AS)

	if data.Hosting {
		logger.Warn("Hosting: YES — range belongs to a data center/hosting provider (a typical sign of VPN/Proxy infrastructure)")
	} else {
		logger.Success("Hosting: no — range is not flagged as a data center")
	}
	if data.Proxy {
		logger.Warn("Reputation: IP is listed in a public VPN/Proxy/TOR node database")
	} else {
		logger.Success("Reputation: not listed in VPN/Proxy/TOR reputation lists")
	}
	if data.Mobile {
		fmt.Printf(" %s • Network flagged as mobile (cellular carrier)\n", cyan(""))
	}
}
