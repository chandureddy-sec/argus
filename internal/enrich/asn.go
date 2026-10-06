package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

// IPIntelligence holds ASN, ISP, country, and organization info for an IP address.
type IPIntelligence struct {
	IP            string `json:"ip"`
	ASN           string `json:"asn,omitempty"`
	Organization  string `json:"organization,omitempty"`
	ISP           string `json:"isp,omitempty"`
	Country       string `json:"country,omitempty"`
	City          string `json:"city,omitempty"`
	CloudProvider string `json:"cloud_provider,omitempty"`
	PTR           string `json:"ptr,omitempty"`
	CountryCode   string `json:"country_code,omitempty"`
	Region        string `json:"region,omitempty"`
	Continent     string `json:"continent,omitempty"`
	ASName        string `json:"as_name,omitempty"`
	Hosting       bool   `json:"hosting,omitempty"`
}

type ipAPIBatchQuery struct {
	Query  string `json:"query"`
	Fields string `json:"fields"`
}

type ipAPIBatchResponse struct {
	Query   string `json:"query"`
	Status  string `json:"status"`
	Country string `json:"country"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	AS      string `json:"as"`
	Reverse string `json:"reverse"`

	CountryCode string `json:"countryCode"`
	RegionName  string `json:"regionName"`
	Continent   string `json:"continent"`
	ASName      string `json:"asname"`
	Hosting     bool   `json:"hosting"`
}

// IPEnricher performs ASN, Geolocation, and Provider intelligence on IPs.
type IPEnricher struct {
	client  *http.Client
	baseURL string
}

// NewIPEnricher initializes an IPEnricher.
func NewIPEnricher(timeout time.Duration) *IPEnricher {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &IPEnricher{
		client: &http.Client{
			Timeout: timeout,
		},
		baseURL: "http://ip-api.com/batch",
	}
}

// EnrichBatch performs batch ASN and organization lookups for up to 100 IPs.
func (e *IPEnricher) EnrichBatch(ctx context.Context, ips []string) map[string]IPIntelligence {
	results := make(map[string]IPIntelligence)
	if len(ips) == 0 {
		return results
	}

	// Limit to unique, public IPs (skip loopback, private)
	var publicIPs []string
	for _, raw := range ips {
		parsed := net.ParseIP(raw)
		if parsed != nil && !parsed.IsPrivate() && !parsed.IsLoopback() {
			publicIPs = append(publicIPs, raw)
		}
	}

	if len(publicIPs) == 0 {
		return results
	}

	// Chunk into slices of 100
	const chunkSize = 100
	for i := 0; i < len(publicIPs); i += chunkSize {
		end := i + chunkSize
		if end > len(publicIPs) {
			end = len(publicIPs)
		}
		chunk := publicIPs[i:end]

		batchQueries := make([]ipAPIBatchQuery, len(chunk))
		for idx, ip := range chunk {
			batchQueries[idx] = ipAPIBatchQuery{
				Query:  ip,
				Fields: "status,continent,country,countryCode,regionName,city,isp,org,as,asname,reverse,hosting,query",
			}
		}

		bodyBytes, err := json.Marshal(batchQueries)
		if err != nil {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL, bytes.NewReader(bodyBytes))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "ReconX/1.0 (+https://github.com/reconx/reconx)")

		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}

		var apiResp []ipAPIBatchResponse
		decErr := json.NewDecoder(resp.Body).Decode(&apiResp)
		resp.Body.Close()

		if decErr == nil {
			for _, item := range apiResp {
				if item.Status == "success" {
					intel := IPIntelligence{
						IP:            item.Query,
						ASN:           item.AS,
						Organization:  item.Org,
						ISP:           item.ISP,
						Country:       item.Country,
						City:          item.City,
						PTR:           item.Reverse,
						CloudProvider: detectCloudProvider(item.ISP, item.Org, item.AS),
						CountryCode:   item.CountryCode,
						Region:        item.RegionName,
						Continent:     item.Continent,
						ASName:        item.ASName,
						Hosting:       item.Hosting,
					}
					results[item.Query] = intel
				}
			}
		}
	}

	// Fallback PTR lookup for any remaining IPs
	for _, ip := range ips {
		if _, exists := results[ip]; !exists {
			intel := IPIntelligence{IP: ip}
			names, err := net.LookupAddr(ip)
			if err == nil && len(names) > 0 {
				intel.PTR = strings.TrimSuffix(names[0], ".")
			}
			results[ip] = intel
		}
	}

	return results
}

// detectCloudProvider identifies common cloud & CDN providers from ISP/Org/ASN strings.
func detectCloudProvider(isp, org, as string) string {
	combined := strings.ToLower(isp + " " + org + " " + as)
	switch {
	case strings.Contains(combined, "cloudflare"):
		return "Cloudflare (CDN/Proxy)"
	case strings.Contains(combined, "amazon") || strings.Contains(combined, "aws"):
		return "Amazon Web Services (AWS)"
	case strings.Contains(combined, "google") || strings.Contains(combined, "gcp"):
		return "Google Cloud Platform (GCP)"
	case strings.Contains(combined, "microsoft") || strings.Contains(combined, "azure"):
		return "Microsoft Azure"
	case strings.Contains(combined, "akamai"):
		return "Akamai (CDN/WAF)"
	case strings.Contains(combined, "fastly"):
		return "Fastly (CDN)"
	case strings.Contains(combined, "digitalocean"):
		return "DigitalOcean"
	case strings.Contains(combined, "linode") || strings.Contains(combined, "akamai connected cloud"):
		return "Linode / Akamai"
	case strings.Contains(combined, "ovh"):
		return "OVHcloud"
	case strings.Contains(combined, "hetzner"):
		return "Hetzner"
	default:
		if org != "" {
			return org
		}
		if isp != "" {
			return isp
		}
		return "Unknown / On-Premise"
	}
}
