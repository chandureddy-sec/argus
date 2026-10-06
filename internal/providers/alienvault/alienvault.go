package alienvault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"reconx/internal/providers"
	"reconx/pkg/models"
)

// PassiveDNSRecord is one OTX passive-DNS observation: hostname -> value
// (an IP for A/AAAA, a target name for CNAME) with its observation window.
type PassiveDNSRecord struct {
	Hostname   string `json:"hostname"`
	Address    string `json:"address"`
	RecordType string `json:"record_type"`
	First      string `json:"first"`
	Last       string `json:"last"`
	ASN        string `json:"asn"`
}

type otxResponse struct {
	PassiveDNS []PassiveDNSRecord `json:"passive_dns"`
}

// cache shares one OTX response per domain between subdomain discovery and
// historical-DNS correlation.
var cache = providers.NewMemo[[]PassiveDNSRecord](15 * time.Minute)

// Provider queries AlienVault OTX for passive DNS history.
type Provider struct {
	client    *http.Client
	baseURL   string
	rateLimit time.Duration
}

var _ providers.Provider = (*Provider)(nil)

// NewProvider creates a new AlienVault OTX Provider.
func NewProvider(timeout time.Duration) *Provider {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &Provider{
		client: &http.Client{
			Timeout: timeout,
		},
		baseURL:   "https://otx.alienvault.com/api/v1/indicators/domain/",
		rateLimit: 1 * time.Second,
	}
}

func (p *Provider) Name() string {
	return "alienvault"
}

func (p *Provider) Supports(t models.Target) bool {
	return t.Type == models.TargetTypeDomain
}

func (p *Provider) RateLimit() time.Duration {
	return p.rateLimit
}

func (p *Provider) Collect(ctx context.Context, t models.Target) ([]models.RawResult, error) {
	if !p.Supports(t) {
		return nil, fmt.Errorf("alienvault provider does not support target type %s", t.Type)
	}

	targetDomain := strings.ToLower(strings.TrimSpace(t.Value))
	records, err := p.Fetch(ctx, targetDomain)
	if err != nil {
		return nil, err
	}

	// OTX returns one row per (hostname, value); fold them into one result per
	// hostname spanning the earliest first and latest last observation.
	index := make(map[string]int)
	var results []models.RawResult

	for _, item := range records {
		sub := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(item.Hostname)), ".")
		if sub == "" {
			continue
		}

		// Scope enforcement
		if sub != targetDomain && !strings.HasSuffix(sub, "."+targetDomain) {
			continue
		}

		if i, ok := index[sub]; ok {
			meta := results[i].Metadata
			if item.First != "" && (meta["first_seen"] == "" || item.First < meta["first_seen"]) {
				meta["first_seen"] = item.First
			}
			if item.Last > meta["last_seen"] {
				meta["last_seen"] = item.Last
			}
			continue
		}

		index[sub] = len(results)
		results = append(results, models.RawResult{
			Source:     "alienvault",
			Value:      sub,
			Type:       models.AssetTypeSubdomain,
			Confidence: 0.90,
			Metadata: map[string]string{
				"ip":         item.Address,
				"first_seen": item.First,
				"last_seen":  item.Last,
			},
		})
	}

	return results, nil
}

// Fetch returns the OTX passive-DNS records for the domain, served from the
// shared cache when available.
func (p *Provider) Fetch(ctx context.Context, domain string) ([]PassiveDNSRecord, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return cache.Get(ctx, p.baseURL+"|"+domain, func(ctx context.Context) ([]PassiveDNSRecord, error) {
		return p.fetch(ctx, domain)
	})
}

// FetchPassiveDNS is Fetch using the default OTX endpoint.
func FetchPassiveDNS(ctx context.Context, domain string, timeout time.Duration) ([]PassiveDNSRecord, error) {
	return NewProvider(timeout).Fetch(ctx, domain)
}

func (p *Provider) fetch(ctx context.Context, domain string) ([]PassiveDNSRecord, error) {
	url := fmt.Sprintf("%s%s/passive_dns", p.baseURL, domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create alienvault request: %w", err)
	}
	req.Header.Set("User-Agent", "ReconX/1.0 (+https://github.com/reconx/reconx)")
	req.Header.Set("Accept", "application/json")

	resp, err := providers.DoWithRetry(ctx, p.client, req, providers.DefaultRetryConfig())
	if err != nil {
		return nil, fmt.Errorf("alienvault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("alienvault returned status %s", resp.Status)
	}

	var data otxResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode alienvault JSON: %w", err)
	}
	return data.PassiveDNS, nil
}
