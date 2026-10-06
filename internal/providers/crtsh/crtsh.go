package crtsh

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"reconx/internal/providers"
	"reconx/pkg/models"
)

// Entry is one certificate (or precertificate) row from crt.sh's JSON output.
type Entry struct {
	ID             int64  `json:"id"`
	IssuerCAID     int64  `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	SerialNumber   string `json:"serial_number"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	EntryTimestamp string `json:"entry_timestamp"`
}

// cache shares one crt.sh response per domain between subdomain discovery and
// certificate analysis within a scan (and across scans for a short while).
var cache = providers.NewMemo[[]Entry](15 * time.Minute)

const defaultBaseURL = "https://crt.sh/"

// Provider queries crt.sh for Certificate Transparency logs.
type Provider struct {
	client    *http.Client
	baseURL   string
	rateLimit time.Duration
}

// Ensure Provider implements the providers.Provider interface
var _ providers.Provider = (*Provider)(nil)

// NewProvider creates a new crt.sh Provider instance.
func NewProvider(timeout time.Duration) *Provider {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &Provider{
		client: &http.Client{
			Timeout: timeout,
		},
		baseURL:   defaultBaseURL,
		rateLimit: 1 * time.Second,
	}
}

func (p *Provider) Name() string {
	return "crtsh"
}

func (p *Provider) Supports(t models.Target) bool {
	return t.Type == models.TargetTypeDomain
}

func (p *Provider) RateLimit() time.Duration {
	return p.rateLimit
}

// Fetch returns every CT-log certificate entry matching the domain and its
// subdomains, served from the shared cache when available.
func (p *Provider) Fetch(ctx context.Context, domain string) ([]Entry, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return cache.Get(ctx, p.baseURL+"|"+domain, func(ctx context.Context) ([]Entry, error) {
		return p.fetch(ctx, domain)
	})
}

// FetchEntries is Fetch using the default crt.sh endpoint.
func FetchEntries(ctx context.Context, domain string, timeout time.Duration) ([]Entry, error) {
	return NewProvider(timeout).Fetch(ctx, domain)
}

func (p *Provider) fetch(ctx context.Context, domain string) ([]Entry, error) {
	queryURL := fmt.Sprintf("%s?q=%s&output=json", p.baseURL, url.QueryEscape("%."+domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create crtsh request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconX/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := providers.DoWithRetry(ctx, p.client, req, providers.DefaultRetryConfig())
	if err != nil {
		return nil, fmt.Errorf("crtsh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crtsh returned status %s", resp.Status)
	}

	var entries []Entry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to decode crtsh JSON: %w", err)
	}
	return entries, nil
}

// Names returns the hostnames named by a certificate entry (SANs plus CN),
// lower-cased, with trailing dots removed. Wildcard names keep their "*.".
func (e Entry) Names() []string {
	raw := strings.Split(e.NameValue, "\n")
	if e.CommonName != "" {
		raw = append(raw, e.CommonName)
	}
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, n := range raw {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

func (p *Provider) Collect(ctx context.Context, t models.Target) ([]models.RawResult, error) {
	if !p.Supports(t) {
		return nil, fmt.Errorf("crtsh provider does not support target type %s", t.Type)
	}

	targetDomain := strings.ToLower(strings.TrimSpace(t.Value))
	entries, err := p.Fetch(ctx, targetDomain)
	if err != nil {
		return nil, err
	}

	// Aggregate per hostname: the earliest issuance is when the host first
	// became observable; the latest CT entry is its most recent observation.
	type span struct{ first, last string }
	spans := make(map[string]*span)
	order := []string{}

	for _, entry := range entries {
		for _, name := range entry.Names() {
			clean := strings.TrimPrefix(strings.TrimPrefix(name, "*."), ".")
			if clean == "" {
				continue
			}
			// Scope validation: candidate must equal or end with .targetDomain
			if clean != targetDomain && !strings.HasSuffix(clean, "."+targetDomain) {
				continue
			}
			s, ok := spans[clean]
			if !ok {
				s = &span{}
				spans[clean] = s
				order = append(order, clean)
			}
			if entry.NotBefore != "" && (s.first == "" || entry.NotBefore < s.first) {
				s.first = entry.NotBefore
			}
			last := entry.EntryTimestamp
			if last == "" {
				last = entry.NotBefore
			}
			if last > s.last {
				s.last = last
			}
		}
	}

	results := make([]models.RawResult, 0, len(order))
	for _, host := range order {
		s := spans[host]
		results = append(results, models.RawResult{
			Source:     "crtsh",
			Value:      host,
			Type:       models.AssetTypeSubdomain,
			Confidence: 0.85,
			Metadata: map[string]string{
				"first_seen": s.first,
				"last_seen":  s.last,
			},
		})
	}

	return results, nil
}
