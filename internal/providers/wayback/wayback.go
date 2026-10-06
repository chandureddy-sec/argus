package wayback

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

// Provider queries Wayback Machine CDX API for historical subdomains.
type Provider struct {
	client    *http.Client
	baseURL   string
	rateLimit time.Duration
}

var _ providers.Provider = (*Provider)(nil)

// NewProvider creates a new Wayback Machine CDX Provider.
func NewProvider(timeout time.Duration) *Provider {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &Provider{
		client: &http.Client{
			Timeout: timeout,
		},
		baseURL:   "https://web.archive.org/cdx/search/cdx",
		rateLimit: 1 * time.Second,
	}
}

func (p *Provider) Name() string {
	return "wayback"
}

func (p *Provider) Supports(t models.Target) bool {
	return t.Type == models.TargetTypeDomain
}

func (p *Provider) RateLimit() time.Duration {
	return p.rateLimit
}

func (p *Provider) Collect(ctx context.Context, t models.Target) ([]models.RawResult, error) {
	if !p.Supports(t) {
		return nil, fmt.Errorf("wayback provider does not support target type %s", t.Type)
	}

	targetDomain := strings.ToLower(strings.TrimSpace(t.Value))
	queryURL := fmt.Sprintf("%s?url=*.%s/*&output=json&fl=original,timestamp&collapse=urlkey", p.baseURL, url.QueryEscape(targetDomain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create wayback request: %w", err)
	}
	req.Header.Set("User-Agent", "ReconX/1.0 (+https://github.com/reconx/reconx)")

	resp, err := providers.DoWithRetry(ctx, p.client, req, providers.DefaultRetryConfig())
	if err != nil {
		return nil, fmt.Errorf("wayback request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback returned status %s", resp.Status)
	}

	var rawMatrix [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rawMatrix); err != nil {
		return nil, fmt.Errorf("failed to decode wayback JSON: %w", err)
	}

	index := make(map[string]int)
	var results []models.RawResult

	// The first row is usually header ["original", "timestamp"]
	startIndex := 0
	if len(rawMatrix) > 0 && len(rawMatrix[0]) > 0 && rawMatrix[0][0] == "original" {
		startIndex = 1
	}

	for i := startIndex; i < len(rawMatrix); i++ {
		if len(rawMatrix[i]) == 0 {
			continue
		}
		rawURL := rawMatrix[i][0]
		stamp := ""
		if len(rawMatrix[i]) > 1 {
			stamp = rawMatrix[i][1]
		}

		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" {
			continue
		}

		hostname := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		hostname = strings.TrimPrefix(hostname, "*.")
		hostname = strings.TrimPrefix(hostname, ".")

		if hostname == "" {
			continue
		}

		// Scope enforcement
		if hostname != targetDomain && !strings.HasSuffix(hostname, "."+targetDomain) {
			continue
		}

		// Track the earliest and latest archive capture seen for the host.
		if idx, ok := index[hostname]; ok {
			meta := results[idx].Metadata
			if stamp != "" && (meta["first_seen"] == "" || stamp < meta["first_seen"]) {
				meta["first_seen"] = stamp
			}
			if stamp > meta["last_seen"] {
				meta["last_seen"] = stamp
			}
			continue
		}

		index[hostname] = len(results)
		results = append(results, models.RawResult{
			Source:     "wayback",
			Value:      hostname,
			Type:       models.AssetTypeSubdomain,
			Confidence: 0.80,
			Metadata:   map[string]string{"first_seen": stamp, "last_seen": stamp},
		})
	}

	return results, nil
}
