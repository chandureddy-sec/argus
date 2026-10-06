package hackertarget

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"reconx/internal/providers"
	"reconx/pkg/models"
)

// Provider queries HackerTarget hostsearch free endpoint for passive DNS records.
type Provider struct {
	client    *http.Client
	baseURL   string
	rateLimit time.Duration
}

var _ providers.Provider = (*Provider)(nil)

// NewProvider creates a new HackerTarget Provider.
func NewProvider(timeout time.Duration) *Provider {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Provider{
		client: &http.Client{
			Timeout: timeout,
		},
		baseURL:   "https://api.hackertarget.com/hostsearch/?q=",
		rateLimit: 2 * time.Second,
	}
}

func (p *Provider) Name() string {
	return "hackertarget"
}

func (p *Provider) Supports(t models.Target) bool {
	return t.Type == models.TargetTypeDomain
}

func (p *Provider) RateLimit() time.Duration {
	return p.rateLimit
}

func (p *Provider) Collect(ctx context.Context, t models.Target) ([]models.RawResult, error) {
	if !p.Supports(t) {
		return nil, fmt.Errorf("hackertarget provider does not support target type %s", t.Type)
	}

	targetDomain := strings.ToLower(strings.TrimSpace(t.Value))
	url := p.baseURL + targetDomain

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create hackertarget request: %w", err)
	}
	req.Header.Set("User-Agent", "ReconX/1.0 (+https://github.com/reconx/reconx)")

	resp, err := providers.DoWithRetry(ctx, p.client, req, providers.DefaultRetryConfig())
	if err != nil {
		return nil, fmt.Errorf("hackertarget request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hackertarget returned status %s", resp.Status)
	}

	scanner := bufio.NewScanner(resp.Body)
	seen := make(map[string]bool)
	var results []models.RawResult

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "error") || strings.HasPrefix(line, "API count exceeded") {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}

		subdomain := strings.ToLower(strings.TrimSpace(parts[0]))
		ip := strings.TrimSpace(parts[1])

		// Scope enforcement
		if subdomain != targetDomain && !strings.HasSuffix(subdomain, "."+targetDomain) {
			continue
		}

		if seen[subdomain] {
			continue
		}
		seen[subdomain] = true

		results = append(results, models.RawResult{
			Source:     "hackertarget",
			Value:      subdomain,
			Type:       models.AssetTypeSubdomain,
			Confidence: 0.90,
			Metadata: map[string]string{
				"ip": ip,
			},
		})
	}

	return results, scanner.Err()
}
