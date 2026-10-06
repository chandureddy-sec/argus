package anubis

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

// Provider queries Anubis for passive subdomains.
type Provider struct {
	client    *http.Client
	baseURL   string
	rateLimit time.Duration
}

var _ providers.Provider = (*Provider)(nil)

// NewProvider creates a new Anubis Provider.
func NewProvider(timeout time.Duration) *Provider {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &Provider{
		client: &http.Client{
			Timeout: timeout,
		},
		baseURL:   "https://jldc.me/anubis/subdomains/",
		rateLimit: 1 * time.Second,
	}
}

func (p *Provider) Name() string {
	return "anubis"
}

func (p *Provider) Supports(t models.Target) bool {
	return t.Type == models.TargetTypeDomain
}

func (p *Provider) RateLimit() time.Duration {
	return p.rateLimit
}

func (p *Provider) Collect(ctx context.Context, t models.Target) ([]models.RawResult, error) {
	if !p.Supports(t) {
		return nil, fmt.Errorf("anubis provider does not support target type %s", t.Type)
	}

	targetDomain := strings.ToLower(strings.TrimSpace(t.Value))
	url := p.baseURL + targetDomain

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create anubis request: %w", err)
	}
	req.Header.Set("User-Agent", "ReconX/1.0 (+https://github.com/reconx/reconx)")
	req.Header.Set("Accept", "application/json")

	resp, err := providers.DoWithRetry(ctx, p.client, req, providers.DefaultRetryConfig())
	if err != nil {
		return nil, fmt.Errorf("anubis request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anubis returned status %s", resp.Status)
	}

	var subdomains []string
	if err := json.NewDecoder(resp.Body).Decode(&subdomains); err != nil {
		return nil, fmt.Errorf("failed to decode anubis JSON: %w", err)
	}

	seen := make(map[string]bool)
	var results []models.RawResult

	for _, sub := range subdomains {
		clean := strings.TrimSpace(strings.ToLower(sub))
		clean = strings.TrimPrefix(clean, "*.")
		clean = strings.TrimPrefix(clean, ".")

		if clean == "" || seen[clean] {
			continue
		}

		// Scope enforcement
		if clean != targetDomain && !strings.HasSuffix(clean, "."+targetDomain) {
			continue
		}

		seen[clean] = true
		results = append(results, models.RawResult{
			Source:     "anubis",
			Value:      clean,
			Type:       models.AssetTypeSubdomain,
			Confidence: 0.85,
		})
	}

	return results, nil
}
