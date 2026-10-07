package certspotter

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"reconx/internal/providers"
	"reconx/pkg/models"
)

// APIKeyEnv optionally holds an SSLMate API key. Without one, Cert Spotter
// allows 10 include_subdomains queries per hour (each page counts as one).
const APIKeyEnv = "RECONX_CERTSPOTTER_API_KEY"

const (
	anonPages  = 2  // keep anonymous scans to a fifth of the hourly quota
	keyedPages = 10 // paid/keyed quotas are far larger
)

// Provider queries SSLMate's Cert Spotter API for certificates issued to a
// domain and its subdomains — an independent Certificate Transparency
// monitor alongside crt.sh. Passive: only SSLMate's API is contacted.
type Provider struct {
	client    *http.Client
	baseURL   string
	apiKey    string
	maxPages  int
	rateLimit time.Duration
}

var _ providers.Provider = (*Provider)(nil)

type issuance struct {
	ID        string   `json:"id"`
	DNSNames  []string `json:"dns_names"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
}

// NewProvider creates a Cert Spotter provider, reading the optional API key
// from RECONX_CERTSPOTTER_API_KEY.
func NewProvider(timeout time.Duration) *Provider {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	key := strings.TrimSpace(os.Getenv(APIKeyEnv))
	pages := anonPages
	if key != "" {
		pages = keyedPages
	}
	return &Provider{
		client:    &http.Client{Timeout: timeout},
		baseURL:   "https://api.certspotter.com/v1/issuances",
		apiKey:    key,
		maxPages:  pages,
		rateLimit: 1 * time.Second,
	}
}

func (p *Provider) Name() string {
	return "certspotter"
}

func (p *Provider) Supports(t models.Target) bool {
	return t.Type == models.TargetTypeDomain
}

func (p *Provider) RateLimit() time.Duration {
	return p.rateLimit
}

func (p *Provider) Collect(ctx context.Context, t models.Target) ([]models.RawResult, error) {
	if !p.Supports(t) {
		return nil, fmt.Errorf("certspotter provider does not support target type %s", t.Type)
	}
	targetDomain := strings.ToLower(strings.TrimSpace(t.Value))

	issuances, err := p.fetch(ctx, targetDomain)
	if err != nil && len(issuances) == 0 {
		return nil, err
	}
	if err != nil {
		slog.Warn("certspotter returned partial results", slog.Int("issuances", len(issuances)), slog.String("error", err.Error()))
	}

	// Aggregate per hostname: earliest and latest issuance dates.
	type span struct{ first, last string }
	spans := map[string]*span{}
	var order []string
	for _, is := range issuances {
		for _, name := range is.DNSNames {
			host := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "*."), "."), ".")
			if host == "" || (host != targetDomain && !strings.HasSuffix(host, "."+targetDomain)) {
				continue
			}
			s := spans[host]
			if s == nil {
				s = &span{}
				spans[host] = s
				order = append(order, host)
			}
			if is.NotBefore != "" && (s.first == "" || is.NotBefore < s.first) {
				s.first = is.NotBefore
			}
			if is.NotBefore > s.last {
				s.last = is.NotBefore
			}
		}
	}

	results := make([]models.RawResult, 0, len(order))
	for _, host := range order {
		s := spans[host]
		results = append(results, models.RawResult{
			Source:     "certspotter",
			Value:      host,
			Type:       models.AssetTypeSubdomain,
			Confidence: 0.85,
			Metadata: map[string]string{
				"first_seen": s.first,
				"last_seen":  s.last,
			},
		})
	}
	// A later page failing (usually the hourly quota) keeps earlier pages.
	return results, nil
}

// fetch follows Cert Spotter's Link: rel="next" pagination up to maxPages.
func (p *Provider) fetch(ctx context.Context, domain string) ([]issuance, error) {
	q := url.Values{}
	q.Set("domain", domain)
	q.Set("include_subdomains", "true")
	q.Add("expand", "dns_names")
	next := p.baseURL + "?" + q.Encode()

	var all []issuance
	for page := 0; page < p.maxPages && next != ""; page++ {
		batch, link, err := p.page(ctx, next)
		if err != nil {
			return all, err
		}
		all = append(all, batch...)
		if len(batch) == 0 {
			break
		}
		next = link
	}
	return all, nil
}

var nextLink = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="?next"?`)

func (p *Provider) page(ctx context.Context, u string) ([]issuance, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create certspotter request: %w", err)
	}
	req.Header.Set("User-Agent", "ReconX/1.0 (+https://github.com/reconx/reconx)")
	req.Header.Set("Accept", "application/json")
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	resp, err := providers.DoWithRetry(ctx, p.client, req, providers.DefaultRetryConfig())
	if err != nil {
		return nil, "", fmt.Errorf("certspotter request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		msg := "certspotter hourly quota exhausted (429)"
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			msg += "; resets in " + ra + "s"
		}
		if p.apiKey == "" {
			msg += "; set " + APIKeyEnv + " for a higher quota"
		}
		return nil, "", fmt.Errorf("%s", msg)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("certspotter returned status %s", resp.Status)
	}

	var batch []issuance
	if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
		return nil, "", fmt.Errorf("failed to decode certspotter JSON: %w", err)
	}
	link := ""
	if m := nextLink.FindStringSubmatch(resp.Header.Get("Link")); m != nil {
		link = resolve(u, m[1])
	}
	return batch, link, nil
}

// resolve makes a Link target absolute and keeps it on the API host/path
// prefix we called (the v1 API returns links without the /v1 segment).
func resolve(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	r = b.ResolveReference(r)
	if r.Host != b.Host {
		return ""
	}
	// Re-use the called path; only the query (the "after" cursor) changes.
	r.Path = b.Path
	return r.String()
}
