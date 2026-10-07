package githubcode

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"reconx/internal/providers"
	"reconx/pkg/models"
)

// TokenEnv holds a GitHub personal access token. Code search requires
// authentication, so without it the provider is skipped (not failed).
const TokenEnv = "RECONX_GITHUB_TOKEN"

const (
	perPage = 100
	// GitHub allows 9 code-search requests per minute even when
	// authenticated; three pages per scan leaves headroom for re-scans.
	maxPages = 3
	maxRefs  = 3 // example file links kept per hostname
)

// Provider searches public code on GitHub for the target domain and extracts
// hostnames from the matched snippets — leaked internal names, staging hosts
// and API endpoints often surface in configs and scripts. Passive: only
// GitHub's API is contacted.
type Provider struct {
	client    *http.Client
	baseURL   string
	token     string
	maxPages  int
	rateLimit time.Duration
}

var _ providers.Provider = (*Provider)(nil)

type searchResponse struct {
	TotalCount int    `json:"total_count"`
	Items      []item `json:"items"`
}

type item struct {
	HTMLURL    string `json:"html_url"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	TextMatches []struct {
		Fragment string `json:"fragment"`
	} `json:"text_matches"`
}

// NewProvider creates a GitHub code-search provider, reading the token from
// RECONX_GITHUB_TOKEN.
func NewProvider(timeout time.Duration) *Provider {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &Provider{
		client:    &http.Client{Timeout: timeout},
		baseURL:   "https://api.github.com/search/code",
		token:     strings.TrimSpace(os.Getenv(TokenEnv)),
		maxPages:  maxPages,
		rateLimit: 7 * time.Second, // ≤9/min across back-to-back scans
	}
}

func (p *Provider) Name() string {
	return "githubcode"
}

func (p *Provider) Supports(t models.Target) bool {
	return t.Type == models.TargetTypeDomain
}

func (p *Provider) RateLimit() time.Duration {
	return p.rateLimit
}

type hit struct {
	refs  []string
	repos map[string]bool
}

func (p *Provider) Collect(ctx context.Context, t models.Target) ([]models.RawResult, error) {
	if !p.Supports(t) {
		return nil, fmt.Errorf("githubcode provider does not support target type %s", t.Type)
	}
	if p.token == "" {
		return nil, fmt.Errorf("%w: set %s to enable GitHub code search", providers.ErrSkipped, TokenEnv)
	}
	domain := strings.ToLower(strings.TrimSpace(t.Value))

	hits := map[string]*hit{}
	var fetchErr error
	for page := 1; page <= p.maxPages; page++ {
		resp, more, err := p.search(ctx, domain, page)
		if err != nil {
			fetchErr = err
			break
		}
		for _, it := range resp.Items {
			for _, tm := range it.TextMatches {
				for _, h := range ExtractHosts(tm.Fragment, domain) {
					e := hits[h]
					if e == nil {
						e = &hit{repos: map[string]bool{}}
						hits[h] = e
					}
					e.repos[it.Repository.FullName] = true
					if len(e.refs) < maxRefs && !contains(e.refs, it.HTMLURL) {
						e.refs = append(e.refs, it.HTMLURL)
					}
				}
			}
		}
		if !more || page*perPage >= resp.TotalCount || len(resp.Items) < perPage {
			break
		}
	}
	if fetchErr != nil && len(hits) == 0 {
		return nil, fetchErr
	}
	if fetchErr != nil {
		slog.Warn("githubcode returned partial results", slog.Int("hosts", len(hits)), slog.String("error", fetchErr.Error()))
	}

	hosts := make([]string, 0, len(hits))
	for h := range hits {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	results := make([]models.RawResult, 0, len(hosts))
	for _, h := range hosts {
		results = append(results, models.RawResult{
			Source:     "githubcode",
			Value:      h,
			Type:       models.AssetTypeSubdomain,
			Confidence: 0.60, // a mention in code, possibly stale or a typo
			Metadata: map[string]string{
				"code_refs": strings.Join(hits[h].refs, " "),
				"repos":     strconv.Itoa(len(hits[h].repos)),
			},
		})
	}
	return results, nil
}

// search fetches one results page. more is false once the rate-limit budget
// is spent, so the caller stops before GitHub starts refusing requests.
func (p *Provider) search(ctx context.Context, domain string, page int) (*searchResponse, bool, error) {
	q := url.Values{}
	q.Set("q", `"`+domain+`"`)
	q.Set("per_page", strconv.Itoa(perPage))
	q.Set("page", strconv.Itoa(page))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create github request: %w", err)
	}
	req.Header.Set("User-Agent", "ReconX/1.0 (+https://github.com/reconx/reconx)")
	req.Header.Set("Accept", "application/vnd.github.text-match+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := providers.DoWithRetry(ctx, p.client, req, providers.DefaultRetryConfig())
	if err != nil {
		return nil, false, fmt.Errorf("github code search request failed: %w", err)
	}
	defer resp.Body.Close()

	remaining := resp.Header.Get("X-RateLimit-Remaining")
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, false, fmt.Errorf("github rejected the token in %s (401): check it is valid and not expired", TokenEnv)
	case (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) && remaining == "0":
		return nil, false, fmt.Errorf("github code search rate limit reached (resets at %s)", resetTime(resp.Header.Get("X-RateLimit-Reset")))
	case resp.StatusCode != http.StatusOK:
		return nil, false, fmt.Errorf("github code search returned status %s", resp.Status)
	}

	var data searchResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, false, fmt.Errorf("failed to decode github JSON: %w", err)
	}
	return &data, remaining != "0", nil
}

var (
	// Escaped separators in code ("https%3A%2F%2Fapi.x.com", "/api.x.com",
	// "\napi.x.com") would otherwise glue junk onto the hostname.
	escapes = strings.NewReplacer(`%2f`, " ", `%3a`, " ", `%40`, " ", `/`, " ", `\/`, " ", `\n`, " ", `\t`, " ", `\r`, " ")
	token   = regexp.MustCompile(`[a-z0-9.-]+`)
	label   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ExtractHosts returns the distinct hostnames in text that equal domain or are
// subdomains of it. Tokens are matched whole, so "notexample.com" and
// "example.com.evil.org" never count as example.com hosts.
func ExtractHosts(text, domain string) []string {
	text = escapes.Replace(strings.ToLower(text))
	var out []string
	seen := map[string]bool{}
	for _, tok := range token.FindAllString(text, -1) {
		h := strings.Trim(tok, ".-")
		if h != domain && !strings.HasSuffix(h, "."+domain) || seen[h] || !validHost(h) {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

func validHost(h string) bool {
	if len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if !label.MatchString(l) {
			return false
		}
	}
	return true
}

func resetTime(unix string) string {
	if n, err := strconv.ParseInt(unix, 10, 64); err == nil {
		return time.Unix(n, 0).UTC().Format("15:04:05 UTC")
	}
	return "unknown"
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
