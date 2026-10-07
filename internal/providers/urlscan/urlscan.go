package urlscan

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"reconx/internal/providers"
	"reconx/pkg/models"
)

// APIKeyEnv optionally holds a urlscan.io API key. Search works without one;
// a key raises the rate limits and unlocks per-scan technology detection.
const APIKeyEnv = "RECONX_URLSCAN_API_KEY"

const (
	pageSize = 100
	maxPages = 3 // 300 most recent scans
	// pageDelay keeps anonymous search under its 30 requests/minute limit.
	pageDelay = 2500 * time.Millisecond
	// maxTechLookups caps result-API calls (keyed only), spaced by techDelay so
	// they fit inside the subdomain stage's time budget.
	maxTechLookups = 10
	techDelay      = 1 * time.Second
)

// Provider searches urlscan.io's public scan archive. Every scan in it was
// submitted by a third party, so reading the archive is passive: the target
// is never contacted by ReconX.
type Provider struct {
	client    *http.Client
	baseURL   string
	apiKey    string
	pageDelay time.Duration
	techDelay time.Duration
	rateLimit time.Duration
}

var _ providers.Provider = (*Provider)(nil)

// NewProvider creates a urlscan.io provider, reading the optional API key
// from RECONX_URLSCAN_API_KEY.
func NewProvider(timeout time.Duration) *Provider {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &Provider{
		client:    &http.Client{Timeout: timeout},
		baseURL:   "https://urlscan.io/api/v1/",
		apiKey:    strings.TrimSpace(os.Getenv(APIKeyEnv)),
		pageDelay: pageDelay,
		techDelay: techDelay,
		rateLimit: 2 * time.Second,
	}
}

func (p *Provider) Name() string {
	return "urlscan"
}

func (p *Provider) Supports(t models.Target) bool {
	return t.Type == models.TargetTypeDomain
}

func (p *Provider) RateLimit() time.Duration {
	return p.rateLimit
}

// Scan is the latest archived urlscan.io observation of one hostname.
type Scan struct {
	Host         string
	URL          string
	Title        string
	Server       string
	Status       string
	IP           string
	ASN          string
	ASNName      string
	TLSIssuer    string
	Screenshot   string // urlscan-hosted PNG; stored as a link, never downloaded
	ScanURL      string // human-readable result page
	UUID         string
	Time         time.Time
	FirstSeen    time.Time
	Scans        int
	Technologies []string

	detailAt *time.Time // scan time the page details came from
}

type searchResponse struct {
	Results []searchResult `json:"results"`
	Total   int            `json:"total"`
	HasMore bool           `json:"has_more"`
}

type searchResult struct {
	ID   string            `json:"_id"`
	Sort []json.RawMessage `json:"sort"`
	Task struct {
		Domain string `json:"domain"`
		URL    string `json:"url"`
		Time   string `json:"time"`
	} `json:"task"`
	Page struct {
		Domain    string `json:"domain"`
		URL       string `json:"url"`
		Title     string `json:"title"`
		Server    string `json:"server"`
		Status    string `json:"status"`
		IP        string `json:"ip"`
		ASN       string `json:"asn"`
		ASNName   string `json:"asnname"`
		TLSIssuer string `json:"tlsIssuer"`
	} `json:"page"`
	Screenshot string `json:"screenshot"`
}

func (p *Provider) Collect(ctx context.Context, t models.Target) ([]models.RawResult, error) {
	if !p.Supports(t) {
		return nil, fmt.Errorf("urlscan provider does not support target type %s", t.Type)
	}
	scans, err := p.Fetch(ctx, t.Value)
	if err != nil && len(scans) == 0 {
		return nil, err
	}
	if err != nil {
		slog.Warn("urlscan returned partial results", slog.Int("hosts", len(scans)), slog.String("error", err.Error()))
	}

	results := make([]models.RawResult, 0, len(scans))
	for _, s := range scans {
		meta := map[string]string{
			"first_seen":  s.FirstSeen.Format(time.RFC3339),
			"last_seen":   s.Time.Format(time.RFC3339),
			"ip":          s.IP,
			"url":         s.URL,
			"title":       s.Title,
			"server":      s.Server,
			"http_status": s.Status,
			"asn":         strings.TrimSpace(s.ASN + " " + s.ASNName),
			"tls_issuer":  s.TLSIssuer,
			"screenshot":  s.Screenshot,
			"scan_url":    s.ScanURL,
			"scans":       strconv.Itoa(s.Scans),
		}
		if len(s.Technologies) > 0 {
			meta["technologies"] = strings.Join(s.Technologies, ", ")
		}
		for k, v := range meta {
			if v == "" {
				delete(meta, k)
			}
		}
		results = append(results, models.RawResult{
			Source:     "urlscan",
			Value:      s.Host,
			Type:       models.AssetTypeSubdomain,
			Confidence: 0.85,
			Metadata:   meta,
		})
	}
	// A partial fetch (e.g. page 3 rate limited) still yields usable results.
	return results, nil
}

// Fetch pages through urlscan.io's search for the domain and returns the
// latest scan per in-scope hostname, newest first.
func (p *Provider) Fetch(ctx context.Context, domain string) ([]Scan, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	byHost := map[string]*Scan{}
	var searchAfter string
	var fetchErr error

	for page := 0; page < maxPages; page++ {
		if page > 0 {
			if err := sleep(ctx, p.pageDelay); err != nil {
				fetchErr = err
				break
			}
		}
		resp, err := p.search(ctx, domain, searchAfter)
		if err != nil {
			fetchErr = err
			break
		}
		for _, r := range resp.Results {
			p.absorb(byHost, domain, r)
		}
		if !resp.HasMore || len(resp.Results) == 0 {
			break
		}
		searchAfter = sortKey(resp.Results[len(resp.Results)-1].Sort)
		if searchAfter == "" {
			break
		}
	}

	scans := make([]Scan, 0, len(byHost))
	for _, s := range byHost {
		scans = append(scans, *s)
	}
	sort.Slice(scans, func(i, j int) bool {
		if !scans[i].Time.Equal(scans[j].Time) {
			return scans[i].Time.After(scans[j].Time)
		}
		return scans[i].Host < scans[j].Host
	})

	if p.apiKey != "" {
		p.addTechnologies(ctx, scans)
	}
	return scans, fetchErr
}

// absorb folds one search hit into the per-host map. Both the submitted URL's
// host and the final page host count as observations when in scope; page
// details come from the newest scan whose page was served by that host.
func (p *Provider) absorb(byHost map[string]*Scan, domain string, r searchResult) {
	ts, _ := time.Parse(time.RFC3339Nano, r.Task.Time)
	pageHost := cleanHost(r.Page.Domain)
	hosts := []string{cleanHost(r.Task.Domain)}
	if pageHost != hosts[0] {
		hosts = append(hosts, pageHost)
	}
	for _, h := range hosts {
		if h == "" || (h != domain && !strings.HasSuffix(h, "."+domain)) {
			continue
		}
		s := byHost[h]
		if s == nil {
			s = &Scan{Host: h}
			byHost[h] = s
		}
		s.Scans++
		if s.FirstSeen.IsZero() || ts.Before(s.FirstSeen) {
			s.FirstSeen = ts
		}
		if ts.After(s.Time) {
			s.Time = ts
		}
		if h != pageHost || (s.detailAt != nil && !ts.After(*s.detailAt)) {
			continue
		}
		s.detailAt = &ts
		s.URL, s.Title, s.Server, s.Status = r.Page.URL, r.Page.Title, r.Page.Server, r.Page.Status
		s.IP, s.ASN, s.ASNName, s.TLSIssuer = r.Page.IP, r.Page.ASN, r.Page.ASNName, r.Page.TLSIssuer
		s.Screenshot, s.UUID, s.ScanURL = r.Screenshot, r.ID, ""
		if r.ID != "" {
			s.ScanURL = "https://urlscan.io/result/" + r.ID + "/"
		}
	}
}

func (p *Provider) search(ctx context.Context, domain, searchAfter string) (*searchResponse, error) {
	q := url.Values{}
	q.Set("q", "domain:"+domain)
	q.Set("size", strconv.Itoa(pageSize))
	if searchAfter != "" {
		q.Set("search_after", searchAfter)
	}
	var data searchResponse
	if err := p.getJSON(ctx, p.baseURL+"search/?"+q.Encode(), &data); err != nil {
		return nil, err
	}
	return &data, nil
}

type resultResponse struct {
	Meta struct {
		Processors struct {
			Wappa struct {
				Data []struct {
					App string `json:"app"`
				} `json:"data"`
			} `json:"wappa"`
		} `json:"processors"`
	} `json:"meta"`
}

// addTechnologies fetches Wappalyzer detections for the newest scans. The
// result API requires a key; failures leave the host without technologies.
func (p *Provider) addTechnologies(ctx context.Context, scans []Scan) {
	done := 0
	for i := range scans {
		if done == maxTechLookups || ctx.Err() != nil {
			return
		}
		if scans[i].UUID == "" {
			continue
		}
		if done > 0 {
			if sleep(ctx, p.techDelay) != nil {
				return
			}
		}
		done++
		var r resultResponse
		if err := p.getJSON(ctx, p.baseURL+"result/"+scans[i].UUID+"/", &r); err != nil {
			continue
		}
		seen := map[string]bool{}
		for _, d := range r.Meta.Processors.Wappa.Data {
			if d.App != "" && !seen[d.App] {
				seen[d.App] = true
				scans[i].Technologies = append(scans[i].Technologies, d.App)
			}
		}
	}
}

func (p *Provider) getJSON(ctx context.Context, u string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("failed to create urlscan request: %w", err)
	}
	req.Header.Set("User-Agent", "ReconX/1.0 (+https://github.com/reconx/reconx)")
	req.Header.Set("Accept", "application/json")
	if p.apiKey != "" {
		req.Header.Set("API-Key", p.apiKey)
	}

	resp, err := providers.DoWithRetry(ctx, p.client, req, providers.DefaultRetryConfig())
	if err != nil {
		return fmt.Errorf("urlscan request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("urlscan returned status %s", resp.Status)
		if resp.StatusCode == http.StatusTooManyRequests {
			if ra := resp.Header.Get("X-Rate-Limit-Reset-After"); ra != "" {
				msg += " (rate limited; resets in " + ra + "s)"
			}
		}
		return fmt.Errorf("%s", msg)
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return fmt.Errorf("failed to decode urlscan JSON: %w", err)
	}
	return nil
}

// sortKey turns a hit's sort values into urlscan's search_after cursor,
// e.g. [1791349560787,"01a1…"] -> "1791349560787,01a1…".
func sortKey(vals []json.RawMessage) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		var s string
		if json.Unmarshal(v, &s) == nil {
			parts = append(parts, s)
			continue
		}
		parts = append(parts, strings.TrimSpace(string(v)))
	}
	return strings.Join(parts, ",")
}

func cleanHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
