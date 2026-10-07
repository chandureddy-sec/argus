package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"reconx/internal/providers"
	"reconx/pkg/models"
)

// InternetDB queries Shodan's free InternetDB (https://internetdb.shodan.io),
// which serves the open ports, CPEs, hostnames, tags and CVE IDs from Shodan's
// own most recent crawl of an IP. No key is needed and nothing is sent to the
// target: this is a lookup of third-party crawl data, so it is passive.
type InternetDB struct {
	client      *http.Client
	baseURL     string
	concurrency int
}

type internetDBResponse struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	CPEs      []string `json:"cpes"`
	Hostnames []string `json:"hostnames"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
}

// NewInternetDB creates an InternetDB client.
func NewInternetDB(timeout time.Duration) *InternetDB {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &InternetDB{
		client:      &http.Client{Timeout: timeout},
		baseURL:     "https://internetdb.shodan.io/",
		concurrency: 5,
	}
}

// LookupBatch looks up each unique, publicly routable IP with bounded
// concurrency. IPs Shodan has never indexed (HTTP 404) are simply absent from
// the result. The error summarises failed lookups; it never aborts the batch,
// so callers keep whatever succeeded.
func (d *InternetDB) LookupBatch(ctx context.Context, ips []string) (map[string]*models.IPExposure, error) {
	out := map[string]*models.IPExposure{}
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		failed   int
		firstErr error
	)
	sem := make(chan struct{}, d.concurrency)
	for _, ip := range dedupe(ips) {
		if !publicIP(ip) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			exp, err := d.Lookup(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				failed++
				if firstErr == nil {
					firstErr = err
				}
			case exp != nil:
				out[ip] = exp
			}
		}(ip)
	}
	wg.Wait()
	if failed > 0 {
		return out, fmt.Errorf("%d lookup(s) failed: %w", failed, firstErr)
	}
	return out, nil
}

// Lookup returns Shodan's exposure data for one IP, or nil (and no error) when
// the IP is not in the index.
func (d *InternetDB) Lookup(ctx context.Context, ip string) (*models.IPExposure, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.baseURL+ip, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create internetdb request: %w", err)
	}
	req.Header.Set("User-Agent", "ReconX/1.0 (+https://github.com/reconx/reconx)")
	req.Header.Set("Accept", "application/json")

	resp, err := providers.DoWithRetry(ctx, d.client, req, providers.DefaultRetryConfig())
	if err != nil {
		return nil, fmt.Errorf("internetdb request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // "No information available" — not indexed
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("internetdb returned status %s for %s", resp.Status, ip)
	}

	var data internetDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode internetdb JSON for %s: %w", ip, err)
	}
	exp := &models.IPExposure{
		Ports:     data.Ports,
		CPEs:      data.CPEs,
		Hostnames: data.Hostnames,
		Tags:      data.Tags,
	}
	sort.Ints(exp.Ports)
	ids := make([]string, 0, len(data.Vulns))
	for _, id := range data.Vulns {
		ids = append(ids, strings.ToUpper(strings.TrimSpace(id)))
	}
	ids = dedupe(ids)
	sort.Strings(ids)
	for _, id := range ids {
		exp.Vulns = append(exp.Vulns, models.CVERef{ID: id})
	}
	return exp, nil
}

// publicIP reports whether ip is a globally routable unicast address. Private,
// loopback, link-local and documentation ranges carry no public crawl data.
func publicIP(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsGlobalUnicast() && !p.IsPrivate()
}
