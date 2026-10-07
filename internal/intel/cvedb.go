package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"reconx/internal/providers"
	"reconx/pkg/models"
)

// maxCVELookups caps CVEDB requests per scan. Old, unpatched servers can carry
// hundreds of version-matched CVE IDs; past the cap the rest stay unenriched.
const maxCVELookups = 300

// cveCache shares CVE records across scans in the same process (the dashboard
// runs many); CVE metadata changes slowly, EPSS at most daily.
var cveCache = providers.NewMemo[*models.CVERef](12 * time.Hour)

// CVEDB queries Shodan's free CVE database (https://cvedb.shodan.io) for the
// CVSS, EPSS score and CISA KEV status of CVE IDs. No key is needed and the
// target is never contacted.
type CVEDB struct {
	client      *http.Client
	baseURL     string
	concurrency int
}

type cvedbResponse struct {
	CVEID       string   `json:"cve_id"`
	Summary     string   `json:"summary"`
	CVSS        *float64 `json:"cvss"`
	CVSSVersion *float64 `json:"cvss_version"`
	EPSS        *float64 `json:"epss"`
	RankingEPSS *float64 `json:"ranking_epss"`
	KEV         bool     `json:"kev"`
	Ransomware  *string  `json:"ransomware_campaign"`
	Published   string   `json:"published_time"`
}

// NewCVEDB creates a CVEDB client.
func NewCVEDB(timeout time.Duration) *CVEDB {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &CVEDB{
		client:      &http.Client{Timeout: timeout},
		baseURL:     "https://cvedb.shodan.io/cve/",
		concurrency: 5,
	}
}

// LookupBatch fetches each unique CVE ID (up to maxCVELookups) with bounded
// concurrency. IDs CVEDB does not know are absent from the result. The error
// summarises failures and skipped IDs; it never aborts the batch.
func (c *CVEDB) LookupBatch(ctx context.Context, ids []string) (map[string]*models.CVERef, error) {
	ids = dedupe(ids)
	sort.Strings(ids)
	skipped := 0
	if len(ids) > maxCVELookups {
		skipped = len(ids) - maxCVELookups
		ids = ids[:maxCVELookups]
	}

	out := map[string]*models.CVERef{}
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		failed   int
		firstErr error
	)
	sem := make(chan struct{}, c.concurrency)
	for _, id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			ref, err := c.Lookup(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				failed++
				if firstErr == nil {
					firstErr = err
				}
			case ref != nil:
				out[id] = ref
			}
		}(id)
	}
	wg.Wait()

	var notes []string
	if failed > 0 {
		notes = append(notes, fmt.Sprintf("%d lookup(s) failed: %v", failed, firstErr))
	}
	if skipped > 0 {
		notes = append(notes, fmt.Sprintf("%d CVE(s) over the %d-lookup cap left unenriched", skipped, maxCVELookups))
	}
	if len(notes) > 0 {
		return out, fmt.Errorf("%s", strings.Join(notes, "; "))
	}
	return out, nil
}

// Lookup returns the CVEDB record for one CVE ID, or nil (and no error) when
// CVEDB has no record of it.
func (c *CVEDB) Lookup(ctx context.Context, id string) (*models.CVERef, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	return cveCache.Get(ctx, c.baseURL+id, func(ctx context.Context) (*models.CVERef, error) {
		return c.fetch(ctx, id)
	})
}

func (c *CVEDB) fetch(ctx context.Context, id string) (*models.CVERef, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cvedb request: %w", err)
	}
	req.Header.Set("User-Agent", "ReconX/1.0 (+https://github.com/reconx/reconx)")
	req.Header.Set("Accept", "application/json")

	resp, err := providers.DoWithRetry(ctx, c.client, req, providers.DefaultRetryConfig())
	if err != nil {
		return nil, fmt.Errorf("cvedb request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cvedb returned status %s for %s", resp.Status, id)
	}

	var d cvedbResponse
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("failed to decode cvedb JSON for %s: %w", id, err)
	}
	ref := &models.CVERef{
		ID: id, Enriched: true, KEV: d.KEV,
		CVSS: deref(d.CVSS), CVSSVersion: deref(d.CVSSVersion),
		EPSS: deref(d.EPSS), EPSSPercentile: deref(d.RankingEPSS),
		Published: d.Published, Summary: truncate(d.Summary, 240),
	}
	if d.Ransomware != nil {
		ref.Ransomware = *d.Ransomware
	}
	if len(ref.Published) >= 10 {
		ref.Published = ref.Published[:10]
	}
	return ref, nil
}

// ApplyCVEDetails copies CVEDB data onto every IP's CVE list and orders each
// list for triage: KEV-listed first, then by EPSS, then by CVSS.
func ApplyCVEDetails(ips []models.IPInfo, details map[string]*models.CVERef) {
	for i := range ips {
		e := ips[i].Exposure
		if e == nil {
			continue
		}
		for j, v := range e.Vulns {
			if d := details[v.ID]; d != nil {
				e.Vulns[j] = *d
			}
		}
		sort.SliceStable(e.Vulns, func(a, b int) bool {
			x, y := e.Vulns[a], e.Vulns[b]
			if x.KEV != y.KEV {
				return x.KEV
			}
			if x.EPSS != y.EPSS {
				return x.EPSS > y.EPSS
			}
			if x.CVSS != y.CVSS {
				return x.CVSS > y.CVSS
			}
			return x.ID < y.ID
		})
	}
}

// exposureCVEIDs lists every CVE ID reported across the IPs.
func exposureCVEIDs(ips []models.IPInfo) []string {
	var ids []string
	for _, ip := range ips {
		if ip.Exposure == nil {
			continue
		}
		for _, v := range ip.Exposure.Vulns {
			ids = append(ids, v.ID)
		}
	}
	return dedupe(ids)
}

func deref(f *float64) float64 {
	if f == nil {
		return 0
	}
	return *f
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
