package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"reconx/internal/providers"
)

// RIPEstat queries the RIPE NCC's public RIPEstat Data API
// (https://stat.ripe.net) for BGP routing facts about an IP: origin ASN and
// holder, announced prefix, registry (RIR) and the origin's upstream
// neighbours. It is keyless and BGP-collector derived, which makes it an
// independent cross-check for Team Cymru's IP-to-ASN mapping. (It replaces
// BGPView, whose API was shut down.) The target is never contacted.
type RIPEstat struct {
	client      *http.Client
	baseURL     string
	concurrency int
	maxUpstream int
	upstreams   *providers.Memo[[]string] // per ASN; concurrent IPs share one fetch
}

// RoutingInfo is RIPEstat's view of an IP.
type RoutingInfo struct {
	IP        string
	ASNs      []string // origin ASNs, digits only; >1 means multi-origin (MOAS)
	Holder    string
	Prefix    string
	Announced bool
	RIR       string
	Upstreams []string // "AS174"…, strongest first
}

// NewRIPEstat creates a RIPEstat client.
func NewRIPEstat(timeout time.Duration) *RIPEstat {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &RIPEstat{
		client:      &http.Client{Timeout: timeout},
		baseURL:     "https://stat.ripe.net/data/",
		concurrency: 4, // RIPEstat asks clients to keep parallelism modest
		maxUpstream: 5,
		upstreams:   providers.NewMemo[[]string](time.Hour),
	}
}

// LookupBatch looks up every public IP with bounded concurrency. The error
// summarises failed lookups; successful ones are always returned.
func (r *RIPEstat) LookupBatch(ctx context.Context, ips []string) (map[string]*RoutingInfo, error) {
	out := map[string]*RoutingInfo{}
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		failed   int
		firstErr error
	)
	seen := map[string]bool{}
	sem := make(chan struct{}, r.concurrency)
	for _, ip := range ips {
		p := net.ParseIP(ip)
		if p == nil || !p.IsGlobalUnicast() || p.IsPrivate() || seen[ip] {
			continue
		}
		seen[ip] = true
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			info, err := r.Lookup(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			out[ip] = info
		}(ip)
	}
	wg.Wait()
	if failed > 0 {
		return out, fmt.Errorf("%d lookup(s) failed: %w", failed, firstErr)
	}
	return out, nil
}

// Lookup returns the routing view of one IP. The prefix lookup is required;
// RIR and upstreams are best-effort extras.
func (r *RIPEstat) Lookup(ctx context.Context, ip string) (*RoutingInfo, error) {
	var po struct {
		Announced bool   `json:"announced"`
		Resource  string `json:"resource"`
		ASNs      []struct {
			ASN    int64  `json:"asn"`
			Holder string `json:"holder"`
		} `json:"asns"`
	}
	if err := r.call(ctx, "prefix-overview", ip, &po); err != nil {
		return nil, err
	}
	info := &RoutingInfo{IP: ip, Prefix: po.Resource, Announced: po.Announced}
	for _, a := range po.ASNs {
		info.ASNs = append(info.ASNs, strconv.FormatInt(a.ASN, 10))
		if info.Holder == "" {
			info.Holder = a.Holder
		}
	}

	var rir struct {
		RIRs []struct {
			RIR string `json:"rir"`
		} `json:"rirs"`
	}
	if r.call(ctx, "rir", ip, &rir) == nil && len(rir.RIRs) > 0 {
		info.RIR = strings.ToUpper(rir.RIRs[0].RIR)
	}

	if len(info.ASNs) > 0 {
		info.Upstreams = r.upstreamsOf(ctx, info.ASNs[0])
	}
	return info, nil
}

// upstreamsOf returns the strongest "left" neighbours of an ASN — the
// networks that appear before it in observed AS paths (transit or peers).
// Cached per ASN, since many IPs usually share one origin. Best-effort.
func (r *RIPEstat) upstreamsOf(ctx context.Context, asn string) []string {
	ups, _ := r.upstreams.Get(ctx, asn, func(ctx context.Context) ([]string, error) {
		return r.fetchUpstreams(ctx, asn)
	})
	return ups
}

func (r *RIPEstat) fetchUpstreams(ctx context.Context, asn string) ([]string, error) {
	var nb struct {
		Neighbours []struct {
			ASN   int64   `json:"asn"`
			Type  string  `json:"type"`
			Power float64 `json:"power"`
		} `json:"neighbours"`
	}
	if err := r.call(ctx, "asn-neighbours", "AS"+asn, &nb); err != nil {
		return nil, err // not cached: a later IP may retry
	}
	left := nb.Neighbours[:0]
	for _, n := range nb.Neighbours {
		if n.Type == "left" {
			left = append(left, n)
		}
	}
	sort.SliceStable(left, func(i, j int) bool { return left[i].Power > left[j].Power })
	ups := []string{}
	for i := 0; i < len(left) && i < r.maxUpstream; i++ {
		ups = append(ups, "AS"+strconv.FormatInt(left[i].ASN, 10))
	}
	return ups, nil
}

// call fetches one RIPEstat data call and decodes its "data" member.
func (r *RIPEstat) call(ctx context.Context, name, resource string, into any) error {
	q := url.Values{"resource": {resource}, "sourceapp": {"reconx"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+name+"/data.json?"+q.Encode(), nil)
	if err != nil {
		return fmt.Errorf("failed to create ripestat request: %w", err)
	}
	req.Header.Set("User-Agent", "ReconX/1.0 (+https://github.com/reconx/reconx)")
	req.Header.Set("Accept", "application/json")

	resp, err := providers.DoWithRetry(ctx, r.client, req, providers.DefaultRetryConfig())
	if err != nil {
		return fmt.Errorf("ripestat %s request failed: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ripestat %s returned status %s for %s", name, resp.Status, resource)
	}

	var env struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("failed to decode ripestat %s JSON: %w", name, err)
	}
	if env.Status != "ok" {
		return fmt.Errorf("ripestat %s returned status %q for %s", name, env.Status, resource)
	}
	if err := json.Unmarshal(env.Data, into); err != nil {
		return fmt.Errorf("failed to decode ripestat %s data: %w", name, err)
	}
	return nil
}
