// Package threatlens links a scan to a ThreatLens threat-intelligence server
// (threatlens/ in this repository): the scan's hosts and IPs are sent to its
// bulk enrichment API (POST /api/v1/enrich), and each comes back with a
// verdict, score, evidence and recommended action.
//
// The contract is the HTTP API only (ADR 0002 in threatlens/docs/adr). The
// server decides which third parties see the values, within the TLP sent with
// them (TLP:GREEN by default: no provider that publishes lookups).
package threatlens

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"reconx/pkg/models"
)

// Environment variables. The key can also be stored with `reconx keys set threatlens`.
const (
	EnvURL = "RECONX_THREATLENS_URL"
	EnvKey = "RECONX_THREATLENS_API_KEY"
)

// BatchSize matches ThreatLens's default per-request limit (TL_ENRICH_BULK_MAX).
const BatchSize = 100

// TLPs ThreatLens accepts.
var TLPs = []string{"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"}

// ErrNotConfigured means no server URL or no API key is available.
var ErrNotConfigured = errors.New("ThreatLens is not configured")

// Config says where the server is and how to use it.
type Config struct {
	URL    string // e.g. http://127.0.0.1:8000
	Key    string // analyst API key (tl_…)
	TLP    string // TLP of the scan's values; default TLP:GREEN
	Budget int    // metered provider calls per batch; 0 = server default
	Limit  int    // max values sent; 0 = 500
}

// FromEnv fills URL and key from the environment where they are empty.
func (c Config) FromEnv() Config {
	if c.URL == "" {
		c.URL = os.Getenv(EnvURL)
	}
	if c.Key == "" {
		c.Key = os.Getenv(EnvKey)
	}
	return c
}

// Configured reports whether both the URL and key are set.
func (c Config) Configured() bool { return c.URL != "" && c.Key != "" }

// Validate checks the URL and TLP.
func (c Config) Validate() error {
	if !c.Configured() {
		return fmt.Errorf("%w: set --threatlens <url> (or %s) and an API key (%s, or `reconx keys set threatlens`)", ErrNotConfigured, EnvURL, EnvKey)
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("ThreatLens URL must be http(s)://host[:port], got %q", c.URL)
	}
	if c.TLP != "" && !validTLP(c.TLP) {
		return fmt.Errorf("unknown TLP %q (use one of %s)", c.TLP, strings.Join(TLPs, ", "))
	}
	return nil
}

func validTLP(t string) bool {
	for _, x := range TLPs {
		if x == t {
			return true
		}
	}
	return false
}

// Client talks to one ThreatLens server.
type Client struct {
	cfg  Config
	http *http.Client
}

// New returns a client; Validate the config first.
func New(cfg Config) *Client {
	if cfg.TLP == "" {
		cfg.TLP = "TLP:GREEN"
	}
	if cfg.Limit <= 0 {
		cfg.Limit = 500
	}
	// Bulk enrichment calls third parties on the server side: allow it time.
	return &Client{cfg: cfg, http: &http.Client{Timeout: 3 * time.Minute}}
}

// ── wire format (ThreatLens /api/v1/enrich) ─────────────────────────────────

type enrichIn struct {
	Indicators []string `json:"indicators"`
	TLP        string   `json:"tlp"`
	Budget     *int     `json:"budget,omitempty"`
}

type evidenceOut struct {
	Source string  `json:"source"`
	Kind   string  `json:"kind"`
	Weight int     `json:"weight"`
	Text   string  `json:"text"`
	Ref    *string `json:"ref"`
}

type lookupOut struct {
	Query struct {
		Type     string `json:"type"`
		Value    string `json:"value"`
		Defanged string `json:"defanged"`
	} `json:"query"`
	Verdict    string `json:"verdict"`
	Score      int    `json:"score"`
	Action     string `json:"recommended_action"`
	ActionText string `json:"recommended_action_text"`
	Known      *struct {
		Sources []string `json:"sources"`
	} `json:"known"`
	Evidence []evidenceOut `json:"evidence"`
	Related  []struct {
		Type  string `json:"type"`
		Label string `json:"label"`
	} `json:"related"`
	Enrichments []struct {
		Enricher      string  `json:"enricher"`
		Status        string  `json:"status"`
		SkippedReason *string `json:"skipped_reason"`
		Error         *string `json:"error"`
	} `json:"enrichments"`
	Partial bool `json:"partial"`
}

type enrichOut struct {
	Results  []lookupOut `json:"results"`
	Rejected []struct {
		Value  string `json:"value"`
		Reason string `json:"reason"`
	} `json:"rejected"`
	Counts      map[string]int `json:"counts"`
	BudgetSpent int            `json:"budget_spent"`
}

// Enrich sends values in batches and returns the combined result. A failure
// part-way returns what was collected, with Status "partial" and the error.
func (c *Client) Enrich(ctx context.Context, values []string) *models.ThreatIntel {
	out := &models.ThreatIntel{
		Server:    strings.TrimRight(c.cfg.URL, "/"),
		CheckedAt: time.Now().UTC(),
		TLP:       c.cfg.TLP,
		Status:    "ok",
		Counts:    map[string]int{"malicious": 0, "suspicious": 0, "benign": 0, "unknown": 0},
	}
	values = dedupe(values)
	if len(values) > c.cfg.Limit {
		values = values[:c.cfg.Limit]
	}
	for start := 0; start < len(values); start += BatchSize {
		end := min(start+BatchSize, len(values))
		res, err := c.post(ctx, values[start:end])
		if err != nil {
			out.Error = err.Error()
			out.Status = "error"
			if len(out.Items) > 0 {
				out.Status = "partial"
			}
			break
		}
		out.BudgetSpent += res.BudgetSpent
		for _, r := range res.Rejected {
			out.Rejected = append(out.Rejected, models.ThreatRejected{Value: r.Value, Reason: r.Reason})
		}
		for _, r := range res.Results {
			v := convert(r)
			out.Items = append(out.Items, v)
			out.Counts[v.Verdict]++
			if v.Partial && out.Status == "ok" {
				out.Status = "partial"
			}
		}
	}
	sortVerdicts(out.Items)
	return out
}

func (c *Client) post(ctx context.Context, batch []string) (*enrichOut, error) {
	in := enrichIn{Indicators: batch, TLP: c.cfg.TLP}
	if c.cfg.Budget > 0 {
		b := c.cfg.Budget
		in.Budget = &b
	}
	body, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(c.cfg.URL, "/") + "/api/v1/enrich"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-Key", c.cfg.Key)
	req.Header.Set("User-Agent", "ReconX (ThreatLens link)")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ThreatLens unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("reading ThreatLens answer: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, errors.New("ThreatLens rejected the API key (401)")
	case resp.StatusCode == http.StatusForbidden:
		return nil, errors.New("ThreatLens API key lacks the analyst role (403)")
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, errors.New("ThreatLens rate limit reached (429); try again in a minute")
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("ThreatLens answered HTTP %d: %s", resp.StatusCode, snippet(raw))
	}
	var out enrichOut
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("unexpected ThreatLens answer: %w", err)
	}
	return &out, nil
}

func convert(r lookupOut) models.ThreatVerdict {
	v := models.ThreatVerdict{
		Value:      r.Query.Value,
		Type:       r.Query.Type,
		Defanged:   r.Query.Defanged,
		Verdict:    r.Verdict,
		Score:      r.Score,
		Action:     r.Action,
		ActionText: r.ActionText,
		Partial:    r.Partial,
	}
	if r.Known != nil {
		v.KnownSources = r.Known.Sources
	}
	for i, e := range r.Evidence {
		if i == 8 {
			break
		}
		ev := models.ThreatEvidence{Source: e.Source, Kind: e.Kind, Weight: e.Weight, Text: e.Text}
		if e.Ref != nil {
			ev.Ref = *e.Ref
		}
		v.Evidence = append(v.Evidence, ev)
	}
	for _, rel := range r.Related {
		if rel.Type == "malware" || rel.Type == "intrusion-set" || rel.Type == "campaign" || rel.Type == "tool" {
			v.Related = append(v.Related, rel.Type+" "+rel.Label)
		}
	}
	for _, e := range r.Enrichments {
		switch {
		case e.SkippedReason != nil && *e.SkippedReason != "active_not_requested":
			v.Skipped = append(v.Skipped, e.Enricher+": "+*e.SkippedReason)
		case e.Error != nil:
			v.Skipped = append(v.Skipped, e.Enricher+": error")
		}
	}
	return v
}

var verdictRank = map[string]int{"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3}

func sortVerdicts(items []models.ThreatVerdict) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if verdictRank[a.Verdict] != verdictRank[b.Verdict] {
			return verdictRank[a.Verdict] < verdictRank[b.Verdict]
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.Value < b.Value
	})
}

func dedupe(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// Values picks what a scan sends: the target, every host that currently
// resolves, and every IP, in that order. Hosts that no longer resolve are
// left out: ThreatLens would only look up registration data for them.
func Values(report *models.ScanReport) []string {
	var out []string
	if t := report.Target; t != nil {
		switch t.Type {
		case models.TargetTypeDomain, models.TargetTypeIPv4, models.TargetTypeIPv6:
			out = append(out, t.Value)
		}
	}
	if report.Intel == nil {
		return out
	}
	for _, h := range report.Intel.Hosts {
		if h.DNSStatus == "resolves" {
			out = append(out, h.Hostname)
		}
	}
	for _, ip := range report.Intel.IPs {
		out = append(out, ip.IP)
	}
	return dedupe(out)
}

// Flagged returns the malicious and suspicious verdicts, worst first.
func Flagged(ti *models.ThreatIntel) []models.ThreatVerdict {
	if ti == nil {
		return nil
	}
	var out []models.ThreatVerdict
	for _, v := range ti.Items {
		if v.Flagged() {
			out = append(out, v)
		}
	}
	return out
}

// ImportResult is ThreatLens's answer to an asset import.
type ImportResult struct {
	ImportID      int  `json:"import_id"`
	Duplicate     bool `json:"duplicate"`
	Hosts         int  `json:"hosts"`
	IPs           int  `json:"ips"`
	Products      int  `json:"products"`
	NewAssets     int  `json:"new_assets"`
	UpdatedAssets int  `json:"updated_assets"`
	Rejected      []struct {
		Value  string `json:"value"`
		Reason string `json:"reason"`
	} `json:"rejected"`
}

// ImportAssets sends the whole scan report to ThreatLens as the
// organization's own assets (POST /api/v1/assets/import/reconx). Only scans
// of your own targets should be imported.
func (c *Client) ImportAssets(ctx context.Context, report *models.ScanReport) (*ImportResult, error) {
	body, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(c.cfg.URL, "/") + "/api/v1/assets/import/reconx"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.cfg.Key)
	req.Header.Set("User-Agent", "ReconX (ThreatLens link)")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ThreatLens unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, errors.New("ThreatLens rejected the API key (401)")
	case http.StatusForbidden:
		return nil, errors.New("ThreatLens API key lacks the analyst role (403)")
	default:
		return nil, fmt.Errorf("ThreatLens answered HTTP %d: %s", resp.StatusCode, snippet(raw))
	}
	var out ImportResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("unexpected ThreatLens answer: %w", err)
	}
	return &out, nil
}
