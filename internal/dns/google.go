package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

// DefaultDoHEndpoint is Google Public DNS's JSON (DNS-over-HTTPS) resolver.
// It is a default, not a hardcoding: GoogleDoH takes the endpoint as a field and
// is selected via config, so other DoH endpoints can be used instead.
const DefaultDoHEndpoint = "https://dns.google/resolve"

// maxDoHBody caps a single DoH response so a hostile or broken resolver cannot
// exhaust memory (req: response-size limits).
const maxDoHBody = 256 * 1024

// GoogleDoH resolves the standard record types over a DNS-over-HTTPS JSON API.
// It implements RecordResolver and is passive: it only asks a public resolver,
// it never probes the target. The endpoint is configurable.
type GoogleDoH struct {
	endpoint string
	client   *http.Client
}

// NewGoogleDoH builds a DoH resolver. An empty endpoint uses DefaultDoHEndpoint;
// a nil client uses a timeout-bounded default.
func NewGoogleDoH(endpoint string, timeout time.Duration, client *http.Client) *GoogleDoH {
	if endpoint == "" {
		endpoint = DefaultDoHEndpoint
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &GoogleDoH{endpoint: endpoint, client: client}
}

// dohAttempts is the total number of tries per query on a transient failure.
const dohAttempts = 3

// retryableStatus reports whether an HTTP status warrants a retry (transient
// server-side / throttling conditions). 4xx client errors are left to the caller.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// do issues req with a small exponential backoff on transient network errors
// and retryable statuses, aborting promptly when ctx is cancelled. The caller
// owns closing the returned body.
func (g *GoogleDoH) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	var lastErr error
	for attempt := 1; attempt <= dohAttempts; attempt++ {
		resp, err := g.client.Do(req.Clone(ctx))
		if err == nil && !retryableStatus(resp.StatusCode) {
			return resp, nil // success or a non-retryable status
		}
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("http %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		if attempt == dohAttempts {
			break
		}
		select {
		case <-time.After(time.Duration(300*attempt) * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

// Name implements RecordResolver.
func (g *GoogleDoH) Name() string { return "google" }

// dohResponse mirrors the Google / RFC 8484 application/dns-json shape.
type dohResponse struct {
	Status int  `json:"Status"`
	TC     bool `json:"TC"`
	Answer []struct {
		Name string `json:"name"`
		Type uint16 `json:"type"`
		TTL  uint32 `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// recordTypes is the feature's set of queried record types.
var recordTypes = []uint16{
	mdns.TypeA, mdns.TypeAAAA, mdns.TypeCNAME, mdns.TypeMX,
	mdns.TypeNS, mdns.TypeTXT, mdns.TypeSOA, mdns.TypeCAA,
}

// rcodeString maps a DNS response code to its name.
func rcodeString(code int) string {
	switch code {
	case 0:
		return "NOERROR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", code)
	}
}

// Resolve implements RecordResolver over DoH. NXDOMAIN/SERVFAIL/REFUSED are
// recorded in Status (not treated as errors); a transport/timeout/malformed
// failure on every query returns an error. No answer is ever fabricated.
func (g *GoogleDoH) Resolve(ctx context.Context, domain string) (*Result, error) {
	clean := strings.TrimSuffix(domain, ".")
	res := &Result{
		Domain:    domain,
		Records:   make([]Record, 0),
		Resolver:  g.Name(),
		QueriedAt: time.Now().UTC(),
	}

	var firstErr error
	anyOK := false
	aStatus, firstStatus := -1, -1

	for _, qt := range recordTypes {
		recs, status, err := g.queryOne(ctx, clean, qt)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		anyOK = true
		if firstStatus < 0 {
			firstStatus = status
		}
		if qt == mdns.TypeA {
			aStatus = status
		}
		res.Records = append(res.Records, recs...)
	}

	// Every query failed (resolver unreachable / all malformed): surface it.
	if !anyOK {
		if firstErr == nil {
			firstErr = fmt.Errorf("doh: no response for %s", domain)
		}
		return nil, firstErr
	}

	// DMARC is published at _dmarc.<domain>.
	if recs, _, err := g.queryOne(ctx, "_dmarc."+clean, mdns.TypeTXT); err == nil {
		for _, rec := range recs {
			if strings.HasPrefix(rec.Value, "v=DMARC1") {
				res.SecurityRecords.DMARC = rec.Value
				res.Records = append(res.Records, rec)
				break
			}
		}
	}
	// SPF lives in a root TXT record.
	for _, rec := range res.Records {
		if rec.Type == "TXT" && strings.HasPrefix(rec.Value, "v=spf1") {
			res.SecurityRecords.SPF = rec.Value
			break
		}
	}

	res.Records = dedupeRecords(res.Records)

	apex := aStatus
	if apex < 0 {
		apex = firstStatus
	}
	switch {
	case apex >= 0:
		res.Status = rcodeString(apex)
	case len(res.Records) > 0:
		res.Status = "NOERROR"
	default:
		res.Status = "NXDOMAIN"
	}
	return res, nil
}

func (g *GoogleDoH) queryOne(ctx context.Context, name string, qt uint16) ([]Record, int, error) {
	typeName := mdns.TypeToString[qt]
	q := url.Values{}
	q.Set("name", name)
	q.Set("type", typeName)
	q.Set("cd", "0")
	reqURL := g.endpoint + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, -1, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := g.do(ctx, req)
	if err != nil {
		return nil, -1, fmt.Errorf("doh %s %s: %w", typeName, name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, -1, fmt.Errorf("doh %s %s: http %d", typeName, name, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHBody))
	if err != nil {
		return nil, -1, fmt.Errorf("doh %s %s: read: %w", typeName, name, err)
	}
	var dr dohResponse
	if err := json.Unmarshal(body, &dr); err != nil {
		return nil, -1, fmt.Errorf("doh %s %s: malformed json: %w", typeName, name, err)
	}

	var recs []Record
	for _, a := range dr.Answer {
		recs = append(recs, Record{
			Type:  mdns.TypeToString[a.Type],
			Name:  strings.TrimSuffix(a.Name, "."),
			Value: formatDoHValue(a.Type, a.Data),
			TTL:   a.TTL,
		})
	}
	return recs, dr.Status, nil
}

// formatDoHValue normalizes a DoH presentation-form value to match the port-53
// resolver's formatting, so the UI renders both providers identically.
func formatDoHValue(t uint16, data string) string {
	switch t {
	case mdns.TypeCNAME, mdns.TypeNS:
		return strings.TrimSuffix(data, ".")
	case mdns.TypeMX:
		if f := strings.Fields(data); len(f) == 2 {
			return f[0] + " " + strings.TrimSuffix(f[1], ".")
		}
		return data
	case mdns.TypeTXT:
		return unquoteTXT(data)
	case mdns.TypeSOA:
		if f := strings.Fields(data); len(f) >= 3 {
			return fmt.Sprintf("Primary NS: %s, Admin: %s, Serial: %s",
				strings.TrimSuffix(f[0], "."), strings.TrimSuffix(f[1], "."), f[2])
		}
		return data
	case mdns.TypeCAA:
		if f := strings.Fields(data); len(f) >= 3 {
			return f[1] + " " + strings.Join(f[2:], " ")
		}
		return data
	default:
		return data
	}
}

// unquoteTXT concatenates a TXT record's (possibly multiple, quoted) character
// strings without separators (RFC 7208 §3.3). "a" "b" -> ab; inner spaces kept.
func unquoteTXT(data string) string {
	if !strings.Contains(data, "\"") {
		return data
	}
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(data); i++ {
		switch c := data[i]; {
		case c == '"':
			inQuote = !inQuote
		case inQuote:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// dedupeRecords removes exact (type, name, value) duplicates, which DoH can
// produce when a CNAME chain is echoed across several type queries.
func dedupeRecords(in []Record) []Record {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, r := range in {
		k := r.Type + "\x00" + r.Name + "\x00" + r.Value
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	return out
}
