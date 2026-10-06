package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Record represents a resolved DNS entry.
type Record struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// SecurityRecords holds parsed SPF and DMARC policies.
type SecurityRecords struct {
	SPF   string `json:"spf,omitempty"`
	DMARC string `json:"dmarc,omitempty"`
}

// Result contains all resolved DNS records for a domain.
type Result struct {
	Domain          string          `json:"domain"`
	Records         []Record        `json:"records"`
	SecurityRecords SecurityRecords `json:"security_records"`
}

// Resolver handles DNS queries using miekg/dns.
type Resolver struct {
	nameservers []string
	timeout     time.Duration
	client      *dns.Client
}

// NewResolver initializes a Resolver with fallback nameservers.
func NewResolver(nameservers []string, timeout time.Duration) *Resolver {
	if len(nameservers) == 0 {
		nameservers = []string{
			"1.1.1.1:53",
			"8.8.8.8:53",
			"9.9.9.9:53",
		}
	} else {
		// Ensure host:port format
		for i, ns := range nameservers {
			if !strings.Contains(ns, ":") {
				nameservers[i] = net.JoinHostPort(ns, "53")
			}
		}
	}

	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	return &Resolver{
		nameservers: nameservers,
		timeout:     timeout,
		client: &dns.Client{
			Timeout: timeout,
		},
	}
}

// Lookup queries all standard record types (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA) for a domain.
func (r *Resolver) Lookup(ctx context.Context, domain string) (*Result, error) {
	cleanDomain := strings.TrimSuffix(domain, ".") + "."
	res := &Result{
		Domain:  domain,
		Records: make([]Record, 0),
	}

	types := []uint16{
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeCNAME,
		dns.TypeMX,
		dns.TypeNS,
		dns.TypeTXT,
		dns.TypeSOA,
		dns.TypeCAA,
	}

	for _, qType := range types {
		records, err := r.query(ctx, cleanDomain, qType)
		if err == nil && len(records) > 0 {
			res.Records = append(res.Records, records...)
		}
	}

	// Specifically query DMARC record (_dmarc.domain)
	dmarcDomain := "_dmarc." + cleanDomain
	txtRecords, err := r.query(ctx, dmarcDomain, dns.TypeTXT)
	if err == nil {
		for _, rec := range txtRecords {
			if strings.HasPrefix(rec.Value, "v=DMARC1") {
				res.SecurityRecords.DMARC = rec.Value
				res.Records = append(res.Records, rec)
				break
			}
		}
	}

	// Parse SPF from root TXT records
	for _, rec := range res.Records {
		if rec.Type == "TXT" && strings.HasPrefix(rec.Value, "v=spf1") {
			res.SecurityRecords.SPF = rec.Value
			break
		}
	}

	return res, nil
}

func (r *Resolver) query(ctx context.Context, fqdn string, qType uint16) ([]Record, error) {
	m := new(dns.Msg)
	m.SetQuestion(fqdn, qType)
	m.RecursionDesired = true

	var lastErr error
	for _, ns := range r.nameservers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		in, _, err := r.client.ExchangeContext(ctx, m, ns)
		if err != nil {
			lastErr = err
			continue
		}

		if in.Rcode != dns.RcodeSuccess && in.Rcode != dns.RcodeNameError {
			lastErr = fmt.Errorf("query returned rcode: %s", dns.RcodeToString[in.Rcode])
			continue
		}

		var records []Record
		for _, ans := range in.Answer {
			rec := parseRR(ans)
			if rec != nil {
				records = append(records, *rec)
			}
		}
		return records, nil
	}

	return nil, lastErr
}

func parseRR(rr dns.RR) *Record {
	header := rr.Header()
	typeName := dns.TypeToString[header.Rrtype]
	cleanName := strings.TrimSuffix(header.Name, ".")

	switch v := rr.(type) {
	case *dns.A:
		return &Record{Type: typeName, Name: cleanName, Value: v.A.String(), TTL: header.Ttl}
	case *dns.AAAA:
		return &Record{Type: typeName, Name: cleanName, Value: v.AAAA.String(), TTL: header.Ttl}
	case *dns.CNAME:
		return &Record{Type: typeName, Name: cleanName, Value: strings.TrimSuffix(v.Target, "."), TTL: header.Ttl}
	case *dns.MX:
		return &Record{Type: typeName, Name: cleanName, Value: fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, ".")), TTL: header.Ttl}
	case *dns.NS:
		return &Record{Type: typeName, Name: cleanName, Value: strings.TrimSuffix(v.Ns, "."), TTL: header.Ttl}
	case *dns.TXT:
		// Character strings are concatenated without separators (RFC 7208 §3.3).
		return &Record{Type: typeName, Name: cleanName, Value: strings.Join(v.Txt, ""), TTL: header.Ttl}
	case *dns.SOA:
		return &Record{Type: typeName, Name: cleanName, Value: fmt.Sprintf("Primary NS: %s, Admin: %s, Serial: %d", strings.TrimSuffix(v.Ns, "."), strings.TrimSuffix(v.Mbox, "."), v.Serial), TTL: header.Ttl}
	case *dns.CAA:
		return &Record{Type: typeName, Name: cleanName, Value: fmt.Sprintf("%s %q", v.Tag, v.Value), TTL: header.Ttl}
	default:
		return &Record{Type: typeName, Name: cleanName, Value: rr.String(), TTL: header.Ttl}
	}
}

// Exchange sends a single query to the configured public resolvers and returns
// the raw response from the first one that answers. With dnssec set, the DO bit
// is requested so RRSIGs are returned and validating resolvers report the AD
// (authenticated data) flag.
func (r *Resolver) Exchange(ctx context.Context, name string, qType uint16, dnssec bool) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qType)
	m.RecursionDesired = true
	if dnssec {
		m.SetEdns0(4096, true)
		m.AuthenticatedData = true
	}

	var lastErr error
	for _, ns := range r.nameservers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		in, _, err := r.client.ExchangeContext(ctx, m, ns)
		if err != nil {
			lastErr = err
			continue
		}
		if in.Rcode == dns.RcodeServerFailure || in.Rcode == dns.RcodeRefused {
			lastErr = fmt.Errorf("query returned rcode: %s", dns.RcodeToString[in.Rcode])
			continue
		}
		return in, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no resolvers configured")
	}
	return nil, lastErr
}

// QueryRecords resolves name/qType and returns the parsed answer records plus
// the response code (e.g. dns.RcodeNameError for NXDOMAIN).
func (r *Resolver) QueryRecords(ctx context.Context, name string, qType uint16) ([]Record, int, error) {
	in, err := r.Exchange(ctx, name, qType, false)
	if err != nil {
		return nil, -1, err
	}
	var records []Record
	for _, ans := range in.Answer {
		if rec := parseRR(ans); rec != nil {
			records = append(records, *rec)
		}
	}
	return records, in.Rcode, nil
}

// TXT returns the TXT strings published at name (each record's character
// strings joined), or nil when there are none.
func (r *Resolver) TXT(ctx context.Context, name string) ([]string, error) {
	in, err := r.Exchange(ctx, name, dns.TypeTXT, false)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ans := range in.Answer {
		if t, ok := ans.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out, nil
}
