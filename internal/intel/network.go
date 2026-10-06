package intel

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	rdns "reconx/internal/dns"
)

// Resolution is the current public-DNS state of one hostname.
type Resolution struct {
	Host   string
	Status string   // resolves | nxdomain | no_address | error
	CNAMEs []string // CNAME chain, in order
	IPs    []string // final A and AAAA addresses
	// DanglingTarget is the last CNAME in the chain when the chain ends in
	// NXDOMAIN — i.e. the alias points to a name that no longer exists.
	DanglingTarget string
}

// ResolveHosts resolves A and AAAA (following CNAMEs) for each host through
// public resolvers, with bounded concurrency.
func ResolveHosts(ctx context.Context, r *rdns.Resolver, hosts []string, concurrency int) map[string]Resolution {
	if concurrency <= 0 {
		concurrency = 20
	}
	out := make(map[string]Resolution, len(hosts))
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			res := resolveOne(ctx, r, host)
			mu.Lock()
			out[host] = res
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	return out
}

func resolveOne(ctx context.Context, r *rdns.Resolver, host string) Resolution {
	res := Resolution{Host: host}
	nx, failed := false, 0
	seenCNAME := map[string]bool{}
	ipSet := map[string]bool{}
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		in, err := r.Exchange(qctx, host, qt, false)
		cancel()
		if err != nil {
			failed++
			continue
		}
		if in.Rcode == dns.RcodeNameError {
			nx = true
		}
		for _, rr := range in.Answer {
			switch v := rr.(type) {
			case *dns.CNAME:
				t := strings.ToLower(strings.TrimSuffix(v.Target, "."))
				if !seenCNAME[t] {
					seenCNAME[t] = true
					res.CNAMEs = append(res.CNAMEs, t)
				}
			case *dns.A:
				ipSet[v.A.String()] = true
			case *dns.AAAA:
				ipSet[v.AAAA.String()] = true
			}
		}
	}
	for ip := range ipSet {
		res.IPs = append(res.IPs, ip)
	}
	sort.Strings(res.IPs)
	switch {
	case len(res.IPs) > 0:
		res.Status = "resolves"
	case nx:
		res.Status = "nxdomain"
		if len(res.CNAMEs) > 0 {
			res.DanglingTarget = res.CNAMEs[len(res.CNAMEs)-1]
		}
	case failed == 2:
		res.Status = "error"
	default:
		res.Status = "no_address"
	}
	return res
}

// PrefixInfo is Team Cymru's IP-to-ASN mapping for an address.
type PrefixInfo struct {
	ASN       string
	Prefix    string
	Country   string
	RIR       string
	Allocated string
}

// LookupPrefixes queries Team Cymru's public IP-to-ASN DNS service for the
// announced prefix, RIR and allocation date of each IP. The queries go to
// Cymru's servers, never to the target.
func LookupPrefixes(ctx context.Context, r *rdns.Resolver, ips []string) map[string]PrefixInfo {
	out := map[string]PrefixInfo{}
	var mu sync.Mutex
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	for _, ip := range ips {
		name := cymruName(ip)
		if name == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			txts, err := r.TXT(qctx, name)
			cancel()
			if err != nil || len(txts) == 0 {
				return
			}
			// "15169 | 8.8.8.0/24 | US | arin | 1992-12-01" (several ASNs may be space separated)
			f := strings.Split(txts[0], "|")
			if len(f) < 5 {
				return
			}
			p := PrefixInfo{
				ASN:       strings.Fields(strings.TrimSpace(f[0]) + " ")[0],
				Prefix:    strings.TrimSpace(f[1]),
				Country:   strings.TrimSpace(f[2]),
				RIR:       strings.ToUpper(strings.TrimSpace(f[3])),
				Allocated: strings.TrimSpace(f[4]),
			}
			mu.Lock()
			out[ip] = p
			mu.Unlock()
		}(ip, name)
	}
	wg.Wait()
	return out
}

// LookupPTR resolves reverse DNS for each IP through public resolvers. A PTR
// name is correlation evidence, not proof of who operates an address.
func LookupPTR(ctx context.Context, r *rdns.Resolver, ips []string) map[string]string {
	out := map[string]string{}
	var mu sync.Mutex
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	for _, ip := range ips {
		name, err := dns.ReverseAddr(ip)
		if err != nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			qctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			in, err := r.Exchange(qctx, name, dns.TypePTR, false)
			cancel()
			if err != nil {
				return
			}
			for _, rr := range in.Answer {
				if p, ok := rr.(*dns.PTR); ok {
					mu.Lock()
					out[ip] = strings.TrimSuffix(p.Ptr, ".")
					mu.Unlock()
					return
				}
			}
		}(ip, name)
	}
	wg.Wait()
	return out
}

// cymruName builds the origin lookup name for an IP.
func cymruName(ip string) string {
	p := net.ParseIP(ip)
	if p == nil || p.IsPrivate() || p.IsLoopback() || p.IsUnspecified() {
		return ""
	}
	if v4 := p.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0]) + ".origin.asn.cymru.com"
	}
	const hexd = "0123456789abcdef"
	v6 := p.To16()
	nibbles := make([]string, 0, 32)
	for i := len(v6) - 1; i >= 0; i-- {
		nibbles = append(nibbles, string(hexd[v6[i]&0xf]), string(hexd[v6[i]>>4]))
	}
	return strings.Join(nibbles, ".") + ".origin6.asn.cymru.com"
}

func ipVersion(ip string) string {
	if p := net.ParseIP(ip); p != nil && p.To4() == nil {
		return "IPv6"
	}
	return "IPv4"
}
