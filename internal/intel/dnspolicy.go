package intel

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"

	rdns "reconx/internal/dns"
	"reconx/pkg/models"
)

// CollectDNSSEC checks the DS record in the parent zone, the zone's DNSKEYs and
// signatures, and whether a validating public resolver authenticates the
// answer (AD flag).
func CollectDNSSEC(ctx context.Context, r *rdns.Resolver, domain string) *models.DNSSECInfo {
	info := &models.DNSSECInfo{}
	algs := map[string]bool{}

	ds, err := r.Exchange(ctx, domain, dns.TypeDS, true)
	if err != nil {
		info.Error = "DS lookup failed: " + err.Error()
	} else {
		for _, rr := range ds.Answer {
			if d, ok := rr.(*dns.DS); ok {
				info.DS = append(info.DS, models.DSRecord{
					KeyTag:     d.KeyTag,
					Algorithm:  algName(d.Algorithm),
					DigestType: digestName(d.DigestType),
				})
				algs[algName(d.Algorithm)] = true
			}
		}
	}
	info.Enabled = len(info.DS) > 0

	keys, err := r.Exchange(ctx, domain, dns.TypeDNSKEY, true)
	if err == nil {
		for _, rr := range keys.Answer {
			switch k := rr.(type) {
			case *dns.DNSKEY:
				role := "ZSK"
				if k.Flags&dns.SEP != 0 {
					role = "KSK"
				}
				info.Keys = append(info.Keys, models.DNSKEYInfo{KeyTag: k.KeyTag(), Algorithm: algName(k.Algorithm), Role: role, Flags: k.Flags})
				algs[algName(k.Algorithm)] = true
			case *dns.RRSIG:
				info.Signed = true
			}
		}
		info.Validated = keys.AuthenticatedData
	} else if info.Error == "" {
		info.Error = "DNSKEY lookup failed: " + err.Error()
	}

	for a := range algs {
		info.Algorithms = append(info.Algorithms, a)
	}
	sort.Strings(info.Algorithms)

	switch {
	case info.Enabled && info.Validated:
		info.Status = "Enabled — chain of trust validated by a public validating resolver"
	case info.Enabled && info.Signed:
		info.Status = "Enabled — signed, but the resolver did not report validation"
	case info.Enabled:
		info.Status = "DS published in parent, but no signed DNSKEY answer was returned (possible misconfiguration)"
	case info.Signed || len(info.Keys) > 0:
		info.Status = "Zone is signed but no DS record exists in the parent — chain of trust incomplete"
	default:
		info.Status = "Not enabled"
	}
	return info
}

func algName(a uint8) string {
	if s, ok := dns.AlgorithmToString[a]; ok {
		return fmt.Sprintf("%s (%d)", s, a)
	}
	return fmt.Sprintf("algorithm %d", a)
}

func digestName(d uint8) string {
	switch d {
	case dns.SHA1:
		return "SHA-1"
	case dns.SHA256:
		return "SHA-256"
	case dns.SHA384:
		return "SHA-384"
	}
	return fmt.Sprintf("type %d", d)
}

// CollectCAA fetches CAA records, climbing towards the registered domain when
// the queried name has none (CAA is inherited, RFC 8659 §3).
func CollectCAA(ctx context.Context, r *rdns.Resolver, domain string) *models.CAAInfo {
	name := strings.TrimSuffix(strings.ToLower(domain), ".")
	for {
		in, err := r.Exchange(ctx, name, dns.TypeCAA, false)
		if err == nil {
			var recs []models.CAARecord
			for _, rr := range in.Answer {
				if c, ok := rr.(*dns.CAA); ok {
					recs = append(recs, models.CAARecord{Flag: c.Flag, Tag: strings.ToLower(c.Tag), Value: c.Value})
				}
			}
			if len(recs) > 0 {
				info := ParseCAA(recs)
				if name != domain {
					info.Notes = append(info.Notes, "Inherited from "+name)
				}
				return info
			}
		}
		parts := strings.Split(name, ".")
		if len(parts) <= 2 {
			break
		}
		name = strings.Join(parts[1:], ".")
	}
	return ParseCAA(nil)
}

// ParseCAA turns CAA records into a posture summary. Missing CAA is a common
// default and is reported as posture information, not a vulnerability.
func ParseCAA(recs []models.CAARecord) *models.CAAInfo {
	info := &models.CAAInfo{Records: recs, Present: len(recs) > 0}
	if !info.Present {
		info.Posture = "none"
		info.Notes = append(info.Notes, "No CAA records — any publicly trusted CA may issue certificates (the common default)")
		return info
	}
	denyAll := false
	for _, r := range recs {
		ca := strings.TrimSpace(strings.SplitN(r.Value, ";", 2)[0])
		switch r.Tag {
		case "issue":
			if ca == "" {
				denyAll = true
			} else {
				info.Issue = append(info.Issue, ca)
			}
		case "issuewild":
			if ca == "" {
				info.IssueWild = append(info.IssueWild, "(none — wildcard issuance forbidden)")
			} else {
				info.IssueWild = append(info.IssueWild, ca)
			}
		case "iodef":
			info.Iodef = append(info.Iodef, r.Value)
		default:
			if r.Flag&128 != 0 {
				info.Notes = append(info.Notes, "Unknown critical tag '"+r.Tag+"' — compliant CAs must refuse to issue")
			} else {
				info.Notes = append(info.Notes, "Unrecognized tag '"+r.Tag+"'")
			}
		}
	}

	switch {
	case denyAll && len(info.Issue) == 0:
		info.Posture = "restrictive"
		info.Notes = append(info.Notes, "issue \";\" — no CA is permitted to issue")
	case len(info.Issue) > 0:
		info.Posture = "restrictive"
		info.Notes = append(info.Notes, fmt.Sprintf("Issuance limited to %d CA(s)", len(uniq(info.Issue))))
	default:
		info.Posture = "permissive"
		info.Notes = append(info.Notes, "CAA present but no 'issue' tag — non-wildcard issuance is not restricted")
	}
	if len(info.IssueWild) == 0 {
		info.Notes = append(info.Notes, "No 'issuewild' tag — wildcard issuance follows the 'issue' policy")
	} else {
		for _, w := range info.IssueWild {
			if !strings.HasPrefix(w, "(") && len(info.Issue) > 0 && !contains(info.Issue, w) {
				info.Notes = append(info.Notes, "issuewild permits "+w+", which is not listed under issue (inconsistent policy)")
			}
		}
	}
	if len(info.Iodef) == 0 {
		info.Notes = append(info.Notes, "No iodef — CAs have no address to report policy violations to")
	}
	info.Issue = uniq(info.Issue)
	return info
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
