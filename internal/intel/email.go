package intel

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	rdns "reconx/internal/dns"
	"reconx/pkg/models"
)

// ── SPF ──────────────────────────────────────────────────────────────────────

var spfMechanisms = map[string]bool{
	"all": true, "include": true, "a": true, "mx": true, "ptr": true,
	"ip4": true, "ip6": true, "exists": true,
}

// spfLookupMechanisms are the terms that cost a DNS lookup (RFC 7208 §4.6.4).
var spfLookupMechanisms = map[string]bool{"include": true, "a": true, "mx": true, "ptr": true, "exists": true}

// ParseSPF parses the SPF policy among the TXT strings published at a domain.
// It is pure: nested includes are not expanded (see CountSPFLookups).
func ParseSPF(txts []string) models.SPFInfo {
	var recs []string
	for _, t := range txts {
		lt := strings.ToLower(strings.TrimSpace(t))
		if lt == "v=spf1" || strings.HasPrefix(lt, "v=spf1 ") {
			recs = append(recs, strings.TrimSpace(t))
		}
	}
	info := models.SPFInfo{RecordCount: len(recs)}
	if len(recs) == 0 {
		return info
	}
	info.Present = true
	info.Raw = recs[0]
	info.Valid = true
	if len(recs) > 1 {
		info.Valid = false
		info.Issues = append(info.Issues, fmt.Sprintf("%d SPF records published — receivers treat this as a permanent error (RFC 7208 §3.2)", len(recs)))
	}

	senders := map[string]bool{}
	for _, term := range strings.Fields(recs[0])[1:] {
		lterm := strings.ToLower(term)
		// Modifiers are name=value.
		if eq := strings.Index(lterm, "="); eq > 0 && !strings.ContainsAny(lterm[:eq], ":/") {
			name, val := lterm[:eq], term[eq+1:]
			switch name {
			case "redirect":
				info.Redirect = val
				info.LookupCount++
			case "exp":
			default:
				info.Issues = append(info.Issues, "Unknown modifier: "+term)
			}
			continue
		}

		q := "+"
		if strings.ContainsAny(lterm[:1], "+-~?") {
			q, lterm, term = lterm[:1], lterm[1:], term[1:]
		}
		mech, val := lterm, ""
		if i := strings.IndexAny(lterm, ":/"); i >= 0 {
			mech = lterm[:i]
			val = strings.TrimPrefix(term[i:], ":")
		}
		if !spfMechanisms[mech] {
			info.Valid = false
			info.Issues = append(info.Issues, "Unknown mechanism: "+term)
			continue
		}
		info.Mechanisms = append(info.Mechanisms, models.SPFMechanism{Qualifier: q, Type: mech, Value: val})
		if spfLookupMechanisms[mech] {
			info.LookupCount++
		}
		switch mech {
		case "all":
			info.All = q + "all"
		case "ptr":
			info.Issues = append(info.Issues, "Uses the deprecated 'ptr' mechanism (RFC 7208 §5.5)")
		case "include":
			if r := MatchSPFInclude(val); r != nil {
				senders[r.Name] = true
			}
		}
	}

	switch info.All {
	case "-all":
		info.Policy = "Hard fail — mail from unlisted senders should be rejected"
	case "~all":
		info.Policy = "Soft fail — mail from unlisted senders should be marked suspicious"
	case "?all":
		info.Policy = "Neutral — no assertion about unlisted senders"
	case "+all":
		info.Policy = "Pass all — any server may send as this domain"
		info.Issues = append(info.Issues, "'+all' authorizes every sender on the internet")
	default:
		if info.Redirect != "" {
			info.Policy = "Delegated via redirect=" + info.Redirect
		} else {
			info.Policy = "No 'all' mechanism — unlisted senders default to neutral"
		}
	}

	for s := range senders {
		info.Senders = append(info.Senders, s)
	}
	sort.Strings(info.Senders)
	return info
}

// CountSPFLookups expands include/redirect chains over public DNS to compute
// the total DNS-lookup cost of the policy (limit 10, RFC 7208 §4.6.4). Only
// third-party SPF records and the domain's own TXT are queried.
func CountSPFLookups(ctx context.Context, r *rdns.Resolver, info *models.SPFInfo) {
	if !info.Present {
		return
	}
	visited := map[string]bool{}
	var walk func(spf models.SPFInfo, depth int) int
	walk = func(spf models.SPFInfo, depth int) int {
		n := spf.LookupCount
		if depth >= 10 {
			return n
		}
		targets := []string{}
		for _, m := range spf.Mechanisms {
			if m.Type == "include" && m.Value != "" {
				targets = append(targets, m.Value)
			}
		}
		if spf.Redirect != "" {
			targets = append(targets, spf.Redirect)
		}
		for _, t := range targets {
			t = strings.ToLower(t)
			if visited[t] || strings.Contains(t, "%{") {
				continue // macros can't be expanded passively
			}
			visited[t] = true
			txts, err := r.TXT(ctx, t)
			if err != nil {
				continue
			}
			n += walk(ParseSPF(txts), depth+1)
		}
		return n
	}
	info.LookupCount = walk(*info, 0)
	if info.LookupCount > 10 {
		info.Valid = false
		info.Issues = append(info.Issues, fmt.Sprintf("Requires %d DNS lookups — exceeds the limit of 10 (receivers return permerror)", info.LookupCount))
	} else if info.LookupCount >= 8 {
		info.Issues = append(info.Issues, fmt.Sprintf("Requires %d of the 10 allowed DNS lookups — close to the limit", info.LookupCount))
	}
}

// ── DMARC ────────────────────────────────────────────────────────────────────

// ParseDMARC parses the TXT strings published at _dmarc.<domain>.
func ParseDMARC(txts []string) models.DMARCInfo {
	var recs []string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
			recs = append(recs, strings.TrimSpace(t))
		}
	}
	info := models.DMARCInfo{Pct: 100}
	if len(recs) == 0 {
		info.Posture = "Missing — receivers apply no domain-owner policy"
		return info
	}
	info.Present = true
	info.Raw = recs[0]
	info.Valid = true
	if len(recs) > 1 {
		info.Valid = false
		info.Issues = append(info.Issues, fmt.Sprintf("%d DMARC records published — receivers ignore DMARC when more than one exists", len(recs)))
	}

	tags := map[string]string{}
	for i, part := range strings.Split(recs[0], ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if !ok {
			info.Valid = false
			info.Issues = append(info.Issues, "Malformed tag: "+part)
			continue
		}
		if i == 0 && k != "v" {
			info.Valid = false
		}
		tags[k] = v
	}

	info.Policy = strings.ToLower(tags["p"])
	info.SubdomainPolicy = strings.ToLower(tags["sp"])
	if info.SubdomainPolicy == "" {
		info.SubdomainPolicy = info.Policy
	}
	if v, ok := tags["pct"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 100 {
			info.Pct = n
		} else {
			info.Issues = append(info.Issues, "Invalid pct value: "+v)
		}
	}
	info.RUA = splitURIs(tags["rua"])
	info.RUF = splitURIs(tags["ruf"])
	info.ADKIM = alignment(tags["adkim"])
	info.ASPF = alignment(tags["aspf"])
	info.FO = tags["fo"]
	info.RI = tags["ri"]
	if info.FO == "" {
		info.FO = "0"
	}
	if info.RI == "" {
		info.RI = "86400"
	}

	switch info.Policy {
	case "reject":
		info.Posture = "Enforced — failing mail is rejected"
	case "quarantine":
		info.Posture = "Enforced — failing mail is quarantined"
	case "none":
		info.Posture = "Monitoring only (p=none) — weaker enforcement; failing mail is still delivered"
	case "":
		info.Valid = false
		info.Posture = "Invalid — required p= tag is missing"
		info.Issues = append(info.Issues, "Missing required p= tag")
	default:
		info.Valid = false
		info.Posture = "Invalid policy value: " + info.Policy
		info.Issues = append(info.Issues, "Unknown p= value: "+info.Policy)
	}
	if info.Pct < 100 && (info.Policy == "reject" || info.Policy == "quarantine") {
		info.Issues = append(info.Issues, fmt.Sprintf("Policy applies to only %d%% of failing mail", info.Pct))
	}
	if len(info.RUA) == 0 {
		info.Issues = append(info.Issues, "No aggregate reporting address (rua) — the owner receives no DMARC reports")
	}
	return info
}

func splitURIs(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func alignment(v string) string {
	switch strings.ToLower(v) {
	case "s":
		return "strict"
	default:
		return "relaxed"
	}
}

// ── DKIM ─────────────────────────────────────────────────────────────────────

// dkimSelectors is a short list of selectors published by widely used mail
// services. It is deliberately small: DKIM selectors can't be enumerated
// passively, so this checks well-known names only rather than brute-forcing.
var dkimSelectors = []struct{ name, service string }{
	{"google", "Google Workspace"},
	{"selector1", "Microsoft 365"},
	{"selector2", "Microsoft 365"},
	{"k1", "Mailchimp / Mandrill"},
	{"k2", "Mailchimp / Mandrill"},
	{"mandrill", "Mandrill"},
	{"s1", "SendGrid"},
	{"s2", "SendGrid"},
	{"smtpapi", "SendGrid"},
	{"mxvault", "Mailgun"},
	{"pic", "Mailgun"},
	{"zoho", "Zoho Mail"},
	{"zmail", "Zoho Mail"},
	{"protonmail", "Proton Mail"},
	{"fm1", "Fastmail"},
	{"cm", "Campaign Monitor"},
	{"default", ""},
	{"dkim", ""},
	{"mail", ""},
	{"smtp", ""},
}

// ParseDKIM parses a DKIM key record (v=DKIM1; k=rsa; p=...).
func ParseDKIM(selector, raw string) models.DKIMSelector {
	sel := models.DKIMSelector{Selector: selector, Raw: raw, KeyType: "rsa"}
	tags := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
			tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	if k := strings.ToLower(tags["k"]); k != "" {
		sel.KeyType = k
	}
	sel.Flags = tags["t"]
	p := strings.ReplaceAll(tags["p"], " ", "")
	if p == "" {
		sel.Revoked = true
		return sel
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return sel
	}
	if sel.KeyType == "ed25519" {
		if len(der) == ed25519.PublicKeySize {
			sel.KeyBits = 256
		}
		return sel
	}
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rk, ok := pub.(*rsa.PublicKey); ok {
			sel.KeyBits = rk.N.BitLen()
		}
	} else if rk, err := x509.ParsePKCS1PublicKey(der); err == nil {
		sel.KeyBits = rk.N.BitLen()
	}
	return sel
}

func isDKIMRecord(txt string) bool {
	lt := strings.ToLower(txt)
	return strings.HasPrefix(lt, "v=dkim1") || strings.Contains(lt, "p=")
}

// ── MTA-STS / TLS-RPT ────────────────────────────────────────────────────────

// ParseMTASTS parses the _mta-sts TXT record. The policy itself (mode,
// max_age) lives in a file served by the target's own mta-sts host over HTTPS,
// which passive mode never fetches.
func ParseMTASTS(txts []string) models.MTASTSInfo {
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=stsv1") {
			info := models.MTASTSInfo{Present: true, Raw: t,
				Note: "Policy mode and max_age are published at https://mta-sts.<domain>/.well-known/mta-sts.txt on the target's own server, so passive mode does not fetch them."}
			for _, part := range strings.Split(t, ";") {
				if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && strings.EqualFold(strings.TrimSpace(k), "id") {
					info.ID = strings.TrimSpace(v)
				}
			}
			return info
		}
	}
	return models.MTASTSInfo{}
}

// ParseTLSRPT parses the _smtp._tls TXT record.
func ParseTLSRPT(txts []string) models.TLSRPTInfo {
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=tlsrptv1") {
			info := models.TLSRPTInfo{Present: true, Raw: t}
			for _, part := range strings.Split(t, ";") {
				if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && strings.EqualFold(strings.TrimSpace(k), "rua") {
					info.RUA = splitURIs(v)
				}
			}
			return info
		}
	}
	return models.TLSRPTInfo{}
}

// ── Collection & scoring ─────────────────────────────────────────────────────

// CollectEmailSecurity gathers SPF, DMARC, DKIM, MTA-STS and TLS-RPT for a
// domain from public DNS. rootTXT are the TXT strings already fetched for the
// domain apex.
func CollectEmailSecurity(ctx context.Context, r *rdns.Resolver, domain string, rootTXT []string) *models.EmailSecurity {
	es := &models.EmailSecurity{}
	es.SPF = ParseSPF(rootTXT)
	CountSPFLookups(ctx, r, &es.SPF)

	if txts, err := r.TXT(ctx, "_dmarc."+domain); err == nil {
		es.DMARC = ParseDMARC(txts)
	} else {
		es.DMARC = ParseDMARC(nil)
	}

	for _, s := range dkimSelectors {
		es.DKIM.Checked = append(es.DKIM.Checked, s.name)
		txts, err := r.TXT(ctx, s.name+"._domainkey."+domain)
		if err != nil {
			continue
		}
		for _, t := range txts {
			if isDKIMRecord(t) {
				sel := ParseDKIM(s.name, t)
				sel.Service = s.service
				es.DKIM.Found = append(es.DKIM.Found, sel)
				break
			}
		}
	}

	if txts, err := r.TXT(ctx, "_mta-sts."+domain); err == nil {
		es.MTASTS = ParseMTASTS(txts)
	}
	if txts, err := r.TXT(ctx, "_smtp._tls."+domain); err == nil {
		es.TLSRPT = ParseTLSRPT(txts)
	}

	ScoreEmail(es)
	return es
}

// ScoreEmail computes the transparent email-authentication posture score.
// Each control contributes fixed points, and every award is explained in
// ScoreBreakdown. DKIM is excluded from the maximum when no key is found,
// because selectors can't be enumerated passively — absence is inconclusive.
func ScoreEmail(es *models.EmailSecurity) {
	var items []models.ScoreItem
	add := func(control string, pts, max int, reason string) {
		items = append(items, models.ScoreItem{Control: control, Points: pts, Max: max, Reason: reason})
	}

	spf := es.SPF
	switch {
	case !spf.Present:
		add("SPF", 0, 25, "No SPF record")
	case !spf.Valid:
		add("SPF", 5, 25, "SPF record present but invalid")
	case spf.All == "-all":
		add("SPF", 25, 25, "Valid SPF ending in -all (hard fail)")
	case spf.All == "~all":
		add("SPF", 20, 25, "Valid SPF ending in ~all (soft fail)")
	case spf.All == "+all":
		add("SPF", 0, 25, "SPF authorizes all senders (+all)")
	case spf.Redirect != "":
		add("SPF", 20, 25, "Valid SPF delegated via redirect")
	default:
		add("SPF", 10, 25, "SPF without an enforcing 'all' (neutral)")
	}

	d := es.DMARC
	switch {
	case !d.Present:
		add("DMARC", 0, 30, "No DMARC record")
	case !d.Valid:
		add("DMARC", 5, 30, "DMARC record present but invalid")
	case d.Policy == "reject" && d.Pct == 100:
		add("DMARC", 30, 30, "p=reject on 100% of mail")
	case d.Policy == "reject":
		add("DMARC", 25, 30, fmt.Sprintf("p=reject on %d%% of mail", d.Pct))
	case d.Policy == "quarantine" && d.Pct == 100:
		add("DMARC", 22, 30, "p=quarantine on 100% of mail")
	case d.Policy == "quarantine":
		add("DMARC", 17, 30, fmt.Sprintf("p=quarantine on %d%% of mail", d.Pct))
	default:
		add("DMARC", 10, 30, "p=none (monitoring only)")
	}

	active := 0
	for _, k := range es.DKIM.Found {
		if !k.Revoked {
			active++
		}
	}
	if active > 0 {
		add("DKIM", 20, 20, fmt.Sprintf("%d active key(s) found at well-known selectors", active))
	} else {
		add("DKIM", 0, 0, "Inconclusive — no key at well-known selectors (custom selectors can't be discovered passively); not counted")
	}

	if es.MTASTS.Present {
		add("MTA-STS", 15, 15, "MTA-STS TXT record published")
	} else {
		add("MTA-STS", 0, 15, "No MTA-STS record")
	}
	if es.TLSRPT.Present {
		add("TLS-RPT", 10, 10, "TLS-RPT reporting configured")
	} else {
		add("TLS-RPT", 0, 10, "No TLS-RPT record")
	}

	es.Score, es.MaxScore = 0, 0
	for _, it := range items {
		es.Score += it.Points
		es.MaxScore += it.Max
	}
	es.ScoreBreakdown = items
}
