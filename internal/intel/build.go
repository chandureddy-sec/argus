package intel

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	rdns "reconx/internal/dns"
	"reconx/internal/enrich"
	"reconx/internal/normalize"
	"reconx/internal/orchestrator"
	"reconx/internal/providers"
	"reconx/internal/providers/alienvault"
	"reconx/internal/providers/crtsh"
	"reconx/pkg/models"
)

// Input is everything the passive pipeline has already gathered.
type Input struct {
	Domain   string
	DNS      *rdns.Result                  // apex records
	Raw      []models.RawResult            // per-source subdomain results (unmerged)
	Assets   []models.Asset                // normalized subdomains
	Statuses []orchestrator.ProviderStatus // subdomain source outcomes
	RDAP     *SourceTiming                 // optional, to record the RDAP source run
	Progress func(msg string)
}

// SourceTiming is an externally measured source run (e.g. RDAP, apex DNS).
type SourceTiming struct {
	Duration time.Duration
	Err      error
	Results  int
}

// Output is the assembled passive intelligence plus the host->IP map and IP
// enrichment the legacy correlation graph is built from. Raw and Assets are
// the subdomain results, extended when a failed source was recovered.
type Output struct {
	Intel  *models.PassiveIntel
	Raw    []models.RawResult
	Assets []models.Asset
	HostIP map[string][]string
	IPMeta map[string]enrich.IPIntelligence
}

var purposes = map[string]string{
	"crtsh":        "Subdomains from Certificate Transparency logs",
	"hackertarget": "Subdomains from host-search database",
	"alienvault":   "Subdomains from OTX passive DNS",
	"anubis":       "Subdomains from Anubis dataset",
	"wayback":      "Hostnames from archived URLs",
	"urlscan":      "Hostnames, page titles, servers and screenshots from urlscan.io's public scan archive",
	"certspotter":  "Subdomains from Cert Spotter (SSLMate) Certificate Transparency monitor",
	"githubcode":   "Hostnames mentioned in public code on GitHub (needs RECONX_GITHUB_TOKEN)",
}

// Collect builds the passive intelligence model. Every query here goes to a
// public third party (crt.sh, OTX, ip-api, Team Cymru) or a public DNS
// resolver; nothing contacts the target's own servers.
func Collect(ctx context.Context, r *rdns.Resolver, in Input) Output {
	now := time.Now().UTC()
	domain := strings.ToLower(in.Domain)
	progress := in.Progress
	if progress == nil {
		progress = func(string) {}
	}
	pi := &models.PassiveIntel{Version: models.IntelVersion}

	if in.RDAP != nil {
		pi.Sources = append(pi.Sources, sourceRun("rdap", "Registration (RDAP via rdap.org)", in.RDAP.Duration, in.RDAP.Err, in.RDAP.Results))
	}
	for _, st := range in.Statuses {
		pi.Sources = append(pi.Sources, sourceRun(st.Name, purposes[st.Name], st.Elapsed, st.Err, st.Results))
	}

	// ── Certificates (shared crt.sh response) ──
	progress("Analysing Certificate Transparency certificates…")
	start := time.Now()
	// Each shared-response stage gets its own budget: a flaky upstream (crt.sh
	// often 502s and is retried) must not consume the rest of the scan.
	entries, err := withBudget(ctx, 40*time.Second, func(ctx context.Context) ([]crtsh.Entry, error) {
		return crtsh.FetchEntries(ctx, domain, 35*time.Second)
	})
	var hostCerts map[string]int
	pi.Certificates, pi.CertSummary, hostCerts = BuildCertificates(entries, domain, now)
	pi.Sources = append(pi.Sources, sourceRun("crtsh-certificates", "Certificate details (shared crt.sh response)", time.Since(start), err, pi.CertSummary.Total))

	// crt.sh is often briefly unavailable. If subdomain discovery failed but
	// this certificate fetch succeeded, recover its hostnames from the cache.
	if err == nil && len(entries) > 0 {
		for i, st := range pi.Sources {
			if st.Name != "crtsh" || st.Status == models.SourceSuccess {
				continue
			}
			recovered, rerr := crtsh.NewProvider(35*time.Second).Collect(ctx, models.Target{Value: domain, Type: models.TargetTypeDomain})
			if rerr != nil {
				break
			}
			in.Raw = append(in.Raw, recovered...)
			in.Assets = normalize.NormalizeAndDedup(in.Raw, normalize.DefaultOptions(domain))
			pi.Sources[i].Status = models.SourceSuccess
			pi.Sources[i].Results = len(recovered)
			pi.Sources[i].Error = "first attempt failed (" + st.Error + "); recovered on retry"
			progress(fmt.Sprintf("Recovered %d crt.sh subdomains on retry", len(recovered)))
		}
	}

	// ── Historical DNS (shared OTX response) ──
	progress("Collecting historical DNS (OTX passive DNS)…")
	start = time.Now()
	pdns, err := withBudget(ctx, 40*time.Second, func(ctx context.Context) ([]alienvault.PassiveDNSRecord, error) {
		return alienvault.FetchPassiveDNS(ctx, domain, 35*time.Second)
	})
	pi.Sources = append(pi.Sources, sourceRun("otx-passive-dns", "Historical DNS values (shared OTX response)", time.Since(start), err, len(pdns)))
	history := map[string][]models.HistoricalValue{}
	for _, rec := range pdns {
		h := strings.ToLower(strings.TrimSuffix(rec.Hostname, "."))
		typ := strings.ToUpper(rec.RecordType)
		if typ != "A" && typ != "AAAA" && typ != "CNAME" {
			continue
		}
		history[h] = append(history[h], models.HistoricalValue{
			Type: typ, Value: strings.ToLower(strings.TrimSuffix(rec.Address, ".")), Source: "alienvault",
			FirstSeen: tptr(parseAny(rec.First)), LastSeen: tptr(parseAny(rec.Last)),
		})
	}

	// ── DNS posture & email security ──
	progress("Checking DNSSEC, CAA and email security records…")
	start = time.Now()
	pi.DNSSEC = CollectDNSSEC(ctx, r, domain)
	pi.CAA = CollectCAA(ctx, r, domain)
	var rootTXT, nsHosts []string
	type mx struct {
		pri  int
		host string
	}
	var mxHosts []mx
	if in.DNS != nil {
		for _, rec := range in.DNS.Records {
			if !strings.EqualFold(rec.Name, domain) {
				continue
			}
			switch rec.Type {
			case "TXT":
				rootTXT = append(rootTXT, rec.Value)
			case "NS":
				nsHosts = append(nsHosts, strings.ToLower(rec.Value))
			case "MX":
				f := strings.Fields(rec.Value)
				if len(f) == 2 {
					p, _ := strconv.Atoi(f[0])
					mxHosts = append(mxHosts, mx{p, strings.ToLower(f[1])})
				}
			}
		}
	}
	pi.Email = CollectEmailSecurity(ctx, r, domain, rootTXT)
	present := 0
	for _, ok := range []bool{pi.DNSSEC.Enabled, pi.CAA.Present, pi.Email.SPF.Present, pi.Email.DMARC.Present, len(pi.Email.DKIM.Found) > 0, pi.Email.MTASTS.Present, pi.Email.TLSRPT.Present} {
		if ok {
			present++
		}
	}
	pi.Sources = append(pi.Sources, partialRun(sourceRun("dns-posture", "DNSSEC, CAA, SPF, DMARC, DKIM, MTA-STS, TLS-RPT (public resolvers)", time.Since(start), ctx.Err(), present), present))

	// ── Resolve every host, nameserver and MX ──
	hostSet := map[string]bool{}
	var hosts []string
	for _, a := range in.Assets {
		if !hostSet[a.Asset] {
			hostSet[a.Asset] = true
			hosts = append(hosts, a.Asset)
		}
	}
	progress(fmt.Sprintf("Resolving %d hosts, %d nameservers and %d mail servers…", len(hosts), len(nsHosts), len(mxHosts)))
	start = time.Now()
	lookup := append([]string{}, hosts...)
	for _, n := range nsHosts {
		lookup = append(lookup, n)
	}
	for _, m := range mxHosts {
		lookup = append(lookup, m.host)
	}
	resolved := ResolveHosts(ctx, r, dedupe(lookup), 25)
	resolving := 0
	for _, h := range hosts {
		if resolved[h].Status == "resolves" {
			resolving++
		}
	}
	pi.Sources = append(pi.Sources, partialRun(sourceRun("dns-resolution", "Current A/AAAA/CNAME for every host (public resolvers)", time.Since(start), ctx.Err(), resolving), resolving))

	// ── Enrich every IP ──
	ipHosts := map[string][]string{}
	for _, h := range dedupe(lookup) {
		for _, ip := range resolved[h].IPs {
			ipHosts[ip] = append(ipHosts[ip], h)
		}
	}
	allIPs := make([]string, 0, len(ipHosts))
	for ip := range ipHosts {
		allIPs = append(allIPs, ip)
	}
	sort.Strings(allIPs)
	progress(fmt.Sprintf("Enriching %d IPs (ip-api.com, Team Cymru)…", len(allIPs)))
	start = time.Now()
	ipMeta := enrich.NewIPEnricher(10*time.Second).EnrichBatch(ctx, allIPs)
	enriched := 0
	for _, m := range ipMeta {
		if m.ASN != "" {
			enriched++
		}
	}
	var ipErr error
	if len(allIPs) > 0 && enriched == 0 {
		ipErr = errors.New("no enrichment returned (service unreachable or rate limited)")
	}
	pi.Sources = append(pi.Sources, sourceRun("ip-api", "IP geolocation, ASN, ISP, reverse DNS", time.Since(start), ipErr, enriched))
	start = time.Now()
	prefixes := LookupPrefixes(ctx, r, allIPs)
	pi.Sources = append(pi.Sources, partialRun(sourceRun("team-cymru", "Announced prefix, RIR, allocation date (DNS)", time.Since(start), ctx.Err(), len(prefixes)), len(prefixes)))
	progress(fmt.Sprintf("Cross-checking routing for %d IPs (RIPEstat)…", len(allIPs)))
	start = time.Now()
	routing, rtErr := withBudget(ctx, 90*time.Second, func(ctx context.Context) (map[string]*enrich.RoutingInfo, error) {
		return enrich.NewRIPEstat(15*time.Second).LookupBatch(ctx, allIPs)
	})
	pi.Sources = append(pi.Sources, partialRun(sourceRun("ripestat", "Origin ASN, prefix, RIR and upstreams (cross-check of Team Cymru)", time.Since(start), rtErr, len(routing)), len(routing)))
	var noPTR []string
	for _, ip := range allIPs {
		if ipMeta[ip].PTR == "" {
			noPTR = append(noPTR, ip)
		}
	}
	start = time.Now()
	ptrs := LookupPTR(ctx, r, noPTR)
	pi.Sources = append(pi.Sources, partialRun(sourceRun("reverse-dns", "PTR records (public resolvers)", time.Since(start), ctx.Err(), len(ptrs)), len(ptrs)))

	// ── Exposure from Shodan's crawl data (InternetDB) ──
	progress(fmt.Sprintf("Looking up %d IPs in Shodan InternetDB…", len(allIPs)))
	start = time.Now()
	exposures, expErr := withBudget(ctx, 90*time.Second, func(ctx context.Context) (map[string]*models.IPExposure, error) {
		return NewInternetDB(10*time.Second).LookupBatch(ctx, allIPs)
	})
	pi.Sources = append(pi.Sources, partialRun(sourceRun("shodan-internetdb", "Open ports, CPEs, tags and CVE IDs from Shodan's last crawl", time.Since(start), expErr, len(exposures)), len(exposures)))

	ipInfo := map[string]*models.IPInfo{}
	for _, ip := range allIPs {
		m := ipMeta[ip]
		info := &models.IPInfo{
			IP: ip, Version: ipVersion(ip), Hostnames: dedupe(ipHosts[ip]),
			ASN: m.ASN, ASName: m.ASName, Organization: m.Organization, ISP: m.ISP,
			Country: m.Country, Region: m.Region, City: m.City, Continent: m.Continent,
			ReverseDNS: m.PTR, Hosting: m.Hosting, Sources: []string{"dns"},
		}
		if info.ReverseDNS == "" {
			info.ReverseDNS = ptrs[ip]
		}
		if m.ASN != "" {
			info.Sources = append(info.Sources, "ip-api")
		}
		if p, ok := prefixes[ip]; ok {
			info.Prefix, info.RIR, info.Allocated = p.Prefix, p.RIR, p.Allocated
			if info.ASN == "" && p.ASN != "" {
				info.ASN = "AS" + p.ASN
			}
			info.Sources = append(info.Sources, "team-cymru")
		}
		if rt := routing[ip]; rt != nil {
			cy, hasCymru := prefixes[ip]
			info.Routing = CompareRouting(rt, cy, hasCymru)
			// Fill only what Team Cymru left blank; conflicts stay in Routing.
			if info.Prefix == "" {
				info.Prefix = rt.Prefix
			}
			if info.RIR == "" {
				info.RIR = rt.RIR
			}
			if info.ASN == "" && len(rt.ASNs) > 0 {
				info.ASN = info.Routing.ASNs[0]
			}
			info.Sources = append(info.Sources, "ripestat")
		}
		if exp := exposures[ip]; exp != nil {
			info.Exposure = exp
			info.Sources = append(info.Sources, "shodan-internetdb")
		}
		if rule := MatchIP(info.ASN, info.Organization, info.ISP, info.ASName); rule != nil {
			info.Provider, info.ProviderKind = rule.Name, rule.Kind
		}
		ipInfo[ip] = info
		pi.IPs = append(pi.IPs, *info)
	}

	// ── CVE exploitation context (Shodan CVEDB: CVSS, EPSS, CISA KEV) ──
	if ids := exposureCVEIDs(pi.IPs); len(ids) > 0 {
		progress(fmt.Sprintf("Enriching %d CVE IDs from Shodan CVEDB (KEV, EPSS)…", len(ids)))
		start = time.Now()
		details, cveErr := withBudget(ctx, 120*time.Second, func(ctx context.Context) (map[string]*models.CVERef, error) {
			return NewCVEDB(10*time.Second).LookupBatch(ctx, ids)
		})
		ApplyCVEDetails(pi.IPs, details)
		pi.Sources = append(pi.Sources, partialRun(sourceRun("shodan-cvedb", "CVSS, EPSS and CISA KEV status for reported CVE IDs", time.Since(start), cveErr, len(details)), len(details)))
	}

	// ── Nameservers & mail servers ──
	server := func(host string, pri int) models.ServerInfo {
		s := models.ServerInfo{Hostname: host, Priority: pri, IPs: resolved[host].IPs}
		if len(s.IPs) > 0 {
			if ip := ipInfo[s.IPs[0]]; ip != nil {
				s.ASN, s.Organization, s.Country = ip.ASN, ip.Organization, ip.Country
			}
		}
		return s
	}
	providerUse := newProviderTracker()
	for _, n := range dedupe(nsHosts) {
		s := server(n, 0)
		if rule := MatchNS(n); rule != nil {
			s.Provider = rule.Name
			providerUse.add("DNS", rule.Name, domain, "NS "+n)
		}
		pi.Nameservers = append(pi.Nameservers, s)
	}
	sort.Slice(mxHosts, func(i, j int) bool { return mxHosts[i].pri < mxHosts[j].pri })
	mailProviders := []string{}
	for _, m := range mxHosts {
		s := server(m.host, m.pri)
		if rule := MatchMX(m.host); rule != nil {
			s.Provider = rule.Name
			providerUse.add(rule.Category, rule.Name, domain, "MX "+m.host)
			if !contains(mailProviders, rule.Name) {
				mailProviders = append(mailProviders, rule.Name)
			}
		}
		pi.MailServers = append(pi.MailServers, s)
	}
	for _, sender := range pi.Email.SPF.Senders {
		if rule := findRule(sender); rule != nil {
			providerUse.add(rule.Category, rule.Name, domain, "SPF include")
		}
	}
	pi.Email.MailProviders = mailProviders

	// ── Hosts ──
	rawBySource := map[string]map[string][2]*time.Time{} // host -> source -> first,last
	web := map[string]*models.WebCapture{}
	codeRefs := map[string][]string{}
	for _, rr := range in.Raw {
		h := strings.ToLower(rr.Value)
		if wc := webCapture(rr); wc != nil {
			web[h] = wc
		}
		if refs := rr.Metadata["code_refs"]; refs != "" && strings.Contains(rr.Source, "githubcode") {
			codeRefs[h] = strings.Fields(refs)
		}
		if rawBySource[h] == nil {
			rawBySource[h] = map[string][2]*time.Time{}
		}
		first, last := tptr(parseAny(rr.Metadata["first_seen"])), tptr(parseAny(rr.Metadata["last_seen"]))
		for _, src := range strings.Split(rr.Source, ",") {
			src = strings.TrimSpace(src)
			cur := rawBySource[h][src]
			cur[0] = minT(cur[0], first)
			cur[1] = maxT(cur[1], last)
			rawBySource[h][src] = cur
		}
	}

	for _, a := range in.Assets {
		res := resolved[a.Asset]
		h := models.HostIntel{
			Hostname: a.Asset, Sources: a.Sources, SourceCount: len(a.Sources),
			DNSStatus: res.Status, IPs: res.IPs, CNAMEs: res.CNAMEs,
			Certificates: hostCerts[a.Asset],
		}
		for _, src := range a.Sources {
			ev := models.SourceEvidence{Source: src, Reliability: Reliability(src)}
			if span, ok := rawBySource[a.Asset][src]; ok {
				ev.FirstSeen, ev.LastSeen = span[0], span[1]
			}
			h.Evidence = append(h.Evidence, ev)
			h.FirstSeen = minT(h.FirstSeen, ev.FirstSeen)
			h.LastSeen = maxT(h.LastSeen, ev.LastSeen)
		}
		if res.Status == "resolves" {
			h.LastSeen = maxT(h.LastSeen, &now)
		}

		// Current values first, then historical ones from passive DNS.
		current := map[string]bool{}
		for _, ip := range res.IPs {
			current[ip] = true
			h.History = append(h.History, models.HistoricalValue{Type: ipVersionType(ip), Value: ip, Source: "dns", FirstSeen: &now, LastSeen: &now, Current: true})
		}
		for _, c := range res.CNAMEs {
			current[c] = true
			h.History = append(h.History, models.HistoricalValue{Type: "CNAME", Value: c, Source: "dns", FirstSeen: &now, LastSeen: &now, Current: true})
		}
		for _, hv := range history[a.Asset] {
			if current[hv.Value] {
				// Same value seen historically: extend its window instead of duplicating.
				for i := range h.History {
					if h.History[i].Value == hv.Value {
						h.History[i].FirstSeen = minT(h.History[i].FirstSeen, hv.FirstSeen)
						h.History[i].Source = "dns, alienvault"
					}
				}
				continue
			}
			h.History = append(h.History, hv)
		}

		h.Role, h.Indicators = Classify(a.Asset, domain)
		h.Web = web[a.Asset]
		h.CodeRefs = codeRefs[a.Asset]
		if len(res.IPs) > 0 {
			if ip := ipInfo[res.IPs[0]]; ip != nil {
				h.ASN, h.Organization, h.Country = ip.ASN, ip.Organization, ip.Country
			}
		}
		inferHostProviders(&h, res, ipInfo, providerUse, a.Asset)

		if res.DanglingTarget != "" {
			d := models.DanglingIndicator{Hostname: a.Asset, CNAME: res.DanglingTarget}
			if rule := MatchCNAME(res.DanglingTarget); rule != nil {
				d.Service = rule.Name
				if rule.Dangling {
					d.Reason = "CNAME points to a " + rule.Name + " name that returns NXDOMAIN — the resource may have been deleted and could be re-registrable. Requires verification."
				} else {
					d.Reason = "CNAME points to a " + rule.Name + " name that returns NXDOMAIN. Requires verification."
				}
			} else {
				d.Reason = "CNAME target does not exist (NXDOMAIN). Requires verification."
			}
			pi.Dangling = append(pi.Dangling, d)
		}

		h.Lifecycle = "active"
		if res.Status != "resolves" {
			h.Lifecycle = "historical"
		}
		ScoreConfidence(&h, now)
		ClassifyRecency(&h, now)
		pi.Hosts = append(pi.Hosts, h)
	}
	pi.Providers = providerUse.list()

	// Legacy correlation graph for the existing report sections.
	hostIP := map[string][]string{}
	for _, h := range hosts {
		if ips := resolved[h].IPs; len(ips) > 0 {
			hostIP[h] = ips
		}
	}
	return Output{Intel: pi, Raw: in.Raw, Assets: in.Assets, HostIP: hostIP, IPMeta: ipMeta}
}

// Finalize computes interest scores and aggregate metrics. Call it after
// lifecycle labels have been applied from scan history.
func Finalize(pi *models.PassiveIntel) {
	dangling := map[string]bool{}
	for _, d := range pi.Dangling {
		dangling[d.Hostname] = true
	}
	ag := models.Aggregates{Subdomains: len(pi.Hosts), Certificates: pi.CertSummary.Total}
	cloud, role := map[string]int{}, map[string]int{}
	histIPs := map[string]bool{}
	kevByIP := map[string][]string{}
	for _, ip := range pi.IPs {
		if ip.Exposure == nil {
			continue
		}
		for _, v := range ip.Exposure.Vulns {
			if v.KEV {
				kevByIP[ip.IP] = append(kevByIP[ip.IP], v.ID)
			}
		}
	}
	for i := range pi.Hosts {
		h := &pi.Hosts[i]
		ScoreInterest(h, dangling[h.Hostname])
		AddExposureInterest(h, kevByIP)
		if h.DNSStatus == "resolves" {
			ag.Resolving++
		} else {
			ag.HistoricalHosts++
		}
		if h.Interest == "high" {
			ag.HighInterest++
		}
		p := h.CDN
		if p == "" {
			p = h.Cloud
		}
		if p != "" {
			cloud[strings.TrimPrefix(p, "Likely ")]++
		}
		role[h.Role]++
		for _, hv := range h.History {
			if !hv.Current && (hv.Type == "A" || hv.Type == "AAAA") {
				histIPs[hv.Value] = true
			}
		}
	}
	country, asns := map[string]int{}, map[string]*models.ASNCount{}
	cves, kevs := map[string]bool{}, map[string]bool{}
	for _, ip := range pi.IPs {
		ag.UniqueIPs++
		if ip.Routing != nil && ip.Routing.Agreement == "disagree" {
			ag.RoutingConflicts++
		}
		if e := ip.Exposure; e != nil {
			ag.ExposedIPs++
			ag.OpenPorts += len(e.Ports)
			for _, v := range e.Vulns {
				cves[v.ID] = true
				if v.KEV {
					kevs[v.ID] = true
				}
			}
		}
		if ip.Version == "IPv6" {
			ag.IPv6++
		} else {
			ag.IPv4++
		}
		if ip.Country != "" {
			country[ip.Country]++
		}
		if ip.ASN == "" {
			continue
		}
		key := strings.Fields(ip.ASN)[0]
		a := asns[key]
		if a == nil {
			name := ip.ASName
			if name == "" {
				name = ip.Organization
			}
			a = &models.ASNCount{ASN: key, Name: name, Provider: ip.Provider}
			asns[key] = a
		}
		a.IPs++
		a.Hosts += len(ip.Hostnames)
		if ip.Country != "" && !contains(a.Countries, ip.Country) {
			a.Countries = append(a.Countries, ip.Country)
		}
	}
	for ip := range histIPs {
		found := false
		for _, cur := range pi.IPs {
			if cur.IP == ip {
				found = true
				break
			}
		}
		if !found {
			ag.HistoricalIPs++
		}
	}
	ag.ASNs, ag.Countries, ag.ReportedCVEs, ag.KEVCVEs = len(asns), len(country), len(cves), len(kevs)
	ag.ByCloud, ag.ByCountry, ag.ByRole = toCounts(cloud), toCounts(country), toCounts(role)
	for _, a := range asns {
		ag.ByASN = append(ag.ByASN, *a)
	}
	sort.Slice(ag.ByASN, func(i, j int) bool { return ag.ByASN[i].Hosts > ag.ByASN[j].Hosts })
	pi.Aggregates = ag

	// Highest-interest, then most-confident hosts first.
	sort.SliceStable(pi.Hosts, func(i, j int) bool {
		a, b := pi.Hosts[i], pi.Hosts[j]
		if a.InterestScore != b.InterestScore {
			return a.InterestScore > b.InterestScore
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		return a.Hostname < b.Hostname
	})
}

// inferHostProviders sets the likely cloud / CDN for a host. CNAME evidence
// is preferred over IP-ownership evidence, and both are labelled inferences.
func inferHostProviders(h *models.HostIntel, res Resolution, ipInfo map[string]*models.IPInfo, pu *providerTracker, host string) {
	for _, c := range res.CNAMEs {
		if rule := MatchCNAME(c); rule != nil {
			switch rule.Kind {
			case KindCDN:
				h.CDN = "Likely " + rule.Name
			case KindCloud, KindHosting:
				h.Cloud = "Likely " + rule.Name
			}
			pu.add(rule.Category, rule.Name, host, "CNAME → "+c)
		}
	}
	for _, ip := range res.IPs {
		info := ipInfo[ip]
		if info == nil || info.Provider == "" {
			continue
		}
		rule := findRule(info.Provider)
		if rule == nil {
			continue
		}
		ev := strings.TrimSpace(info.ASN + " (" + firstNonEmpty(info.ASName, info.Organization) + ")")
		switch rule.Kind {
		case KindCDN:
			if h.CDN == "" {
				h.CDN = "Likely " + rule.Name
			}
		default:
			if h.Cloud == "" {
				h.Cloud = "Likely " + rule.Name
			}
		}
		pu.add(rule.Category, rule.Name, host, ev)
		break
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

type providerTracker struct {
	m     map[string]*models.ProviderUse
	hosts map[string]map[string]bool
	order []string
}

func newProviderTracker() *providerTracker {
	return &providerTracker{m: map[string]*models.ProviderUse{}, hosts: map[string]map[string]bool{}}
}

func (p *providerTracker) add(category, name, host, evidence string) {
	key := category + "|" + name
	u := p.m[key]
	if u == nil {
		u = &models.ProviderUse{Category: category, Name: name}
		p.m[key] = u
		p.hosts[key] = map[string]bool{}
		p.order = append(p.order, key)
	}
	if !p.hosts[key][host] {
		p.hosts[key][host] = true
		u.Hosts++
	}
	if len(u.Evidence) < 5 && !contains(u.Evidence, evidence) {
		u.Evidence = append(u.Evidence, evidence)
	}
}

func (p *providerTracker) list() []models.ProviderUse {
	out := make([]models.ProviderUse, 0, len(p.order))
	for _, k := range p.order {
		out = append(out, *p.m[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Hosts > out[j].Hosts
	})
	return out
}

func findRule(name string) *Rule {
	for i := range catalog {
		if catalog[i].Name == name {
			return &catalog[i]
		}
	}
	return nil
}

func sourceRun(name, purpose string, d time.Duration, err error, results int) models.SourceRun {
	s := models.SourceRun{Name: name, Purpose: purpose, DurationMs: d.Milliseconds(), Results: results, Reliability: Reliability(baseSource(name)), Status: models.SourceSuccess}
	if errors.Is(err, providers.ErrSkipped) {
		s.Error, s.Status, s.Results = err.Error(), models.SourceSkipped, 0
		return s
	}
	if err != nil {
		s.Error = err.Error()
		s.Status = models.SourceError
		s.Results = 0
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(s.Error), "timeout") || strings.Contains(s.Error, "deadline exceeded") {
			s.Status = models.SourceTimeout
		}
	}
	return s
}

// webCapture rebuilds a urlscan page capture from a raw result's metadata.
func webCapture(rr models.RawResult) *models.WebCapture {
	m := rr.Metadata
	if !strings.Contains(rr.Source, "urlscan") || m["scan_url"] == "" {
		return nil
	}
	wc := &models.WebCapture{
		Source: "urlscan", URL: m["url"], Title: m["title"], Server: m["server"], HTTPStatus: m["http_status"],
		IP: m["ip"], ASN: m["asn"], TLSIssuer: m["tls_issuer"], Screenshot: m["screenshot"], ScanURL: m["scan_url"],
		CapturedAt: tptr(parseAny(m["last_seen"])),
	}
	wc.Scans, _ = strconv.Atoi(m["scans"])
	if t := m["technologies"]; t != "" {
		wc.Technologies = strings.Split(t, ", ")
	}
	return wc
}

// partialRun keeps a source counted as successful when some of its lookups
// failed but others returned data; the error text is kept as a note.
func partialRun(s models.SourceRun, results int) models.SourceRun {
	if s.Status != models.SourceSuccess && results > 0 {
		s.Status = models.SourceSuccess
		s.Results = results
		s.Error = "partial: " + s.Error
	}
	return s
}

// withBudget runs fn under its own deadline so one slow third-party source
// cannot stall the rest of the scan. Partial results are still returned.
func withBudget[T any](ctx context.Context, d time.Duration, fn func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return fn(ctx)
}

func baseSource(name string) string {
	switch {
	case strings.HasPrefix(name, "crtsh"):
		return "crtsh"
	case strings.HasPrefix(name, "otx"):
		return "alienvault"
	case strings.HasPrefix(name, "dns"), name == "reverse-dns":
		return "dns"
	}
	return name
}

func toCounts(m map[string]int) []models.Count {
	out := make([]models.Count, 0, len(m))
	for k, v := range m {
		out = append(out, models.Count{Name: k, Count: v})
	}
	sortCounts(out)
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func ipVersionType(ip string) string {
	if ipVersion(ip) == "IPv6" {
		return "AAAA"
	}
	return "A"
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

var timeLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05.999", "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02", "20060102150405"}

func parseAny(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func tptr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func minT(a, b *time.Time) *time.Time {
	if a == nil {
		return b
	}
	if b == nil || a.Before(*b) {
		return a
	}
	return b
}

func maxT(a, b *time.Time) *time.Time {
	if a == nil {
		return b
	}
	if b == nil || a.After(*b) {
		return a
	}
	return b
}
