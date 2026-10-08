package correlate

import (
	"sort"
	"strings"

	"reconx/internal/intel"
	"reconx/pkg/models"
)

// GraphOptions tunes BuildInfraGraph.
type GraphOptions struct {
	// IncludeHistorical adds hosts that don't resolve now. They have no
	// infrastructure edges, so they are off by default to keep the graph legible.
	IncludeHistorical bool
	// MaxHosts caps the host nodes (highest interest first); 0 means 300.
	MaxHosts int
}

// BuildInfraGraph turns a scan's passive intelligence into an infrastructure
// graph: domain → hosts → CNAME targets → IPs → ASNs → likely providers, plus
// the domain's nameservers and mail servers. Returns nil for reports without
// passive intel.
func BuildInfraGraph(rep *models.ScanReport, opt GraphOptions) *models.InfraGraph {
	if rep == nil || rep.Intel == nil {
		return nil
	}
	pi := rep.Intel
	if opt.MaxHosts <= 0 {
		opt.MaxHosts = 300
	}
	domain := ""
	if rep.Target != nil {
		domain = strings.ToLower(rep.Target.Value)
	}

	b := &graphBuilder{g: &models.InfraGraph{Target: domain}, idx: map[string]int{}, edges: map[string]bool{}, reach: map[string]map[string]bool{}}
	root := b.node(models.NodeDomain, domain, "Scanned domain")

	ipInfo := map[string]*models.IPInfo{}
	for i := range pi.IPs {
		ipInfo[pi.IPs[i].IP] = &pi.IPs[i]
	}
	dangling := map[string]bool{}
	for _, d := range pi.Dangling {
		dangling[d.Hostname] = true
	}

	hosts := selectHosts(pi.Hosts, opt, b.g)
	hostSet := map[string]bool{}
	for _, h := range hosts {
		hostSet[h.Hostname] = true
	}

	for _, h := range hosts {
		hid := root // the apex host and the domain node are the same entity
		if h.Hostname != domain {
			hid = b.node(models.NodeHost, h.Hostname, hostDetail(h))
			b.edge(root, hid, "subdomain", models.EvidenceObserved)
		}
		b.flag(hid, hostFlags(h, dangling[h.Hostname])...)
		b.touch(hid, h.Hostname)

		// CNAME chain: host → c1 → c2 …; IPs hang off the last link.
		last := hid
		for _, c := range h.CNAMEs {
			var cid string
			if hostSet[c] {
				cid = b.node(models.NodeHost, c, "")
			} else {
				cid = b.node(models.NodeCNAME, c, "CNAME target")
			}
			b.edge(last, cid, "cname", models.EvidenceObserved)
			b.touch(cid, h.Hostname)
			if rule := intel.MatchCNAME(c); rule != nil {
				pid := b.node(models.NodeProvider, rule.Name, rule.Category)
				b.edge(cid, pid, "hosted_by", models.EvidenceInferred)
				b.touch(pid, h.Hostname)
			}
			last = cid
		}
		for _, ip := range h.IPs {
			iid := b.ipNode(ip, ipInfo[ip])
			b.edge(last, iid, "resolves_to", models.EvidenceObserved)
			b.touch(iid, h.Hostname)
			info := ipInfo[ip]
			if info == nil {
				continue
			}
			from := iid
			if asn := asnKey(info.ASN); asn != "" {
				aid := b.node(models.NodeASN, asn, firstNonEmpty(info.ASName, asnName(info.ASN), info.Organization))
				b.edge(iid, aid, "announced_by", models.EvidenceEnriched)
				b.touch(aid, h.Hostname)
				from = aid
			}
			if info.Provider != "" {
				pid := b.node(models.NodeProvider, info.Provider, info.ProviderKind)
				b.edge(from, pid, "hosted_by", models.EvidenceInferred)
				b.touch(pid, h.Hostname)
			}
		}
	}

	for _, s := range pi.Nameservers {
		b.server(root, models.NodeNS, "nameserver", s)
	}
	for _, s := range pi.MailServers {
		b.server(root, models.NodeMX, "mail", s)
	}

	for i := range b.g.Nodes {
		b.g.Nodes[i].Weight = len(b.reach[b.g.Nodes[i].ID])
		if b.g.Nodes[i].Weight == 0 {
			b.g.Nodes[i].Weight = 1
		}
		sort.Strings(b.g.Nodes[i].Flags)
	}
	return b.g
}

// selectHosts picks the hosts to draw: resolving ones (and historical ones
// when asked), highest interest first, up to the cap.
func selectHosts(all []models.HostIntel, opt GraphOptions, g *models.InfraGraph) []models.HostIntel {
	var out []models.HostIntel
	for _, h := range all {
		if h.DNSStatus == "resolves" || opt.IncludeHistorical {
			out = append(out, h)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].InterestScore != out[j].InterestScore {
			return out[i].InterestScore > out[j].InterestScore
		}
		return out[i].Hostname < out[j].Hostname
	})
	if len(out) > opt.MaxHosts {
		g.Truncated, g.Omitted = true, len(out)-opt.MaxHosts
		out = out[:opt.MaxHosts]
	}
	return out
}

type graphBuilder struct {
	g     *models.InfraGraph
	idx   map[string]int             // node id → index
	edges map[string]bool            // dedupe "from|rel|to"
	reach map[string]map[string]bool // node id → hosts that lead to it
}

func (b *graphBuilder) node(kind, label, detail string) string {
	id := kind + ":" + label
	if i, ok := b.idx[id]; ok {
		if b.g.Nodes[i].Detail == "" {
			b.g.Nodes[i].Detail = detail
		}
		return id
	}
	b.idx[id] = len(b.g.Nodes)
	b.g.Nodes = append(b.g.Nodes, models.GraphNode{ID: id, Kind: kind, Label: label, Detail: detail})
	return id
}

func (b *graphBuilder) flag(id string, flags ...string) {
	n := &b.g.Nodes[b.idx[id]]
	for _, f := range flags {
		if f != "" && !contains(n.Flags, f) {
			n.Flags = append(n.Flags, f)
		}
	}
}

func (b *graphBuilder) edge(from, to, rel, evidence string) {
	if from == to {
		return
	}
	key := from + "|" + rel + "|" + to
	if b.edges[key] {
		return
	}
	b.edges[key] = true
	b.g.Edges = append(b.g.Edges, models.GraphEdge{From: from, To: to, Rel: rel, Evidence: evidence})
}

func (b *graphBuilder) touch(id, host string) {
	if b.reach[id] == nil {
		b.reach[id] = map[string]bool{}
	}
	b.reach[id][host] = true
}

func (b *graphBuilder) ipNode(ip string, info *models.IPInfo) string {
	detail := ""
	if info != nil {
		detail = strings.Join(nonEmpty(info.Organization, place(info), info.ReverseDNS), " · ")
	}
	id := b.node(models.NodeIP, ip, detail)
	if info == nil {
		return id
	}
	if e := info.Exposure; e != nil {
		if len(e.Ports) > 0 {
			b.flag(id, "exposed")
		}
		for _, v := range e.Vulns {
			if v.KEV {
				b.flag(id, "kev")
				break
			}
		}
	}
	if info.Routing != nil && info.Routing.Agreement == "disagree" {
		b.flag(id, "routing-conflict")
	}
	return id
}

func (b *graphBuilder) server(root, kind, rel string, s models.ServerInfo) {
	detail := strings.Join(nonEmpty(s.ASN, s.Organization, s.Country), " · ")
	id := b.node(kind, s.Hostname, detail)
	b.edge(root, id, rel, models.EvidenceObserved)
	if s.Provider != "" {
		pid := b.node(models.NodeProvider, s.Provider, "")
		b.edge(id, pid, "hosted_by", models.EvidenceInferred)
	}
}

func hostDetail(h models.HostIntel) string {
	return strings.Join(nonEmpty(h.Role, h.Organization, h.CDN, h.Cloud), " · ")
}

func hostFlags(h models.HostIntel, dangling bool) []string {
	var f []string
	if h.Interest == "high" {
		f = append(f, "high-interest")
	}
	if h.Lifecycle == "new" || h.Lifecycle == "changed" {
		f = append(f, h.Lifecycle)
	}
	if dangling {
		f = append(f, "dangling")
	}
	if h.DNSStatus != "" && h.DNSStatus != "resolves" {
		f = append(f, "not-resolving")
	}
	return f
}

// asnKey normalises "AS13335 Cloudflare, Inc." to "AS13335".
func asnKey(asn string) string {
	f := strings.Fields(asn)
	if len(f) == 0 {
		return ""
	}
	k := strings.ToUpper(f[0])
	if !strings.HasPrefix(k, "AS") {
		k = "AS" + k
	}
	return k
}

func asnName(asn string) string {
	if _, rest, ok := strings.Cut(strings.TrimSpace(asn), " "); ok {
		return strings.TrimSpace(rest)
	}
	return ""
}

func place(info *models.IPInfo) string {
	return strings.Join(nonEmpty(info.City, info.Country), ", ")
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
