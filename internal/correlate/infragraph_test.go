package correlate

import (
	"encoding/xml"
	"strings"
	"testing"

	"reconx/pkg/models"
)

func sampleReport() *models.ScanReport {
	return &models.ScanReport{
		Target: &models.Target{Value: "example.com", Type: models.TargetTypeDomain},
		Intel: &models.PassiveIntel{
			Hosts: []models.HostIntel{
				{Hostname: "example.com", DNSStatus: "resolves", IPs: []string{"93.184.216.34"}},
				{Hostname: "www.example.com", DNSStatus: "resolves", CNAMEs: []string{"example.cdn.cloudflare.net"}, IPs: []string{"104.16.1.1"}, Interest: "high", InterestScore: 60, Lifecycle: "new"},
				{Hostname: "api.example.com", DNSStatus: "resolves", CNAMEs: []string{"example.cdn.cloudflare.net"}, IPs: []string{"104.16.1.1"}, InterestScore: 30},
				{Hostname: "old.example.com", DNSStatus: "nxdomain"},
			},
			IPs: []models.IPInfo{
				{IP: "93.184.216.34", ASN: "AS15133 Edgecast", Organization: "Edgecast", Country: "US",
					Exposure: &models.IPExposure{Ports: []int{80, 443}, Vulns: []models.CVERef{{ID: "CVE-1", KEV: true}}}},
				{IP: "104.16.1.1", ASN: "AS13335 Cloudflare, Inc.", Provider: "Cloudflare", ProviderKind: "cdn",
					Routing: &models.RoutingCheck{Agreement: "disagree"}},
			},
			Nameservers: []models.ServerInfo{{Hostname: "a.iana-servers.net", Provider: "IANA"}},
			MailServers: []models.ServerInfo{{Hostname: "mx.example.com"}},
			Dangling:    []models.DanglingIndicator{{Hostname: "api.example.com"}},
		},
	}
}

func nodeByID(g *models.InfraGraph, id string) *models.GraphNode {
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			return &g.Nodes[i]
		}
	}
	return nil
}

func hasEdge(g *models.InfraGraph, from, rel, to string) bool {
	for _, e := range g.Edges {
		if e.From == from && e.Rel == rel && e.To == to {
			return true
		}
	}
	return false
}

func TestBuildInfraGraph(t *testing.T) {
	g := BuildInfraGraph(sampleReport(), GraphOptions{})
	if g == nil {
		t.Fatal("nil graph")
	}
	if nodeByID(g, "host:old.example.com") != nil {
		t.Error("non-resolving host included by default")
	}
	if nodeByID(g, "host:example.com") != nil {
		t.Error("apex host should merge into the domain node")
	}
	for _, want := range [][3]string{
		{"domain:example.com", "resolves_to", "ip:93.184.216.34"},
		{"domain:example.com", "subdomain", "host:www.example.com"},
		{"host:www.example.com", "cname", "cname:example.cdn.cloudflare.net"},
		{"cname:example.cdn.cloudflare.net", "resolves_to", "ip:104.16.1.1"},
		{"cname:example.cdn.cloudflare.net", "hosted_by", "provider:Cloudflare"},
		{"ip:104.16.1.1", "announced_by", "asn:AS13335"},
		{"asn:AS13335", "hosted_by", "provider:Cloudflare"},
		{"domain:example.com", "nameserver", "ns:a.iana-servers.net"},
		{"ns:a.iana-servers.net", "hosted_by", "provider:IANA"},
		{"domain:example.com", "mail", "mx:mx.example.com"},
	} {
		if !hasEdge(g, want[0], want[1], want[2]) {
			t.Errorf("missing edge %v", want)
		}
	}
	// Duplicate edges (two hosts share the CNAME) are collapsed.
	n := 0
	for _, e := range g.Edges {
		if e.From == "cname:example.cdn.cloudflare.net" && e.Rel == "resolves_to" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("cname→ip edges = %d, want 1", n)
	}

	cf := nodeByID(g, "cname:example.cdn.cloudflare.net")
	if cf.Weight != 2 {
		t.Errorf("shared CNAME weight = %d, want 2", cf.Weight)
	}
	if asn := nodeByID(g, "asn:AS13335"); asn == nil || asn.Detail != "Cloudflare, Inc." {
		t.Errorf("ASN node = %+v", asn)
	}
	www := nodeByID(g, "host:www.example.com")
	if strings.Join(www.Flags, ",") != "high-interest,new" {
		t.Errorf("www flags = %v", www.Flags)
	}
	if f := nodeByID(g, "host:api.example.com").Flags; strings.Join(f, ",") != "dangling" {
		t.Errorf("api flags = %v", f)
	}
	if f := nodeByID(g, "ip:93.184.216.34").Flags; strings.Join(f, ",") != "exposed,kev" {
		t.Errorf("ip flags = %v", f)
	}
	if f := nodeByID(g, "ip:104.16.1.1").Flags; strings.Join(f, ",") != "routing-conflict" {
		t.Errorf("cf ip flags = %v", f)
	}
}

func TestBuildInfraGraphHistoricalAndCap(t *testing.T) {
	g := BuildInfraGraph(sampleReport(), GraphOptions{IncludeHistorical: true})
	old := nodeByID(g, "host:old.example.com")
	if old == nil || strings.Join(old.Flags, ",") != "not-resolving" {
		t.Errorf("historical host = %+v", old)
	}

	g = BuildInfraGraph(sampleReport(), GraphOptions{MaxHosts: 1})
	if !g.Truncated || g.Omitted != 2 {
		t.Errorf("truncated=%v omitted=%d, want true/2", g.Truncated, g.Omitted)
	}
	if nodeByID(g, "host:www.example.com") == nil {
		t.Error("highest-interest host should survive the cap")
	}

	if BuildInfraGraph(&models.ScanReport{}, GraphOptions{}) != nil {
		t.Error("report without intel should give nil")
	}
}

func TestWriteGraphML(t *testing.T) {
	g := BuildInfraGraph(sampleReport(), GraphOptions{})
	var sb strings.Builder
	if err := WriteGraphML(g, &sb); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Graph struct {
			Nodes []struct {
				ID string `xml:"id,attr"`
			} `xml:"node"`
			Edges []struct{} `xml:"edge"`
		} `xml:"graph"`
	}
	if err := xml.Unmarshal([]byte(sb.String()), &doc); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}
	if len(doc.Graph.Nodes) != len(g.Nodes) || len(doc.Graph.Edges) != len(g.Edges) {
		t.Errorf("graphml has %d nodes/%d edges, want %d/%d", len(doc.Graph.Nodes), len(doc.Graph.Edges), len(g.Nodes), len(g.Edges))
	}
	if !strings.Contains(sb.String(), "Cloudflare, Inc.") {
		t.Error("node detail missing")
	}
}
