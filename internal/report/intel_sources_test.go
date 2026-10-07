package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"reconx/pkg/models"
)

// intelReport is a minimal passive-intel report carrying third-party
// enrichment, for checking that each source renders in every format.
func intelReport() *models.ScanReport {
	return &models.ScanReport{
		Target:    &models.Target{Value: "example.com", Type: models.TargetTypeDomain},
		Timestamp: time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC),
		Intel: &models.PassiveIntel{
			Version: models.IntelVersion,
			Hosts: []models.HostIntel{{Hostname: "www.example.com", Sources: []string{"crtsh", "urlscan"}, DNSStatus: "resolves", IPs: []string{"93.184.216.34"},
				Web:      &models.WebCapture{Source: "urlscan", Title: "Example Home", Server: "nginx", ScanURL: "https://urlscan.io/result/u1/", Screenshot: "https://urlscan.io/screenshots/u1.png"},
				CodeRefs: []string{"https://github.com/acme/infra/blob/main/hosts.txt"}}},
			IPs: []models.IPInfo{
				{IP: "93.184.216.34", Version: "IPv4", Hostnames: []string{"www.example.com"},
					Exposure: &models.IPExposure{Ports: []int{22, 443}, CPEs: []string{"cpe:/a:nginx:nginx:1.18.0"}, Tags: []string{"cloud"},
						Vulns: []models.CVERef{{ID: "CVE-2021-23017", Enriched: true, KEV: true, EPSS: 0.42, CVSS: 7.7}}}},
				{IP: "93.184.216.35", Version: "IPv4", Routing: &models.RoutingCheck{Source: "ripestat", Agreement: "disagree", Holder: "EDGECAST",
					Conflicts: []string{"Origin ASN: Team Cymru AS64500 vs RIPEstat AS15133"}, Upstreams: []string{"AS174"}}},
			},
			Aggregates: models.Aggregates{UniqueIPs: 2, ExposedIPs: 1, OpenPorts: 2, ReportedCVEs: 1, KEVCVEs: 1, RoutingConflicts: 1},
		},
	}
}

func TestExposureRendersInHTMLAndMarkdown(t *testing.T) {
	rep := intelReport()

	var html bytes.Buffer
	if err := RenderHTMLToWriter(rep, &html); err != nil {
		t.Fatalf("RenderHTMLToWriter: %v", err)
	}
	md := RenderMarkdown(rep)

	for name, out := range map[string]string{"html": html.String(), "markdown": md} {
		for _, want := range []string{"Shodan InternetDB", "22, 443", "CVE-2021-23017 [KEV] EPSS 0.42 CVSS 7.7", "cpe:/a:nginx:nginx:1.18.0", "1 in CISA KEV", "Example Home", "https://urlscan.io/screenshots/u1.png", "https://github.com/acme/infra/blob/main/hosts.txt"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s report missing %q", name, want)
			}
		}
	}
	for name, out := range map[string]string{"html": html.String(), "markdown": md} {
		if !strings.Contains(out, "Team Cymru AS64500 vs RIPEstat AS15133") {
			t.Errorf("%s report hides the routing disagreement", name)
		}
	}
	// The un-indexed IP must not get an exposure row.
	exposure := md[strings.Index(md, "## Exposure"):]
	exposure = exposure[:strings.Index(exposure[3:], "## ")+3]
	if strings.Contains(exposure, "93.184.216.35") {
		t.Error("markdown lists an IP with no exposure data")
	}
}

func TestExposureSectionOmittedWhenNoData(t *testing.T) {
	rep := intelReport()
	rep.Intel.IPs[0].Exposure = nil
	rep.Intel.Aggregates = models.Aggregates{UniqueIPs: 2}
	if md := RenderMarkdown(rep); strings.Contains(md, "Shodan InternetDB") {
		t.Error("exposure section rendered without any exposure data")
	}
}
