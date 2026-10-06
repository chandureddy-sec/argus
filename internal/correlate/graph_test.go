package correlate

import (
	"testing"

	"reconx/internal/enrich"
	"reconx/pkg/models"
)

func TestBuildGraph(t *testing.T) {
	normalizedAssets := []models.Asset{
		{Asset: "dead.example.com", Sources: []string{"crtsh"}, Confidence: 0.8},
		{Asset: "live.example.com", Sources: []string{"alienvault", "crtsh"}, Confidence: 0.9},
	}

	hostIPs := map[string][]string{
		"live.example.com": {"1.1.1.1"},
		"dead.example.com": {},
	}

	ipIntel := map[string]enrich.IPIntelligence{
		"1.1.1.1": {
			IP:            "1.1.1.1",
			ASN:           "AS13335",
			Organization:  "Cloudflare, Inc.",
			CloudProvider: "Cloudflare (CDN/Proxy)",
			Country:       "Australia",
		},
	}

	graph := BuildGraph("example.com", normalizedAssets, hostIPs, ipIntel)

	if graph.TotalAssets != 2 {
		t.Fatalf("expected 2 total assets, got %d", graph.TotalAssets)
	}
	if graph.LiveAssets != 1 {
		t.Fatalf("expected 1 live asset, got %d", graph.LiveAssets)
	}

	// Live assets should be sorted first
	if graph.Nodes[0].Hostname != "live.example.com" {
		t.Errorf("expected live asset first, got %s", graph.Nodes[0].Hostname)
	}
	if !graph.Nodes[0].IsAlive {
		t.Errorf("expected node to be alive")
	}
	if graph.Nodes[0].CloudProvider != "Cloudflare (CDN/Proxy)" {
		t.Errorf("expected Cloudflare, got %s", graph.Nodes[0].CloudProvider)
	}

	if graph.Nodes[1].Hostname != "dead.example.com" {
		t.Errorf("expected dead asset second, got %s", graph.Nodes[1].Hostname)
	}
	if graph.Nodes[1].IsAlive {
		t.Errorf("expected dead asset to not be alive")
	}
}
