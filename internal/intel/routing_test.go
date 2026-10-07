package intel

import (
	"strings"
	"testing"

	"reconx/internal/enrich"
)

func TestCompareRouting(t *testing.T) {
	rs := &enrich.RoutingInfo{ASNs: []string{"15133"}, Prefix: "93.184.216.0/24", RIR: "ARIN", Announced: true, Upstreams: []string{"AS174"}}

	rc := CompareRouting(rs, PrefixInfo{ASN: "15133", Prefix: "93.184.216.0/24", RIR: "arin"}, true)
	if rc.Agreement != "agree" || len(rc.Conflicts) != 0 || rc.ASNs[0] != "AS15133" {
		t.Errorf("expected agreement, got %+v", rc)
	}
	if rs.ASNs[0] != "15133" {
		t.Error("CompareRouting mutated its input")
	}

	rc = CompareRouting(rs, PrefixInfo{ASN: "64500", Prefix: "93.184.0.0/16", RIR: "RIPENCC"}, true)
	if rc.Agreement != "disagree" || len(rc.Conflicts) != 3 {
		t.Fatalf("expected 3 conflicts, got %+v", rc)
	}
	if !strings.Contains(rc.Conflicts[0], "Team Cymru AS64500 vs RIPEstat AS15133") {
		t.Errorf("conflict should name both values: %q", rc.Conflicts[0])
	}

	// Multi-origin prefix: Cymru reporting either origin is not a conflict.
	moas := &enrich.RoutingInfo{ASNs: []string{"15133", "64500"}, Prefix: "93.184.216.0/24"}
	if rc := CompareRouting(moas, PrefixInfo{ASN: "64500", Prefix: "93.184.216.0/24"}, true); rc.Agreement != "agree" {
		t.Errorf("MOAS treated as conflict: %+v", rc)
	}

	// Same registry, different spelling (seen live: Cymru "RIPENCC", RIPEstat "RIPE NCC").
	ripe := &enrich.RoutingInfo{ASNs: []string{"47583"}, Prefix: "72.61.224.0/20", RIR: "RIPE NCC"}
	if rc := CompareRouting(ripe, PrefixInfo{ASN: "47583", Prefix: "72.61.224.0/20", RIR: "RIPENCC"}, true); rc.Agreement != "agree" {
		t.Errorf("RIR spelling treated as conflict: %+v", rc)
	}

	if rc := CompareRouting(rs, PrefixInfo{}, false); rc.Agreement != "ripestat-only" || len(rc.Conflicts) != 0 {
		t.Errorf("expected ripestat-only, got %+v", rc)
	}
}
