package monitor

import (
	"strings"
	"testing"

	"reconx/pkg/models"
)

func verdicts(vs ...models.ThreatVerdict) *models.ThreatIntel {
	return &models.ThreatIntel{Status: "ok", Items: vs}
}

func tv(value, verdict string, score int) models.ThreatVerdict {
	return models.ThreatVerdict{
		Value: value, Defanged: strings.ReplaceAll(value, ".", "[.]"), Verdict: verdict, Score: score, Action: "block",
		Evidence: []models.ThreatEvidence{{Source: "feodo", Kind: verdict, Weight: score, Text: "Active indicator"}},
	}
}

func TestThreatIntelFlaggedRule(t *testing.T) {
	m := &Monitor{ID: "m1", Target: "example.com"}
	prev, cur := rep(nil), rep(nil)
	prev.ThreatIntel = verdicts(tv("1.1.1.1", "unknown", 0), tv("2.2.2.2", "malicious", 90), tv("3.3.3.3", "suspicious", 40))
	cur.ThreatIntel = verdicts(
		tv("1.1.1.1", "malicious", 85),  // newly malicious
		tv("2.2.2.2", "malicious", 90),  // already known: quiet
		tv("3.3.3.3", "suspicious", 45), // unchanged verdict: quiet
		tv("4.4.4.4", "suspicious", 35), // new asset, suspicious
	)
	a, ok := byRule(Evaluate(m, prev, cur, "p.json", "c.json"))[RuleThreatFlagged]
	if !ok {
		t.Fatal("no threat_intel_flagged alert")
	}
	if a.Severity != SevHigh || len(a.Items) != 2 {
		t.Fatalf("severity %s items %v", a.Severity, a.Items)
	}
	if !strings.HasPrefix(a.Items[0], "1[.]1[.]1[.]1: MALICIOUS (score 85, block) — feodo:") {
		t.Errorf("item %q", a.Items[0])
	}

	// Downgrades and runs without ThreatLens raise nothing.
	down := rep(nil)
	down.ThreatIntel = verdicts(tv("2.2.2.2", "suspicious", 50))
	if _, ok := byRule(Evaluate(m, prev, down, "p.json", "c.json"))[RuleThreatFlagged]; ok {
		t.Error("malicious -> suspicious must not alert")
	}
	if _, ok := byRule(Evaluate(m, prev, rep(nil), "p.json", "c.json"))[RuleThreatFlagged]; ok {
		t.Error("a run without ThreatLens must not alert")
	}

	// First ThreatLens run after a baseline without it: every flagged asset is new.
	first := rep(nil)
	first.ThreatIntel = verdicts(tv("4.4.4.4", "suspicious", 35))
	if a := byRule(Evaluate(m, rep(nil), first, "p.json", "c.json"))[RuleThreatFlagged]; a.Severity != SevMedium {
		t.Errorf("suspicious-only severity = %q", a.Severity)
	}
	if err := ValidateRules([]string{RuleThreatFlagged}); err != nil {
		t.Error(err)
	}
}
