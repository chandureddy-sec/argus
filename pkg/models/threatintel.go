package models

import "time"

// ThreatIntel is what a ThreatLens server said about the scan's hosts and IPs
// (POST /api/v1/enrich). ThreatLens combines its own feeds with third-party
// reputation; every verdict carries its evidence. A verdict is ThreatLens's
// assessment of the asset, not a finding ReconX verified.
type ThreatIntel struct {
	Server      string           `json:"server"`
	CheckedAt   time.Time        `json:"checked_at"`
	TLP         string           `json:"tlp"`
	Status      string           `json:"status"` // ok | partial | error
	Error       string           `json:"error,omitempty"`
	Counts      map[string]int   `json:"counts"` // malicious, suspicious, benign, unknown
	BudgetSpent int              `json:"budget_spent"`
	Items       []ThreatVerdict  `json:"items"`
	Rejected    []ThreatRejected `json:"rejected,omitempty"`
}

// ThreatVerdict is ThreatLens's answer for one asset.
type ThreatVerdict struct {
	Value        string           `json:"value"`
	Type         string           `json:"type"` // ipv4-addr | ipv6-addr | domain-name
	Defanged     string           `json:"defanged"`
	Verdict      string           `json:"verdict"` // malicious | suspicious | benign | unknown
	Score        int              `json:"score"`   // 0-100
	Action       string           `json:"action"`  // block | investigate | no_action | monitor
	ActionText   string           `json:"action_text,omitempty"`
	KnownSources []string         `json:"known_sources,omitempty"` // ThreatLens feeds that list it
	Evidence     []ThreatEvidence `json:"evidence,omitempty"`
	Related      []string         `json:"related,omitempty"` // e.g. "malware Emotet"
	Skipped      []string         `json:"skipped,omitempty"` // "virustotal: no_api_key"
	Partial      bool             `json:"partial"`
}

// ThreatEvidence is one finding behind a verdict.
type ThreatEvidence struct {
	Source string `json:"source"`
	Kind   string `json:"kind"` // malicious | suspicious | benign | info
	Weight int    `json:"weight"`
	Text   string `json:"text"`
	Ref    string `json:"ref,omitempty"`
}

// ThreatRejected is a value ThreatLens refused to look up, and why.
type ThreatRejected struct {
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// Flagged reports whether ThreatLens considers the asset worth attention.
func (v ThreatVerdict) Flagged() bool {
	return v.Verdict == "malicious" || v.Verdict == "suspicious"
}
