package models

import "strings"

// CorrelatedAsset links a discovered hostname to its live IPs, ASN, Organization, and Cloud Provider.
type CorrelatedAsset struct {
	Hostname      string   `json:"hostname"`
	Sources       []string `json:"sources"`
	Confidence    float64  `json:"confidence"`
	IsAlive       bool     `json:"is_alive"`
	ResolvedIPs   []string `json:"resolved_ips,omitempty"`
	ASN           string   `json:"asn,omitempty"`
	Organization  string   `json:"organization,omitempty"`
	ISP           string   `json:"isp,omitempty"`
	CloudProvider string   `json:"cloud_provider,omitempty"`
	Country       string   `json:"country,omitempty"`
}

// PrimaryIPString returns a comma-joined string of resolved IPs for table display.
func (c *CorrelatedAsset) PrimaryIPString() string {
	if len(c.ResolvedIPs) == 0 {
		return "[Unresolved / Inactive]"
	}
	if len(c.ResolvedIPs) > 2 {
		return strings.Join(c.ResolvedIPs[:2], ", ") + " (+" + string(rune('0'+len(c.ResolvedIPs)-2)) + " more)"
	}
	return strings.Join(c.ResolvedIPs, ", ")
}

// Graph represents the consolidated attack surface relationship graph.
type Graph struct {
	TargetDomain string            `json:"target_domain"`
	TotalAssets  int               `json:"total_assets"`
	LiveAssets   int               `json:"live_assets"`
	Nodes        []CorrelatedAsset `json:"nodes"`
}
