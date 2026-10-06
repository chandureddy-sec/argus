package models

import (
	"time"

	"reconx/internal/dns"
	"reconx/internal/whois"
)

// ScanReport gathers all collected and correlated intelligence for a target.
type ScanReport struct {
	Target      *Target            `json:"target"`
	Timestamp   time.Time          `json:"timestamp"`
	RDAP        *whois.RDAPRecord  `json:"rdap,omitempty"`
	DNS         *dns.Result        `json:"dns,omitempty"`
	Subdomains  []RawResult        `json:"raw_subdomains,omitempty"`
	Assets      []Asset            `json:"normalized_assets,omitempty"`
	Correlation *Graph             `json:"attack_surface_graph,omitempty"`
	Intel       *PassiveIntel      `json:"passive_intel,omitempty"`
	ActiveRecon *ActiveReconResult `json:"active_recon,omitempty"`
	WebMap      *WebMapResult      `json:"web_map,omitempty"`
}
