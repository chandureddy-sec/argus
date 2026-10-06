package models

import "time"

// AssetType identifies the category of a discovered asset.
type AssetType string

const (
	AssetTypeDomain    AssetType = "domain"
	AssetTypeSubdomain AssetType = "subdomain"
	AssetTypeIP        AssetType = "ip"
	AssetTypeCIDR      AssetType = "cidr"
	AssetTypeASN       AssetType = "asn"
	AssetTypeOrg       AssetType = "org"
)

// Relationships holds graph links between assets (e.g. domain -> IP -> ASN).
type Relationships struct {
	ResolvesTo []string `json:"resolves_to,omitempty"`
	ASN        string   `json:"asn,omitempty"`
	Org        string   `json:"org,omitempty"`
}

// Asset represents a normalized, deduplicated, confidence-scored finding.
type Asset struct {
	Asset         string        `json:"asset"`
	Type          AssetType     `json:"type"`
	Sources       []string      `json:"sources"`
	FirstSeen     time.Time     `json:"first_seen"`
	LastSeen      time.Time     `json:"last_seen"`
	Confidence    float64       `json:"confidence"`
	Relationships Relationships `json:"relationships,omitempty"`
}

// RawResult represents a finding emitted by an individual provider before normalization.
type RawResult struct {
	Source     string            `json:"source"`
	Value      string            `json:"value"`
	Type       AssetType         `json:"type"`
	Confidence float64           `json:"confidence"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}
