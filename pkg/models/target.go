package models

// TargetType represents the classified type of an input target.
type TargetType string

const (
	TargetTypeDomain  TargetType = "domain"
	TargetTypeIPv4    TargetType = "ipv4"
	TargetTypeIPv6    TargetType = "ipv6"
	TargetTypeCIDR    TargetType = "cidr"
	TargetTypeOrg     TargetType = "org"
	TargetTypeUnknown TargetType = "unknown"
)

// Target represents a normalized, typed target to scan.
type Target struct {
	Original string     `json:"original"`
	Value    string     `json:"value"`
	Type     TargetType `json:"type"`
}

func (t Target) String() string {
	return string(t.Type) + ":" + t.Value
}
