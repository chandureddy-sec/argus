package models

// Severity levels for security findings.
const (
	SeverityInfo     = "INFO"
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

// Finding represents a single security finding from any active or passive module.
type Finding struct {
	Category              string `json:"category"`
	Severity              string `json:"severity"`
	Title                 string `json:"title"`
	Description           string `json:"description"`
	Evidence              string `json:"evidence,omitempty"`
	Target                string `json:"target"`
	RequiresTargetContact bool   `json:"requires_target_contact"`
}
