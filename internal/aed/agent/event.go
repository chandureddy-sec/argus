package agent

import "encoding/json"

// OCSF class uids for the minimal subset AED emits (pinned schema version).
const (
	ClassAuthentication  = 3002 // OCSF Authentication
	ClassDeviceInventory = 5001 // OCSF Device Inventory Info
	OCSFVersion          = "1.1.0"
)

// Event is the AED-normalized event plus its envelope. The original record is
// preserved in Raw so nothing is lost and parsing can be re-checked.
type Event struct {
	ClassUID    int             `json:"class_uid"`
	Time        string          `json:"time"` // RFC3339 UTC
	AgentID     string          `json:"agent_id"`
	OCSFVersion string          `json:"ocsf_version"`
	Fields      map[string]any  `json:"fields"`
	Raw         json.RawMessage `json:"raw,omitempty"`
}
