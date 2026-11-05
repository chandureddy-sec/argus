package agent

import (
	"encoding/json"
	"regexp"
	"strconv"
	"time"
)

// sshd failure messages, e.g.:
//
//	"Failed password for invalid user admin from 203.0.113.9 port 54321 ssh2"
//	"Failed publickey for root from 198.51.100.4 port 2222 ssh2"
var sshFailRe = regexp.MustCompile(`Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port`)

// "Invalid user admin from 203.0.113.9 port 54321"
var sshInvalidRe = regexp.MustCompile(`Invalid user (\S+) from (\S+)`)

func strField(rec map[string]json.RawMessage, key string) string {
	raw, ok := rec[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// ParseSSHFailure turns one `journalctl -o json` record into an OCSF
// Authentication (failure) event. It returns (nil,false) for non-sshd lines,
// non-failure messages, or malformed input — never panicking, never fabricating.
func ParseSSHFailure(agentID string, rawLine []byte) (*Event, bool) {
	var rec map[string]json.RawMessage
	if err := json.Unmarshal(rawLine, &rec); err != nil {
		return nil, false
	}
	if strField(rec, "SYSLOG_IDENTIFIER") != "sshd" {
		return nil, false
	}
	msg := strField(rec, "MESSAGE")
	var user, ip string
	if m := sshFailRe.FindStringSubmatch(msg); m != nil {
		user, ip = m[1], m[2]
	} else if m := sshInvalidRe.FindStringSubmatch(msg); m != nil {
		user, ip = m[1], m[2]
	} else {
		return nil, false
	}

	ts := time.Now().UTC()
	if micros := strField(rec, "__REALTIME_TIMESTAMP"); micros != "" {
		if us, err := strconv.ParseInt(micros, 10, 64); err == nil {
			ts = time.UnixMicro(us).UTC()
		}
	}
	return &Event{
		ClassUID:    ClassAuthentication,
		Time:        ts.Format(time.RFC3339),
		AgentID:     agentID,
		OCSFVersion: OCSFVersion,
		Fields: map[string]any{
			"activity": "logon",
			"status":   "failure",
			"src_ip":   ip,
			"user":     user,
			"hostname": strField(rec, "_HOSTNAME"),
		},
		Raw: json.RawMessage(append([]byte(nil), rawLine...)),
	}, true
}
