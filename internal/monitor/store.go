// Package monitor runs scheduled passive re-scans of targets and raises
// alerts when their attack surface changes.
//
// Monitors only ever run Passive scans: the same public-source pipeline as a
// manual passive scan, never anything that contacts the target. Each run is
// saved to reports/ like a normal scan, so history, comparison and the
// dashboard all see it; alerts are derived by comparing it with the previous
// saved scan of the same target.
package monitor

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MinInterval keeps monitors from hammering the free public sources.
const MinInterval = time.Hour

// Monitor is one scheduled target.
type Monitor struct {
	ID          string    `json:"id"`
	Target      string    `json:"target"`
	Interval    Duration  `json:"interval"`
	Enabled     bool      `json:"enabled"`
	Rules       []string  `json:"rules,omitempty"`        // alert rules; empty means all
	Webhook     string    `json:"webhook,omitempty"`      // optional Slack / Discord / generic URL
	MinSeverity string    `json:"min_severity,omitempty"` // lowest severity sent to the webhook
	ArchiveRaw  bool      `json:"archive_raw,omitempty"`  // archive raw source responses each run
	Created     time.Time `json:"created"`
	LastRun     time.Time `json:"last_run,omitempty"`
	NextRun     time.Time `json:"next_run"`
	LastStatus  string    `json:"last_status,omitempty"` // ok | error | running
	LastError   string    `json:"last_error,omitempty"`
	LastFile    string    `json:"last_file,omitempty"`
	LastAlerts  int       `json:"last_alerts"`
	Runs        int       `json:"runs"`
}

// Due reports whether the monitor should run at now.
func (m *Monitor) Due(now time.Time) bool {
	return m.Enabled && m.LastStatus != "running" && !now.Before(m.NextRun)
}

// Duration is a time.Duration that marshals as "24h0m0s" and parses day
// suffixes ("7d") as well as Go durations.
type Duration time.Duration

// ParseDuration accepts Go durations plus "d" (days) and "w" (weeks).
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	for suffix, unit := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if n, ok := strings.CutSuffix(s, suffix); ok {
			v, err := strconv.ParseFloat(n, 64)
			if err != nil || v <= 0 {
				return 0, fmt.Errorf("invalid interval %q", s)
			}
			return time.Duration(v * float64(unit)), nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid interval %q (use e.g. 6h, 1d, 1w)", s)
	}
	return d, nil
}

func (d Duration) String() string { return HumanDuration(time.Duration(d)) }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// HumanDuration renders 24h as "1d", 6h as "6h", 90m as "1h30m".
func HumanDuration(d time.Duration) string {
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		if d%(7*24*time.Hour) == 0 {
			return fmt.Sprintf("%dw", d/(7*24*time.Hour))
		}
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	s := d.Round(time.Minute).String() // e.g. "6h0m0s", "1h30m0s"
	s = strings.TrimSuffix(s, "0s")
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// Store persists monitors and the alert log under a directory
// (reports/monitor by default).
type Store struct {
	dir string
	mu  sync.Mutex
}

// DefaultDir keeps monitor state next to the saved scans it produces.
const DefaultDir = "reports/monitor"

// OpenStore returns a store rooted at dir ("" for DefaultDir).
func OpenStore(dir string) *Store {
	if dir == "" {
		dir = DefaultDir
	}
	return &Store{dir: dir}
}

// Dir is the store directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) monitorsPath() string { return filepath.Join(s.dir, "monitors.json") }
func (s *Store) alertsPath() string   { return filepath.Join(s.dir, "alerts.jsonl") }

func (s *Store) load() ([]*Monitor, error) {
	data, err := os.ReadFile(s.monitorsPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Monitor
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("monitor file %s is corrupt: %w", s.monitorsPath(), err)
	}
	return out, nil
}

func (s *Store) save(ms []*Monitor) error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ms, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.monitorsPath() + ".tmp"
	// 0600: a webhook URL is a credential (anyone holding it can post).
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.monitorsPath())
}

// List returns all monitors, ordered by target.
func (s *Store) List() ([]*Monitor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ms, err := s.load()
	sort.Slice(ms, func(i, j int) bool { return ms[i].Target < ms[j].Target })
	return ms, err
}

// Find returns the monitor with this ID, or the one for this target.
func (s *Store) Find(ref string) (*Monitor, error) {
	ms, err := s.List()
	if err != nil {
		return nil, err
	}
	ref = strings.ToLower(strings.TrimSpace(ref))
	for _, m := range ms {
		if m.ID == ref || m.Target == ref {
			return m, nil
		}
	}
	return nil, fmt.Errorf("no monitor %q", ref)
}

// Add creates a monitor; the first run is due immediately.
func (s *Store) Add(m Monitor) (*Monitor, error) {
	m.Target = strings.ToLower(strings.TrimSpace(m.Target))
	if m.Target == "" {
		return nil, fmt.Errorf("target is required")
	}
	if time.Duration(m.Interval) < MinInterval {
		return nil, fmt.Errorf("interval must be at least %s (public sources are rate-limited)", HumanDuration(MinInterval))
	}
	if err := ValidateRules(m.Rules); err != nil {
		return nil, err
	}
	if err := ValidateWebhook(m.Webhook); err != nil {
		return nil, err
	}
	if m.MinSeverity == "" {
		m.MinSeverity = SevLow
	} else if _, ok := sevRank[m.MinSeverity]; !ok {
		return nil, fmt.Errorf("min severity must be one of high, medium, low, info")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ms, err := s.load()
	if err != nil {
		return nil, err
	}
	for _, x := range ms {
		if x.Target == m.Target {
			return nil, fmt.Errorf("%s is already monitored (id %s)", m.Target, x.ID)
		}
	}
	m.ID = newID()
	m.Enabled = true
	m.Created = time.Now().UTC()
	m.NextRun = m.Created
	ms = append(ms, &m)
	if err := s.save(ms); err != nil {
		return nil, err
	}
	return &m, nil
}

// Update applies fn to the monitor with this ID and saves the result.
func (s *Store) Update(id string, fn func(*Monitor) error) (*Monitor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ms, err := s.load()
	if err != nil {
		return nil, err
	}
	for _, m := range ms {
		if m.ID == id {
			if err := fn(m); err != nil {
				return nil, err
			}
			return m, s.save(ms)
		}
	}
	return nil, fmt.Errorf("no monitor %q", id)
}

// Remove deletes a monitor (its saved scans and alerts are kept).
func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ms, err := s.load()
	if err != nil {
		return err
	}
	out := ms[:0]
	found := false
	for _, m := range ms {
		if m.ID == id {
			found = true
			continue
		}
		out = append(out, m)
	}
	if !found {
		return fmt.Errorf("no monitor %q", id)
	}
	return s.save(out)
}

// AppendAlerts adds alerts to the log.
func (s *Store) AppendAlerts(alerts []Alert) error {
	if len(alerts) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(s.alertsPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, a := range alerts {
		if err := enc.Encode(a); err != nil {
			return err
		}
	}
	return nil
}

// Alerts returns logged alerts, newest first, optionally for one target, at
// most limit (0 = all).
func (s *Store) Alerts(target string, limit int) ([]Alert, error) {
	s.mu.Lock()
	data, err := os.ReadFile(s.alertsPath())
	s.mu.Unlock()
	if errors.Is(err, fs.ErrNotExist) {
		return []Alert{}, nil
	}
	if err != nil {
		return nil, err
	}
	target = strings.ToLower(target)
	out := []Alert{}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var a Alert
		if json.Unmarshal([]byte(lines[i]), &a) != nil {
			continue // a partly written line must not hide the rest
		}
		if target != "" && a.Target != target {
			continue
		}
		out = append(out, a)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func newID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
