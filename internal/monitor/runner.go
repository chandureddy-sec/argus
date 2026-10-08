package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"reconx/pkg/models"
)

// ScanFunc runs and saves a passive scan for a monitor, returning the report
// and the saved JSON file name (relative to reports/).
type ScanFunc func(ctx context.Context, m *Monitor) (*models.ScanReport, string, error)

// PrevFunc returns the latest saved scan of a target and its file name, or
// nil when there is none.
type PrevFunc func(target string) (*models.ScanReport, string)

// Runner executes monitors: scan, compare, alert, notify.
type Runner struct {
	Store    *Store
	Scan     ScanFunc
	Previous PrevFunc
	Notifier *Notifier
	Log      func(string)  // optional progress log
	OnAlerts func([]Alert) // optional hook, e.g. for the terminal
	Timeout  time.Duration // per scan; 0 means 10 minutes
	mu       sync.Mutex    // one scan at a time: public sources are rate-limited
}

func (r *Runner) log(format string, args ...interface{}) {
	if r.Log != nil {
		r.Log(fmt.Sprintf(format, args...))
	}
}

// RunOne runs a monitor now, regardless of its schedule.
func (r *Runner) RunOne(ctx context.Context, id string) ([]Alert, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	start := time.Now().UTC()
	m, err := r.Store.Update(id, func(m *Monitor) error {
		if m.LastStatus == "running" {
			return fmt.Errorf("%s is already running", m.Target)
		}
		m.LastStatus = "running"
		m.NextRun = start.Add(time.Duration(m.Interval))
		return nil
	})
	if err != nil {
		return nil, err
	}
	r.log("monitor %s: scanning %s (passive)", m.ID, m.Target)

	var prev *models.ScanReport
	prevFile := ""
	if r.Previous != nil {
		prev, prevFile = r.Previous(m.Target)
	}

	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	sctx, cancel := context.WithTimeout(ctx, timeout)
	rep, file, scanErr := r.Scan(sctx, m)
	cancel()
	if scanErr == nil && rep == nil {
		scanErr = fmt.Errorf("scan returned no report")
	}
	if scanErr != nil {
		_, _ = r.Store.Update(m.ID, func(x *Monitor) error {
			x.LastStatus, x.LastError, x.LastRun = "error", scanErr.Error(), start
			x.Runs++
			return nil
		})
		r.log("monitor %s: scan of %s failed: %v", m.ID, m.Target, scanErr)
		return nil, scanErr
	}

	alerts := Evaluate(m, prev, rep, prevFile, file)
	if r.Notifier != nil {
		r.Notifier.Send(ctx, m, alerts)
	}
	if err := r.Store.AppendAlerts(alerts); err != nil {
		r.log("monitor %s: could not log alerts: %v", m.ID, err)
	}
	notable := 0
	for _, a := range alerts {
		if a.Severity != SevInfo {
			notable++
		}
	}
	_, _ = r.Store.Update(m.ID, func(x *Monitor) error {
		x.LastStatus, x.LastError, x.LastRun, x.LastFile, x.LastAlerts = "ok", "", start, file, notable
		x.Runs++
		return nil
	})
	r.log("monitor %s: %s done — %d alert(s), saved %s", m.ID, m.Target, len(alerts), file)
	if r.OnAlerts != nil && len(alerts) > 0 {
		r.OnAlerts(alerts)
	}
	return alerts, nil
}

// RunDue runs every monitor that is due at now, one after another. It
// returns how many ran.
func (r *Runner) RunDue(ctx context.Context, now time.Time) int {
	ms, err := r.Store.List()
	if err != nil {
		r.log("monitor: %v", err)
		return 0
	}
	n := 0
	for _, m := range ms {
		if ctx.Err() != nil {
			break
		}
		if !m.Due(now) {
			continue
		}
		n++
		_, _ = r.RunOne(ctx, m.ID)
	}
	return n
}

// RecoverInterrupted marks monitors left "running" by a process that exited
// mid-scan, so they become due again.
func (r *Runner) RecoverInterrupted() {
	ms, err := r.Store.List()
	if err != nil {
		return
	}
	for _, m := range ms {
		if m.LastStatus == "running" {
			_, _ = r.Store.Update(m.ID, func(x *Monitor) error {
				x.LastStatus, x.LastError = "error", "interrupted (ReconX stopped mid-scan)"
				x.NextRun = time.Now().UTC()
				return nil
			})
		}
	}
}

// Loop checks for due monitors every tick until ctx is cancelled.
func (r *Runner) Loop(ctx context.Context, tick time.Duration) {
	if tick <= 0 {
		tick = 30 * time.Second
	}
	r.RecoverInterrupted()
	r.RunDue(ctx, time.Now().UTC())
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			r.RunDue(ctx, now.UTC())
		}
	}
}
