package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"reconx/internal/monitor"
	"reconx/internal/target"
	"reconx/pkg/models"
)

// monitorView is a monitor as the dashboard sees it: the webhook URL (a
// credential) is replaced by its kind and host.
type monitorView struct {
	monitor.Monitor
	Webhook     string `json:"webhook"` // masked
	WebhookKind string `json:"webhook_kind,omitempty"`
	Every       string `json:"every"`
}

func viewMonitor(m *monitor.Monitor) monitorView {
	v := monitorView{Monitor: *m, Every: m.Interval.String()}
	if m.Webhook != "" {
		v.Webhook, v.WebhookKind = monitor.MaskWebhook(m.Webhook), monitor.WebhookKind(m.Webhook)
	}
	return v
}

// handleMonitors lists monitors (GET) or adds one (POST).
func (s *webServer) handleMonitors(w http.ResponseWriter, r *http.Request) {
	st := s.monitors.Store
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		if !s.checkToken(w, r) {
			return
		}
		var body struct {
			Target      string   `json:"target"`
			Every       string   `json:"every"`
			Webhook     string   `json:"webhook"`
			MinSeverity string   `json:"min_severity"`
			Rules       []string `json:"rules"`
			ArchiveRaw  bool     `json:"archive_raw"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		t, err := target.Parse(strings.TrimSpace(body.Target))
		if err != nil || t.Type != models.TargetTypeDomain {
			http.Error(w, "enter a domain such as example.com", http.StatusBadRequest)
			return
		}
		every, err := monitor.ParseDuration(firstNonEmptyStr(body.Every, "1d"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m, err := st.Add(monitor.Monitor{Target: t.Value, Interval: monitor.Duration(every), Webhook: strings.TrimSpace(body.Webhook),
			MinSeverity: body.MinSeverity, Rules: body.Rules, ArchiveRaw: body.ArchiveRaw})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !s.schedulerOn {
			// No scheduler: run the baseline now so the monitor isn't idle.
			go func() { _, _ = s.monitors.RunOne(context.Background(), m.ID) }()
		}
	default:
		http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
		return
	}
	ms, err := st.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	views := make([]monitorView, 0, len(ms))
	for _, m := range ms {
		views = append(views, viewMonitor(m))
	}
	writeJSON(w, map[string]interface{}{"monitors": views, "rules": monitor.Rules, "scheduler": s.schedulerOn})
}

// handleMonitor runs an action on one monitor: run, pause, resume, delete, test.
func (s *webServer) handleMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkToken(w, r) {
		return
	}
	id, action, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/api/monitors/"), "/")
	st := s.monitors.Store
	m, err := st.Find(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	switch action {
	case "run":
		if m.LastStatus == "running" {
			http.Error(w, m.Target+" is already running", http.StatusConflict)
			return
		}
		// Runs in the background: a passive scan takes a few minutes. The
		// runner serialises scans, so this waits behind any running monitor.
		go func() { _, _ = s.monitors.RunOne(context.Background(), m.ID) }()
		w.WriteHeader(http.StatusAccepted)
		writeJSON(w, map[string]string{"status": "started"})
		return
	case "pause", "resume":
		on := action == "resume"
		_, err = st.Update(m.ID, func(x *monitor.Monitor) error {
			x.Enabled = on
			if on && x.NextRun.Before(time.Now()) {
				x.NextRun = time.Now().UTC()
			}
			return nil
		})
	case "delete":
		err = st.Remove(m.ID)
	case "test":
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		err = (&monitor.Notifier{}).Test(ctx, m)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// handleAlerts returns logged alerts, newest first.
func (s *webServer) handleAlerts(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	alerts, err := s.monitors.Store.Alerts(r.URL.Query().Get("target"), limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, alerts)
}
