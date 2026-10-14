package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"reconx/internal/correlate"
	"reconx/internal/history"
	"reconx/internal/keystore"
	"reconx/internal/monitor"
	reporter "reconx/internal/report"
	"reconx/internal/target"
	"reconx/internal/threatlens"
	"reconx/pkg/models"
)

var (
	servePort      int
	serveHost      string
	serveNoOpen    bool
	serveNoMonitor bool
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the ReconX engine API (scans, live progress, history, monitors) for Argus",
	Long: `Serve starts the ReconX engine: a JSON API for scans with live progress, scan
history, comparisons and scheduled monitors. Its dashboard is Argus, the unified
ReconX + ThreatLens front end, which runs the engine for you in its Docker stack
(.\tl up in threatlens/). The server binds to localhost unless told otherwise; it has
no user accounts, so never expose it: Argus adds sign-in, roles and audit in front.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		srv := newWebServer()
		addr := net.JoinHostPort(serveHost, fmt.Sprintf("%d", servePort))

		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("could not bind %s: %w", addr, err)
		}

		url := fmt.Sprintf("http://%s", addr)
		fmt.Printf("\n  ReconX engine API at  %s\n", url)
		fmt.Printf("  The dashboard is Argus (http://127.0.0.1:8000/app/ in the ThreatLens stack).\n")
		fmt.Printf("  Press Ctrl+C to stop.\n\n")

		if serveNoMonitor {
			fmt.Printf("  Monitor scheduler: off (--no-monitor); \"Run now\" still works.\n\n")
		} else {
			srv.schedulerOn = true
			go srv.monitors.Loop(context.Background(), time.Minute)
			fmt.Printf("  Monitor scheduler: on — due monitors run while the dashboard is open.\n\n")
		}

		httpSrv := &http.Server{Handler: srv.routes()}
		return httpSrv.Serve(ln)
	},
}

func init() {
	serveCmd.Flags().IntVar(&servePort, "port", 8787, "port to serve the dashboard on")
	serveCmd.Flags().StringVar(&serveHost, "host", "127.0.0.1", "host/interface to bind (keep localhost for safety)")
	serveCmd.Flags().BoolVar(&serveNoOpen, "no-open", false, "kept for compatibility; the engine never opens a browser")
	serveCmd.Flags().BoolVar(&serveNoMonitor, "no-monitor", false, "do not run scheduled monitors while serving")
}

// ── Web server ────────────────────────────────────────────────────────────────

type webServer struct {
	jobs        *jobManager
	token       string
	monitors    *monitor.Runner
	schedulerOn bool
}

func newWebServer() *webServer {
	return &webServer{
		jobs:  newJobManager(),
		token: randomToken(),
		monitors: newMonitorRunner(func(msg string) {
			fmt.Printf("  %s  %s\n", time.Now().Format("15:04:05"), msg)
		}),
	}
}

func (s *webServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/scans", s.handleListScans)
	mux.HandleFunc("/api/scan/", s.handleScanFile)  // /api/scan/{file}[/html|/download]
	mux.HandleFunc("/api/newscan", s.handleNewScan) // POST
	mux.HandleFunc("/api/job/", s.handleJob)        // /api/job/{id}[/events|/report|/html|/download|/save]
	mux.HandleFunc("/api/compare", s.handleCompare) // ?a=<ref>&b=<ref>
	mux.HandleFunc("/api/worldmap", s.handleWorldMap)
	mux.HandleFunc("/api/monitors", s.handleMonitors) // GET list, POST add
	mux.HandleFunc("/api/monitors/", s.handleMonitor) // POST /api/monitors/{id}/{run|pause|resume|delete|test}
	mux.HandleFunc("/api/alerts", s.handleAlerts)     // ?target=&limit=
	mux.HandleFunc("/api/keys", s.handleKeys)         // GET status, POST {name,value}
	mux.HandleFunc("/api/keys/test", s.handleKeyTest) // POST {name}
	return mux
}

func (s *webServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, "ReconX engine API. Its dashboard is Argus: open http://127.0.0.1:8000/app/ (the ThreatLens stack runs this engine for you).\n")
}

// handleConfig returns the session token the page must echo back on POSTs.
func (s *webServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	tl := threatlens.Config{}.FromEnv()
	writeJSON(w, map[string]any{"token": s.token, "threatlens": tl.Configured(), "threatlens_url": tl.URL})
}

// handleListScans returns summaries of saved scans (reports/ dir) plus finished
// dashboard scans from this session that have not been saved to disk yet.
func (s *webServer) handleListScans(w http.ResponseWriter, r *http.Request) {
	out := append(s.jobs.sessionSummaries(), listScanSummaries()...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp > out[j].Timestamp })
	writeJSON(w, out)
}

// handleScanFile routes the saved-report endpoints:
//
//	/api/scan/{file}           full JSON report
//	/api/scan/{file}/html      rendered HTML report, for in-browser viewing
//	/api/scan/{file}/download  ?format=json|html|md as a file attachment
func (s *webServer) handleScanFile(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	name, action, _ := strings.Cut(rest, "/")
	if !isSafeReportName(name) || !strings.HasSuffix(name, ".json") {
		http.Error(w, "invalid report name", http.StatusBadRequest)
		return
	}
	data, err := os.ReadFile(filepath.Join("reports", name))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	switch action {
	case "":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	case "html", "download", "graph", "geo":
		var rep models.ScanReport
		if err := json.Unmarshal(data, &rep); err != nil {
			http.Error(w, "report file is corrupt", http.StatusInternalServerError)
			return
		}
		switch action {
		case "html":
			renderInlineHTML(w, &rep)
		case "graph":
			writeGraph(w, r, &rep)
		case "geo":
			writeGeo(w, &rep)
		default:
			writeReportDownload(w, r, &rep, strings.TrimSuffix(name, ".json"))
		}
	default:
		http.NotFound(w, r)
	}
}

// handleNewScan starts a scan job and returns its id.
func (s *webServer) handleNewScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-ReconX-Token") != s.token {
		http.Error(w, "invalid session token — reload the page", http.StatusForbidden)
		return
	}
	var opts ScanOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	opts.Target = strings.TrimSpace(opts.Target)
	if opts.Target == "" {
		http.Error(w, "target is required", http.StatusBadRequest)
		return
	}
	// Every pipeline phase operates on a domain; anything else would "complete"
	// with an empty report, so reject it up front.
	parsed, err := target.Parse(opts.Target)
	if err != nil || parsed.Type != models.TargetTypeDomain {
		http.Error(w, fmt.Sprintf("%q is not a domain — enter a domain such as example.com", opts.Target), http.StatusBadRequest)
		return
	}
	switch opts.Mode {
	case "":
		opts.Mode = "passive"
	case "passive", "active", "both":
	default:
		http.Error(w, "mode must be passive, active, or both", http.StatusBadRequest)
		return
	}
	if opts.wantsActive() && !opts.Authorized {
		http.Error(w, "active scans require the authorization confirmation", http.StatusForbidden)
		return
	}

	job := s.jobs.start(opts)
	writeJSON(w, map[string]string{"job_id": job.ID})
}

// handleJob routes /api/job/{id} (status), /api/job/{id}/events (SSE),
// /api/job/{id}/report (report JSON), /api/job/{id}/html (rendered report),
// /api/job/{id}/download, and /api/job/{id}/save (POST, writes to reports/).
func (s *webServer) handleJob(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/job/")
	id, action, _ := strings.Cut(rest, "/")
	job := s.jobs.get(id)
	if job == nil {
		http.NotFound(w, r)
		return
	}

	switch action {
	case "":
		job.mu.Lock()
		defer job.mu.Unlock()
		resp := map[string]interface{}{"id": job.ID, "status": job.Status, "events": job.Events}
		if job.SavedFile != "" {
			resp["file"] = job.SavedFile
		}
		if job.Err != "" {
			resp["error"] = job.Err
		}
		writeJSON(w, resp)
	case "events":
		s.streamJob(w, r, job)
	case "report", "html", "download", "graph", "geo":
		rep := job.report()
		if rep == nil {
			http.Error(w, "report not ready", http.StatusNotFound)
			return
		}
		switch action {
		case "report":
			writeJSON(w, rep)
		case "html":
			renderInlineHTML(w, rep)
		case "graph":
			writeGraph(w, r, rep)
		case "geo":
			writeGeo(w, rep)
		default:
			writeReportDownload(w, r, rep, reportBaseName(rep))
		}
	case "save":
		s.handleJobSave(w, r, job)
	default:
		http.NotFound(w, r)
	}
}

// handleJobSave writes a finished dashboard scan to reports/ (JSON, HTML, MD)
// and the drift database, after which it appears in history permanently.
func (s *webServer) handleJobSave(w http.ResponseWriter, r *http.Request, job *Job) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-ReconX-Token") != s.token {
		http.Error(w, "invalid session token — reload the page", http.StatusForbidden)
		return
	}

	job.mu.Lock()
	defer job.mu.Unlock()
	if job.Result == nil || job.Result.Report == nil {
		http.Error(w, "report not ready", http.StatusConflict)
		return
	}
	if job.SavedFile == "" {
		files := persistScan(r.Context(), job.Result.Report, job.Finished.Sub(job.Started))
		for _, f := range files {
			if strings.HasSuffix(f, ".json") {
				job.SavedFile = filepath.Base(f)
			}
		}
		if job.SavedFile == "" {
			http.Error(w, "could not write report files", http.StatusInternalServerError)
			return
		}
		job.Result.Files = files
	}
	writeJSON(w, map[string]string{"file": job.SavedFile})
}

// handleCompare diffs two scans of the same target. Each ref is a saved
// report file name or "job:<id>" for an unsaved scan from this session.
func (s *webServer) handleCompare(w http.ResponseWriter, r *http.Request) {
	a, errA := s.resolveReport(r.URL.Query().Get("a"))
	b, errB := s.resolveReport(r.URL.Query().Get("b"))
	if errA != nil || errB != nil {
		http.Error(w, "both scans must exist (a and b)", http.StatusBadRequest)
		return
	}
	if !strings.EqualFold(targetValue(a), targetValue(b)) {
		http.Error(w, "scans are of different targets", http.StatusBadRequest)
		return
	}
	writeJSON(w, history.Compare(a, b, r.URL.Query().Get("a"), r.URL.Query().Get("b")))
}

// resolveReport loads a report by reference: "job:<id>" or a reports/ file.
func (s *webServer) resolveReport(ref string) (*models.ScanReport, error) {
	if id, ok := strings.CutPrefix(ref, "job:"); ok {
		if job := s.jobs.get(id); job != nil {
			if rep := job.report(); rep != nil {
				return rep, nil
			}
		}
		return nil, fmt.Errorf("job not found")
	}
	if !isSafeReportName(ref) || !strings.HasSuffix(ref, ".json") {
		return nil, fmt.Errorf("invalid report name")
	}
	return history.Load(filepath.Join("reports", ref))
}

// handleKeys lists the API-key statuses (masked, never the keys) and, on
// POST, stores or removes a key. A stored key is used by the next scan.
func (s *webServer) handleKeys(w http.ResponseWriter, r *http.Request) {
	store := keystore.Open("")
	if r.Method == http.MethodPost {
		if !s.checkToken(w, r) {
			return
		}
		var body struct{ Name, Value string }
		if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&body); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		if err := store.SetAndApply(body.Name, body.Value); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if r.Method != http.MethodGet {
		http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
		return
	}
	statuses, err := store.Statuses()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"keys": statuses, "file": store.Path()})
}

// handleKeyTest checks the key a scan would use (environment or stored)
// against its service.
func (s *webServer) handleKeyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkToken(w, r) {
		return
	}
	var body struct{ Name string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&body); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	k, ok := keystore.Lookup(body.Name)
	if !ok {
		http.Error(w, "unknown key", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	writeJSON(w, keystore.Verify(ctx, k.Name, strings.TrimSpace(os.Getenv(k.Env))))
}

// checkToken rejects state-changing requests without the session token.
func (s *webServer) checkToken(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-ReconX-Token") != s.token {
		http.Error(w, "invalid session token — reload the page", http.StatusForbidden)
		return false
	}
	return true
}

// renderInlineHTML renders the styled HTML report for viewing in a browser tab.
func renderInlineHTML(w http.ResponseWriter, rep *models.ScanReport) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := reporter.RenderHTMLToWriter(rep, w); err != nil {
		http.Error(w, "could not render report", http.StatusInternalServerError)
	}
}

// writeReportDownload renders rep in the format named by ?format= and returns
// it as a file attachment called base.<ext>.
func writeReportDownload(w http.ResponseWriter, r *http.Request, rep *models.ScanReport, base string) {
	switch r.URL.Query().Get("format") {
	case "json":
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			http.Error(w, "could not encode report", http.StatusInternalServerError)
			return
		}
		attach(w, base+".json", "application/json")
		_, _ = w.Write(data)
	case "md", "markdown":
		attach(w, base+".md", "text/markdown; charset=utf-8")
		_, _ = w.Write([]byte(reporter.RenderMarkdown(rep)))
	case "html":
		attach(w, base+".html", "text/html; charset=utf-8")
		_ = reporter.RenderHTMLToWriter(rep, w)
	case "csv":
		attach(w, base+"_attack_surface.csv", "text/csv; charset=utf-8")
		_ = reporter.WriteHostsCSV(rep, w)
	case "graphml", "graph":
		g := correlate.BuildInfraGraph(rep, correlate.GraphOptions{IncludeHistorical: true, MaxHosts: 5000})
		if g == nil {
			http.Error(w, "this scan has no passive intelligence to graph", http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("format") == "graph" {
			attach(w, base+"_graph.json", "application/json")
			_ = json.NewEncoder(w).Encode(g)
			return
		}
		attach(w, base+"_graph.graphml", "application/graphml+xml")
		_ = correlate.WriteGraphML(g, w)
	default:
		http.Error(w, "format must be json, html, md, csv, graph, or graphml", http.StatusBadRequest)
	}
}

// writeGraph returns the infrastructure graph for the dashboard.
// ?historical=1 includes hosts that don't resolve now; ?max=N caps the hosts.
func writeGraph(w http.ResponseWriter, r *http.Request, rep *models.ScanReport) {
	opt := correlate.GraphOptions{IncludeHistorical: r.URL.Query().Get("historical") == "1"}
	if n, err := strconv.Atoi(r.URL.Query().Get("max")); err == nil && n > 0 && n <= 5000 {
		opt.MaxHosts = n
	}
	g := correlate.BuildInfraGraph(rep, opt)
	if g == nil {
		http.Error(w, "this scan has no passive intelligence to graph", http.StatusNotFound)
		return
	}
	writeJSON(w, g)
}

// writeGeo returns the map markers for a scan's geolocated IPs.
func writeGeo(w http.ResponseWriter, rep *models.ScanReport) {
	pts, missing := reporter.GeoPoints(rep.Intel)
	if pts == nil {
		pts = []reporter.GeoPoint{}
	}
	writeJSON(w, map[string]interface{}{"points": pts, "missing": missing})
}

// handleWorldMap serves the embedded land outline used by the map tab.
func (s *webServer) handleWorldMap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=86400")
	_, _ = io.WriteString(w, reporter.WorldLandPath)
}

// reportBaseName is the file name (without extension) used for a report.
func reportBaseName(rep *models.ScanReport) string {
	return fmt.Sprintf("recon_%s_%s", sanitizeForFilename(targetValue(rep)), rep.Timestamp.Format("20060102_150405"))
}

// attach sets download headers for a file response.
func attach(w http.ResponseWriter, filename, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))
}

// streamJob streams a job's progress events to the client via SSE. The full
// event history is replayed first, so a reconnecting client catches up.
func (s *webServer) streamJob(w http.ResponseWriter, r *http.Request, job *Job) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, history := job.subscribe()
	defer job.unsubscribe(ch)

	send := func(ev ProgressEvent) {
		data, _ := json.Marshal(ev)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}
	for _, ev := range history {
		send(ev)
	}
	if ch == nil {
		return // job already finished; history included the final event
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return // job finished and channel closed
			}
			send(ev)
		}
	}
}

// ── Job manager ─────────────────────────────────────────────────────────────

type Job struct {
	ID        string
	Opts      ScanOptions
	mu        sync.Mutex
	Events    []ProgressEvent
	Status    string // running | done | error
	Result    *ScanResult
	Err       string
	Started   time.Time
	Finished  time.Time
	SavedFile string // reports/ JSON file name once the user saves the scan
	subs      map[chan ProgressEvent]struct{}
}

type jobManager struct {
	mu   sync.Mutex
	jobs map[string]*Job
}

func newJobManager() *jobManager {
	return &jobManager{jobs: make(map[string]*Job)}
}

func (m *jobManager) get(id string) *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.jobs[id]
}

func (m *jobManager) start(opts ScanOptions) *Job {
	job := &Job{
		ID:      randomToken()[:12],
		Opts:    opts,
		Status:  "running",
		Started: time.Now(),
		subs:    make(map[chan ProgressEvent]struct{}),
	}
	m.mu.Lock()
	m.jobs[job.ID] = job
	m.mu.Unlock()

	go func() {
		// Active phases (crawl, browser) can run for minutes; give them room.
		// Heavy nmap profiles (aggressive/full) can run much longer, so extend
		// the budget when one is requested.
		budget := 8 * time.Minute
		if opts.Nmap {
			switch strings.ToLower(opts.NmapProfile) {
			case "aggressive":
				budget = 25 * time.Minute
			case "full":
				budget = 65 * time.Minute
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()

		// Hold back the pipeline's "done" event and send it only once the
		// result is stored, so a client reacting to it can fetch the report.
		var final *ProgressEvent
		res, err := RunScanPipeline(ctx, opts, func(ev ProgressEvent) {
			if ev.Step == "done" {
				final = &ev
				return
			}
			job.emit(ev)
		})

		if err != nil {
			job.finish("error", nil, err.Error(), ProgressEvent{Step: "error", Message: err.Error(), Percent: 100, Level: "error"})
			return
		}
		if final == nil {
			final = &ProgressEvent{Step: "done", Message: "Scan complete", Percent: 100, Level: "done"}
		}
		job.finish("done", res, "", *final)
	}()

	return job
}

// sessionSummaries returns history rows for finished, successful dashboard
// scans that have not been saved to disk (saved ones are listed from reports/).
func (m *jobManager) sessionSummaries() []scanSummary {
	m.mu.Lock()
	jobs := make([]*Job, 0, len(m.jobs))
	for _, j := range m.jobs {
		jobs = append(jobs, j)
	}
	m.mu.Unlock()

	out := []scanSummary{}
	for _, j := range jobs {
		j.mu.Lock()
		if j.Status == "done" && j.SavedFile == "" && j.Result != nil && j.Result.Report != nil {
			sum := summarize(j.Result.Report)
			sum.JobID = j.ID
			out = append(out, sum)
		}
		j.mu.Unlock()
	}
	return out
}

func (j *Job) emit(ev ProgressEvent) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Events = append(j.Events, ev)
	for ch := range j.subs {
		select {
		case ch <- ev:
		default: // drop if a slow client is backed up; it can reconnect for history
		}
	}
}

// finish records the outcome, delivers the final event to all subscribers,
// and closes their channels to end the SSE streams.
func (j *Job) finish(status string, res *ScanResult, errMsg string, final ProgressEvent) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Status = status
	j.Result = res
	j.Err = errMsg
	j.Finished = time.Now()
	j.Events = append(j.Events, final)
	for ch := range j.subs {
		select {
		case ch <- final:
		default:
		}
		close(ch)
	}
	j.subs = make(map[chan ProgressEvent]struct{})
}

func (j *Job) report() *models.ScanReport {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.Result == nil {
		return nil
	}
	return j.Result.Report
}

func (j *Job) subscribe() (chan ProgressEvent, []ProgressEvent) {
	j.mu.Lock()
	defer j.mu.Unlock()
	history := make([]ProgressEvent, len(j.Events))
	copy(history, j.Events)
	if j.Status != "running" {
		return nil, history // already finished; nothing more will come
	}
	ch := make(chan ProgressEvent, 64)
	j.subs[ch] = struct{}{}
	return ch, history
}

func (j *Job) unsubscribe(ch chan ProgressEvent) {
	if ch == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	delete(j.subs, ch)
}

// ── Scan history (from reports/ dir) ───────────────────────────────────────────

type scanSummary struct {
	File       string `json:"file,omitempty"`   // saved report in reports/
	JobID      string `json:"job_id,omitempty"` // unsaved scan from this session
	Target     string `json:"target"`
	Timestamp  string `json:"timestamp"`
	Mode       string `json:"mode"`
	HasPassive bool   `json:"has_passive"`
	HasActive  bool   `json:"has_active"`
	Subdomains int    `json:"subdomains"`
	LiveHosts  int    `json:"live_hosts"`
	Findings   int    `json:"findings"`
	High       int    `json:"high"` // includes CRITICAL
	Medium     int    `json:"medium"`
	Low        int    `json:"low"`
	Info       int    `json:"info"`
}

func listScanSummaries() []scanSummary {
	entries, err := os.ReadDir("reports")
	if err != nil {
		return []scanSummary{}
	}
	out := []scanSummary{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "recon_") || !strings.HasSuffix(name, ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join("reports", name))
		if err != nil {
			continue
		}
		var rep models.ScanReport
		if err := json.Unmarshal(data, &rep); err != nil || isEmptyReport(&rep) {
			continue
		}
		sum := summarize(&rep)
		sum.File = name
		out = append(out, sum)
	}
	return out
}

// summarize computes the history-row metrics for a report.
func summarize(rep *models.ScanReport) scanSummary {
	sum := scanSummary{
		Target:     strings.ToLower(targetValue(rep)),
		Timestamp:  rep.Timestamp.UTC().Format(time.RFC3339),
		Mode:       reportMode(rep),
		HasPassive: hasPassiveData(rep),
		HasActive:  rep.ActiveRecon != nil,
		Subdomains: len(rep.Assets),
	}
	if rep.Correlation != nil {
		sum.LiveHosts = rep.Correlation.LiveAssets
	}
	if rep.ActiveRecon != nil {
		sum.Findings = len(rep.ActiveRecon.Findings)
		for _, f := range rep.ActiveRecon.Findings {
			switch strings.ToUpper(f.Severity) {
			case models.SeverityCritical, models.SeverityHigh:
				sum.High++
			case models.SeverityMedium:
				sum.Medium++
			case models.SeverityLow:
				sum.Low++
			default:
				sum.Info++
			}
		}
	}
	return sum
}

func targetValue(rep *models.ScanReport) string {
	if rep.Target != nil {
		return rep.Target.Value
	}
	return "(unknown)"
}

func hasPassiveData(rep *models.ScanReport) bool {
	return rep.RDAP != nil || rep.DNS != nil || len(rep.Assets) > 0 || rep.Correlation != nil
}

// isEmptyReport reports whether a scan produced no data at all (e.g. a
// non-domain target that no module could act on).
func isEmptyReport(rep *models.ScanReport) bool {
	return !hasPassiveData(rep) && rep.ActiveRecon == nil && rep.WebMap == nil
}

func reportMode(rep *models.ScanReport) string {
	if rep.ActiveRecon != nil || rep.WebMap != nil {
		if hasPassiveData(rep) {
			return "both"
		}
		return "active"
	}
	return "passive"
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// isSafeReportName blocks path traversal in user-supplied report names.
func isSafeReportName(name string) bool {
	return name != "" && !strings.ContainsAny(name, `/\`) && !strings.Contains(name, "..")
}
