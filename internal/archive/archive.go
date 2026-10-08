// Package archive saves the raw HTTP responses ReconX's passive sources
// return, so every parsed data point can be traced back to the bytes a
// third party actually sent.
//
// Archiving is opt-in per scan. Install wraps http.DefaultTransport once at
// startup; the wrapper only records requests whose context carries an
// *Archive (see WithArchive), so active-mode traffic and scans without
// archiving pass straight through. Request headers are never written (they
// hold API keys) and key-like query parameters are redacted in the manifest.
// DNS lookups are not HTTP and are not archived.
package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// MaxBody caps how much of one response is stored; the rest still reaches
// the provider, and the manifest marks the file as truncated.
const MaxBody = 20 << 20

// Entry is one archived response in the manifest.
type Entry struct {
	Seq         int       `json:"seq"`
	Time        time.Time `json:"time"`
	Method      string    `json:"method"`
	URL         string    `json:"url"` // key-like query parameters redacted
	Host        string    `json:"host"`
	Status      int       `json:"status,omitempty"`
	ContentType string    `json:"content_type,omitempty"`
	File        string    `json:"file,omitempty"` // relative to the archive directory
	Bytes       int       `json:"bytes"`
	SHA256      string    `json:"sha256,omitempty"`
	Truncated   bool      `json:"truncated,omitempty"`
	DurationMs  int64     `json:"duration_ms"`
	Error       string    `json:"error,omitempty"`
}

// Manifest is written to manifest.json when the archive is closed.
type Manifest struct {
	Target   string    `json:"target"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Note     string    `json:"note"`
	Entries  []Entry   `json:"entries"`
}

// Archive collects the responses of one scan into a directory.
type Archive struct {
	dir     string
	target  string
	started time.Time
	mu      sync.Mutex
	entries []Entry
	closed  bool
}

// New creates the archive directory (and its parents).
func New(dir, target string) (*Archive, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Archive{dir: dir, target: target, started: time.Now().UTC()}, nil
}

// Dir is the archive directory.
func (a *Archive) Dir() string { return a.dir }

// Count is the number of responses recorded so far.
func (a *Archive) Count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.entries)
}

// Close writes manifest.json. Responses arriving after Close are ignored.
func (a *Archive) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	m := Manifest{
		Target: a.target, Started: a.started, Finished: time.Now().UTC(), Entries: a.entries,
		Note: "Raw third-party responses captured during the passive scan. Request headers (API keys) are not stored; key-like URL parameters are redacted. DNS queries are not HTTP and are not included.",
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(a.dir, "manifest.json"), data, 0o644)
}

func (a *Archive) record(req *http.Request, resp *http.Response, body []byte, truncated bool, d time.Duration, rtErr error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	e := Entry{
		Seq: len(a.entries) + 1, Time: time.Now().UTC(), Method: req.Method,
		URL: Redact(req.URL), Host: req.URL.Hostname(), DurationMs: d.Milliseconds(),
	}
	if rtErr != nil {
		e.Error = rtErr.Error()
		a.entries = append(a.entries, e)
		return
	}
	e.Status, e.ContentType = resp.StatusCode, resp.Header.Get("Content-Type")
	e.Bytes, e.Truncated = len(body), truncated
	sum := sha256.Sum256(body)
	e.SHA256 = hex.EncodeToString(sum[:])
	e.File = fmt.Sprintf("%04d_%s%s", e.Seq, safeName(e.Host), ext(e.ContentType))
	if err := os.WriteFile(filepath.Join(a.dir, e.File), body, 0o644); err != nil {
		e.Error, e.File = "write failed: "+err.Error(), ""
	}
	a.entries = append(a.entries, e)
}

type ctxKey struct{}

// WithArchive returns a context whose outgoing HTTP requests are archived.
func WithArchive(ctx context.Context, a *Archive) context.Context {
	if a == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, a)
}

// FromContext returns the archive attached to ctx, if any.
func FromContext(ctx context.Context) *Archive {
	a, _ := ctx.Value(ctxKey{}).(*Archive)
	return a
}

// Transport records responses for requests whose context carries an Archive.
type Transport struct {
	Base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	a := FromContext(req.Context())
	if a == nil {
		return t.Base.RoundTrip(req)
	}
	start := time.Now()
	resp, err := t.Base.RoundTrip(req)
	if err != nil {
		a.record(req, nil, nil, false, time.Since(start), err)
		return resp, err
	}
	// Buffer what we store, then hand the provider those same bytes followed
	// by whatever is left (and any read error, which it sees as before).
	read, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	orig := resp.Body
	resp.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(read), orig), closer: orig}

	stored, truncated := read, len(read) > MaxBody
	if truncated {
		stored = read[:MaxBody]
	}
	a.record(req, resp, stored, truncated, time.Since(start), nil)
	return resp, nil
}

type readCloser struct {
	io.Reader
	closer io.Closer
}

func (r readCloser) Close() error { return r.closer.Close() }

var installOnce sync.Once

// Install wraps http.DefaultTransport with the archiving Transport. Call it
// once at startup, before any request is made; it is idempotent.
func Install() {
	installOnce.Do(func() {
		http.DefaultTransport = &Transport{Base: http.DefaultTransport}
	})
}

var secretParam = regexp.MustCompile(`(?i)^(api[-_]?key|apikey|key|token|access[-_]?token|auth|secret|password|sig|signature)$`)

// Redact returns the URL with key-like query parameter values replaced and
// any userinfo removed.
func Redact(u *url.URL) string {
	c := *u
	c.User = nil
	q := c.Query()
	changed := false
	for k := range q {
		if secretParam.MatchString(k) {
			q.Set(k, "REDACTED")
			changed = true
		}
	}
	if changed {
		c.RawQuery = q.Encode()
	}
	return c.String()
}

func ext(contentType string) string {
	mt, _, _ := mime.ParseMediaType(contentType)
	switch {
	case strings.Contains(mt, "json"):
		return ".json"
	case strings.Contains(mt, "html"):
		return ".html"
	case strings.Contains(mt, "xml"):
		return ".xml"
	default:
		return ".txt"
	}
}

func safeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '_'
	}, s)
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}
