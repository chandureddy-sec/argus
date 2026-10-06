// Package apicapture discovers API endpoints by loading a page in a headless
// browser and recording the XHR/fetch requests it actually makes — far higher
// signal than regex-scanning JS, since it captures real runtime calls. This is
// an active, target-contacting module: it loads and executes the target's pages.
package apicapture

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"reconx/pkg/models"
)

// Options configures a capture run.
type Options struct {
	// WaitAfterLoad is how long to let the page settle so late XHR/fetch calls
	// (lazy-loaded data, polling) are observed.
	WaitAfterLoad time.Duration
	// Timeout bounds the whole browser session.
	Timeout time.Duration
	// Headless runs Chrome without a visible window (default true).
	Headless bool
	// UserAgent overrides the browser UA when set.
	UserAgent string
}

// DefaultOptions returns sensible capture defaults.
func DefaultOptions() Options {
	return Options{
		WaitAfterLoad: 4 * time.Second,
		Timeout:       35 * time.Second,
		Headless:      true,
		UserAgent:     "ReconX/2.0 (security assessment; authorized)",
	}
}

type requestInfo struct {
	url    string
	method string
	rtype  network.ResourceType
}

// Capture loads targetURL in a headless browser and returns the deduplicated
// API-like endpoints (XHR and Fetch requests) the page issued, tagged with
// source "network_intercept". It requires a Chrome/Chromium binary on the host;
// a launch failure is returned as an error. Partial results observed before a
// timeout are still returned.
func Capture(ctx context.Context, targetURL string, opts Options) ([]models.APIEndpoint, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultOptions().Timeout
	}
	if opts.WaitAfterLoad <= 0 {
		opts.WaitAfterLoad = DefaultOptions().WaitAfterLoad
	}

	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", opts.Headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	if opts.UserAgent != "" {
		allocOpts = append(allocOpts, chromedp.UserAgent(opts.UserAgent))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, allocOpts...)
	defer cancelAlloc()

	// Silence chromedp's internal logger: with a newer Chrome than the pinned
	// cdproto, benign "unknown ... value" unmarshal warnings are emitted for
	// event types we don't consume. Routing them to a no-op keeps tool output
	// clean without affecting the request/response events we rely on.
	noop := func(string, ...interface{}) {}
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx,
		chromedp.WithErrorf(noop),
		chromedp.WithLogf(noop),
	)
	defer cancelBrowser()

	runCtx, cancelRun := context.WithTimeout(browserCtx, opts.Timeout)
	defer cancelRun()

	var mu sync.Mutex
	requests := make(map[network.RequestID]*requestInfo)
	statuses := make(map[network.RequestID]int64)

	chromedp.ListenTarget(runCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			mu.Lock()
			requests[e.RequestID] = &requestInfo{
				url:    e.Request.URL,
				method: e.Request.Method,
				rtype:  e.Type,
			}
			mu.Unlock()
		case *network.EventResponseReceived:
			mu.Lock()
			statuses[e.RequestID] = e.Response.Status
			mu.Unlock()
		}
	})

	runErr := chromedp.Run(runCtx,
		network.Enable(),
		chromedp.Navigate(targetURL),
		chromedp.Sleep(opts.WaitAfterLoad),
	)

	mu.Lock()
	defer mu.Unlock()

	seen := make(map[string]bool)
	var endpoints []models.APIEndpoint
	for id, r := range requests {
		// Keep only runtime API traffic, not documents/images/styles/scripts.
		if r.rtype != network.ResourceTypeXHR && r.rtype != network.ResourceTypeFetch {
			continue
		}
		key := r.method + " " + r.url
		if seen[key] {
			continue
		}
		seen[key] = true

		ep := models.APIEndpoint{
			URL:    r.url,
			Method: r.method,
			Source: "network_intercept",
		}
		if s, ok := statuses[id]; ok {
			ep.StatusCode = int(s)
		}
		endpoints = append(endpoints, ep)
	}

	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].URL != endpoints[j].URL {
			return endpoints[i].URL < endpoints[j].URL
		}
		return endpoints[i].Method < endpoints[j].Method
	})

	// A timeout after we've already captured traffic is not a failure — return
	// what we saw. Only surface the error when nothing was captured.
	if len(endpoints) > 0 {
		return endpoints, nil
	}
	return endpoints, runErr
}
