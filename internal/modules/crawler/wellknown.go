package crawler

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// WellKnownResult holds data from well-known security/crawl files.
type WellKnownResult struct {
	RobotsTxt   string
	SitemapURLs []string
	SecurityTxt string
}

// FetchWellKnown fetches robots.txt, sitemap.xml, and security.txt for a base URL.
func FetchWellKnown(ctx context.Context, baseURL string) *WellKnownResult {
	// Normalize base URL
	base := strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(base, "http") {
		base = "https://" + base
	}

	client := &http.Client{Timeout: 10 * time.Second}
	result := &WellKnownResult{}

	// Fetch robots.txt
	if body := fetchText(ctx, client, base+"/robots.txt"); body != "" {
		result.RobotsTxt = body
		// Parse sitemap references from robots.txt
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "sitemap:") {
				sitemapURL := strings.TrimSpace(line[8:])
				if sitemapURL != "" {
					result.SitemapURLs = append(result.SitemapURLs, sitemapURL)
				}
			}
		}
	}

	// Fetch sitemap.xml if not already found via robots.txt
	if len(result.SitemapURLs) == 0 {
		if body := fetchText(ctx, client, base+"/sitemap.xml"); body != "" {
			// Extract loc URLs from sitemap XML
			for _, loc := range extractSitemapLocs(body) {
				result.SitemapURLs = append(result.SitemapURLs, loc)
			}
		}
		// Also try sitemap_index.xml
		if body := fetchText(ctx, client, base+"/sitemap_index.xml"); body != "" {
			for _, loc := range extractSitemapLocs(body) {
				result.SitemapURLs = append(result.SitemapURLs, loc)
			}
		}
	}

	// Fetch security.txt (two standard locations)
	if body := fetchText(ctx, client, base+"/.well-known/security.txt"); body != "" {
		result.SecurityTxt = body
	} else if body := fetchText(ctx, client, base+"/security.txt"); body != "" {
		result.SecurityTxt = body
	}

	return result
}

func fetchText(ctx context.Context, client *http.Client, rawURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "ReconX/2.0 (security assessment; authorized)")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return ""
	}
	return string(data)
}

// extractSitemapLocs extracts <loc> URLs from a sitemap XML document.
func extractSitemapLocs(xml string) []string {
	var locs []string
	remaining := xml
	for {
		start := strings.Index(strings.ToLower(remaining), "<loc>")
		if start == -1 {
			break
		}
		end := strings.Index(strings.ToLower(remaining[start:]), "</loc>")
		if end == -1 {
			break
		}
		loc := strings.TrimSpace(remaining[start+5 : start+end])
		if loc != "" {
			locs = append(locs, loc)
		}
		remaining = remaining[start+end+6:]
	}
	return locs
}
