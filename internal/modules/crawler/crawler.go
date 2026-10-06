package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"reconx/pkg/models"
)

// Options configures the web crawler behaviour.
type Options struct {
	MaxDepth    int
	MaxPages    int
	Timeout     time.Duration
	UserAgent   string
	SameOrigin  bool
}

// DefaultOptions returns sensible crawler defaults.
func DefaultOptions() Options {
	return Options{
		MaxDepth:   3,
		MaxPages:   50,
		Timeout:    10 * time.Second,
		UserAgent:  "ReconX/2.0 (security assessment; authorized)",
		SameOrigin: true,
	}
}

// Result holds everything collected during a crawl.
type Result struct {
	Pages      []models.WebPage
	Forms      []models.FormInfo
	APIs       []models.APIEndpoint
	ScriptURLs []string
	DownloadLinks []string
}

type queueItem struct {
	url   string
	depth int
}

// Crawl performs a BFS crawl starting at rootURL, returning collected page data.
func Crawl(ctx context.Context, rootURL string, opts Options) (*Result, error) {
	parsed, err := url.Parse(rootURL)
	if err != nil {
		return nil, fmt.Errorf("invalid root URL: %w", err)
	}
	// Ensure scheme
	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}

	baseDomain := parsed.Hostname()
	client := &http.Client{
		Timeout: opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	var mu sync.Mutex
	visited := make(map[string]bool)
	result := &Result{}

	queue := []queueItem{{url: parsed.String(), depth: 0}}

	for len(queue) > 0 && len(result.Pages) < opts.MaxPages {
		select {
		case <-ctx.Done():
			return result, nil
		default:
		}

		item := queue[0]
		queue = queue[1:]

		mu.Lock()
		if visited[item.url] {
			mu.Unlock()
			continue
		}
		visited[item.url] = true
		mu.Unlock()

		page, links, scripts, downloads, forms, apis := fetchPage(ctx, client, item.url, baseDomain, opts.UserAgent)
		if page == nil {
			continue
		}

		mu.Lock()
		result.Pages = append(result.Pages, *page)
		result.Forms = append(result.Forms, forms...)
		result.APIs = append(result.APIs, apis...)
		mu.Unlock()

		// Collect scripts uniquely
		for _, s := range scripts {
			mu.Lock()
			found := false
			for _, existing := range result.ScriptURLs {
				if existing == s {
					found = true
					break
				}
			}
			if !found {
				result.ScriptURLs = append(result.ScriptURLs, s)
			}
			mu.Unlock()
		}

		// Collect download links
		for _, d := range downloads {
			mu.Lock()
			result.DownloadLinks = append(result.DownloadLinks, d)
			mu.Unlock()
		}

		// Enqueue new links
		if item.depth < opts.MaxDepth {
			for _, link := range links {
				if opts.SameOrigin {
					lu, err := url.Parse(link)
					if err != nil || lu.Hostname() != baseDomain {
						continue
					}
				}
				mu.Lock()
				if !visited[link] {
					queue = append(queue, queueItem{url: link, depth: item.depth + 1})
				}
				mu.Unlock()
			}
		}
	}

	return result, nil
}

// downloadExtensions is the set of file extensions considered downloads.
var downloadExtensions = map[string]bool{
	".pdf": true, ".zip": true, ".exe": true, ".xlsx": true,
	".xls": true, ".doc": true, ".docx": true, ".ppt": true,
	".pptx": true, ".csv": true, ".tar": true, ".gz": true,
	".rar": true, ".7z": true, ".apk": true, ".dmg": true,
}

// csrfFieldNames are common CSRF token field names.
var csrfFieldNames = []string{"csrf", "csrftoken", "_token", "authenticity_token", "__requestverificationtoken"}

// apiEndpointRe matches API-shaped URL paths in JS.
var apiEndpointRe = regexp.MustCompile(`(?i)['"](/(?:api|v\d+|graphql|rest|service)[^'"<>\s]{0,80})['"]`)

// hrefRe extracts href values from anchor tags.
var hrefRe = regexp.MustCompile(`(?i)<a[^>]+href\s*=\s*["']([^"'#\s][^"']*?)["']`)

// srcRe extracts src from script tags.
var srcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)

// formRe finds form blocks.
var formRe = regexp.MustCompile(`(?is)<form[^>]*>.*?</form>`)

// inputRe finds input fields.
var inputRe = regexp.MustCompile(`(?i)<input[^>]+>`)

// attrRe extracts a named HTML attribute value.
func attrVal(tag, attr string) string {
	re := regexp.MustCompile(`(?i)\b` + attr + `\s*=\s*["']?([^"'\s>]*)`)
	m := re.FindStringSubmatch(tag)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

// titleRe extracts the page title.
var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func fetchPage(ctx context.Context, client *http.Client, rawURL, baseDomain, userAgent string) (
	*models.WebPage, []string, []string, []string, []models.FormInfo, []models.APIEndpoint) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, nil, nil, nil, nil
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, nil, nil, nil
	}
	defer resp.Body.Close()

	// Only process HTML
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml") {
		// Still record as a page entry
		page := &models.WebPage{
			URL:        rawURL,
			StatusCode: resp.StatusCode,
		}
		return page, nil, nil, nil, nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB cap
	if err != nil {
		return nil, nil, nil, nil, nil, nil
	}
	content := string(body)

	// Extract title
	title := ""
	if m := titleRe.FindStringSubmatch(content); len(m) > 1 {
		title = strings.TrimSpace(m[1])
	}

	// Extract links
	var links []string
	base, _ := url.Parse(rawURL)
	for _, m := range hrefRe.FindAllStringSubmatch(content, -1) {
		href := m[1]
		if strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") {
			continue
		}
		resolved, err := base.Parse(href)
		if err != nil {
			continue
		}
		resolved.Fragment = ""
		resolved.RawQuery = stripTrackingParams(resolved.RawQuery)
		links = append(links, resolved.String())
	}

	// Extract script URLs
	var scripts []string
	for _, m := range srcRe.FindAllStringSubmatch(content, -1) {
		src := m[1]
		resolved, err := base.Parse(src)
		if err != nil {
			continue
		}
		scripts = append(scripts, resolved.String())
	}

	// Extract download links
	var downloads []string
	for _, link := range links {
		lu, err := url.Parse(link)
		if err != nil {
			continue
		}
		ext := strings.ToLower(lu.Path[strings.LastIndex(lu.Path, ".")+1:])
		if downloadExtensions["."+ext] {
			downloads = append(downloads, link)
		}
	}

	// Extract forms
	forms := extractForms(content, rawURL, base)

	// Extract API endpoints from JS inline/regex
	var apis []models.APIEndpoint
	for _, m := range apiEndpointRe.FindAllStringSubmatch(content, -1) {
		endpoint := m[1]
		resolved, err := base.Parse(endpoint)
		if err != nil {
			continue
		}
		apis = append(apis, models.APIEndpoint{
			URL:    resolved.String(),
			Source: "js_regex",
		})
	}

	page := &models.WebPage{
		URL:        rawURL,
		Title:      title,
		StatusCode: resp.StatusCode,
		Links:      links,
		Forms:      forms,
		APIs:       apis,
	}

	return page, links, scripts, downloads, forms, apis
}

func extractForms(content, pageURL string, base *url.URL) []models.FormInfo {
	var forms []models.FormInfo

	for _, formHTML := range formRe.FindAllString(content, -1) {
		action := attrVal(formHTML, "action")
		method := strings.ToUpper(attrVal(formHTML, "method"))
		if method == "" {
			method = "GET"
		}
		enctype := attrVal(formHTML, "enctype")

		// Resolve action URL
		actionURL := pageURL
		if action != "" {
			if resolved, err := base.Parse(action); err == nil {
				actionURL = resolved.String()
			}
		}

		var fields []models.FormField
		hasCSRF := false
		isLogin := false
		isFileUpload := strings.Contains(strings.ToLower(enctype), "multipart")

		for _, inputTag := range inputRe.FindAllString(formHTML, -1) {
			name := strings.ToLower(attrVal(inputTag, "name"))
			typ := strings.ToLower(attrVal(inputTag, "type"))
			if typ == "" {
				typ = "text"
			}

			fields = append(fields, models.FormField{
				Name:  name,
				Type:  typ,
				Value: attrVal(inputTag, "value"),
			})

			// CSRF detection
			for _, csrf := range csrfFieldNames {
				if strings.Contains(name, csrf) {
					hasCSRF = true
					break
				}
			}

			// Login detection
			if typ == "password" {
				isLogin = true
			}
			if typ == "file" {
				isFileUpload = true
			}
		}

		forms = append(forms, models.FormInfo{
			PageURL:      pageURL,
			Action:       actionURL,
			Method:       method,
			Fields:       fields,
			HasCSRFToken: hasCSRF,
			IsLogin:      isLogin,
			IsFileUpload: isFileUpload,
		})
	}
	return forms
}

// stripTrackingParams removes common tracking query parameters for URL dedup.
func stripTrackingParams(rawQuery string) string {
	trackingParams := map[string]bool{
		"utm_source": true, "utm_medium": true, "utm_campaign": true,
		"utm_term": true, "utm_content": true, "fbclid": true,
		"gclid": true, "ref": true,
	}
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	for k := range trackingParams {
		vals.Del(k)
	}
	return vals.Encode()
}
