package models

import "time"

// TLSInfo holds SSL/TLS certificate and cipher intelligence for a host.
type TLSInfo struct {
	Host            string    `json:"host"`
	Port            int       `json:"port"`
	Issuer          string    `json:"issuer"`
	Subject         string    `json:"subject"`
	SANs            []string  `json:"sans,omitempty"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
	IsExpired       bool      `json:"is_expired"`
	TLSVersion      string    `json:"tls_version"`
	CipherSuite     string    `json:"cipher_suite"`
	IsSelfSigned    bool      `json:"is_self_signed"`
	HSTSHeader      string    `json:"hsts_header,omitempty"`
}

// HTTPProbeResult holds the result of an HTTP probe against a target.
type HTTPProbeResult struct {
	URL           string            `json:"url"`
	FinalURL      string            `json:"final_url"`
	StatusCode    int               `json:"status_code"`
	Title         string            `json:"title,omitempty"`
	Headers       map[string]string `json:"headers"`
	Cookies       []CookieInfo      `json:"cookies,omitempty"`
	RedirectChain []string          `json:"redirect_chain,omitempty"`
	Server        string            `json:"server,omitempty"`
	PoweredBy     string            `json:"powered_by,omitempty"`
	ResponseTime  int64             `json:"response_time_ms"`
}

// CookieInfo describes a single HTTP cookie and its security flags.
type CookieInfo struct {
	Name     string `json:"name"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"`
	Expires  string `json:"expires,omitempty"`
}

// TechStack holds detected technologies for a target.
type TechStack struct {
	WebServer  string   `json:"web_server,omitempty"`
	Language   string   `json:"language,omitempty"`
	Framework  string   `json:"framework,omitempty"`
	CDN        string   `json:"cdn,omitempty"`
	WAF        string   `json:"waf,omitempty"`
	CMS        string   `json:"cms,omitempty"`
	OtherTechs []string `json:"other_techs,omitempty"`
}

// PortResult holds the result of a port scan probe.
type PortResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"` // "open", "closed", "filtered"
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

// HeaderFinding is a security-analyzed HTTP response header result.
type HeaderFinding struct {
	Header   string `json:"header"`
	Present  bool   `json:"present"`
	Value    string `json:"value,omitempty"`
	Severity string `json:"severity"`
	Note     string `json:"note"`
}

// WebPage represents a crawled page with its metadata.
type WebPage struct {
	URL        string        `json:"url"`
	Title      string        `json:"title,omitempty"`
	StatusCode int           `json:"status_code"`
	Links      []string      `json:"links,omitempty"`
	Forms      []FormInfo    `json:"forms,omitempty"`
	APIs       []APIEndpoint `json:"apis,omitempty"`
}

// FormInfo describes an HTML form discovered during crawling.
type FormInfo struct {
	PageURL      string      `json:"page_url"`
	Action       string      `json:"action"`
	Method       string      `json:"method"`
	Fields       []FormField `json:"fields"`
	HasCSRFToken bool        `json:"has_csrf_token"`
	IsLogin      bool        `json:"is_login"`
	IsFileUpload bool        `json:"is_file_upload"`
}

// FormField is a single input within an HTML form.
type FormField struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

// APIEndpoint is a discovered API endpoint.
type APIEndpoint struct {
	URL        string `json:"url"`
	Method     string `json:"method,omitempty"`
	Source     string `json:"source"` // "js_regex", "network_intercept"
	StatusCode int    `json:"status_code,omitempty"`
}

// JSFinding holds results of JavaScript file analysis.
type JSFinding struct {
	ScriptURL          string   `json:"script_url"`
	IsThirdParty       bool     `json:"is_third_party"`
	Secrets            []string `json:"secrets,omitempty"` // matched patterns (no actual secret values stored)
	SourceMapURL       string   `json:"source_map_url,omitempty"`
	SourceMapReachable bool     `json:"source_map_reachable"`
}

// ActiveReconResult holds all active recon module output.
type ActiveReconResult struct {
	TLS          *TLSInfo         `json:"tls,omitempty"`
	HTTPProbe    *HTTPProbeResult `json:"http_probe,omitempty"`
	TechStack    *TechStack       `json:"tech_stack,omitempty"`
	OpenPorts    []PortResult     `json:"open_ports,omitempty"`
	HeaderChecks []HeaderFinding  `json:"header_analysis,omitempty"`
	Findings     []Finding        `json:"findings,omitempty"`
	Nmap         *NmapResult      `json:"nmap,omitempty"`
}

// WebMapResult holds all web mapping module output.
type WebMapResult struct {
	CrawledPages []WebPage     `json:"crawled_pages,omitempty"`
	Forms        []FormInfo    `json:"forms,omitempty"`
	APIs         []APIEndpoint `json:"api_endpoints,omitempty"`
	JSFindings   []JSFinding   `json:"js_analysis,omitempty"`
	RobotsTxt    string        `json:"robots_txt,omitempty"`
	SitemapURLs  []string      `json:"sitemap_urls,omitempty"`
	SecurityTxt  string        `json:"security_txt,omitempty"`
	TotalPages   int           `json:"total_pages_crawled"`
}
