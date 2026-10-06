package models

import "time"

// IntelVersion is bumped whenever the passive-intel parsers change shape, so
// stored reports record which parser produced them.
const IntelVersion = 1

// Evidence kinds distinguish how a piece of information was obtained.
const (
	EvidenceObserved = "observed" // returned directly by a source
	EvidenceEnriched = "enriched" // joined with another public source
	EvidenceInferred = "inferred" // a classification or prediction
)

// Source reliability levels used by the confidence model.
const (
	ReliabilityHigh       = "high"
	ReliabilityMediumHigh = "medium-high"
	ReliabilityMedium     = "medium"
	ReliabilityLow        = "low"
)

// Source run statuses.
const (
	SourceSuccess = "success"
	SourceTimeout = "timeout"
	SourceError   = "error"
	SourceSkipped = "skipped"
)

// PassiveIntel is the evidence-backed passive attack-surface model for a scan.
// Every field is built from public third-party sources or public DNS; nothing
// in it requires contacting the target's own infrastructure.
type PassiveIntel struct {
	Version      int                 `json:"version"`
	Sources      []SourceRun         `json:"sources"`
	Hosts        []HostIntel         `json:"hosts"`
	IPs          []IPInfo            `json:"ips,omitempty"`
	Certificates []CertInfo          `json:"certificates,omitempty"`
	CertSummary  CertSummary         `json:"certificate_summary"`
	DNSSEC       *DNSSECInfo         `json:"dnssec,omitempty"`
	CAA          *CAAInfo            `json:"caa,omitempty"`
	Email        *EmailSecurity      `json:"email_security,omitempty"`
	Nameservers  []ServerInfo        `json:"nameservers,omitempty"`
	MailServers  []ServerInfo        `json:"mail_servers,omitempty"`
	Providers    []ProviderUse       `json:"providers,omitempty"`
	Dangling     []DanglingIndicator `json:"dangling_dns,omitempty"`
	Aggregates   Aggregates          `json:"aggregates"`
	Changes      *ChangeSet          `json:"changes,omitempty"`
}

// SourceRun records the outcome of one data source during a scan.
type SourceRun struct {
	Name        string `json:"name"`
	Purpose     string `json:"purpose"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
	DurationMs  int64  `json:"duration_ms"`
	Results     int    `json:"results"`
	Reliability string `json:"reliability"`
}

// SourceEvidence is one source's observation of a host.
type SourceEvidence struct {
	Source      string     `json:"source"`
	Reliability string     `json:"reliability"`
	FirstSeen   *time.Time `json:"first_seen,omitempty"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
}

// HistoricalValue is a DNS value (IP or CNAME target) observed for a host,
// either now or in the past.
type HistoricalValue struct {
	Type      string     `json:"type"` // A | AAAA | CNAME
	Value     string     `json:"value"`
	Source    string     `json:"source"`
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
	Current   bool       `json:"current"`
}

// HostIntel is the per-subdomain record shown in the attack-surface table.
type HostIntel struct {
	Hostname        string            `json:"hostname"`
	Sources         []string          `json:"sources"`
	SourceCount     int               `json:"source_count"`
	Evidence        []SourceEvidence  `json:"evidence,omitempty"`
	Confidence      int               `json:"confidence"`       // 0-100
	ConfidenceLevel string            `json:"confidence_level"` // high | medium | low
	FirstSeen       *time.Time        `json:"first_seen,omitempty"`
	LastSeen        *time.Time        `json:"last_seen,omitempty"`
	Recency         string            `json:"recency"`    // current | recent | historical | stale
	DNSStatus       string            `json:"dns_status"` // resolves | nxdomain | no_address | error
	IPs             []string          `json:"ips,omitempty"`
	CNAMEs          []string          `json:"cnames,omitempty"`
	History         []HistoricalValue `json:"history,omitempty"`
	ASN             string            `json:"asn,omitempty"`
	Organization    string            `json:"organization,omitempty"`
	Country         string            `json:"country,omitempty"`
	Cloud           string            `json:"cloud,omitempty"` // inferred, e.g. "Likely AWS"
	CDN             string            `json:"cdn,omitempty"`   // inferred
	Certificates    int               `json:"certificates"`
	Role            string            `json:"role"` // inferred "Likely ..." classification
	Indicators      []string          `json:"indicators,omitempty"`
	Interest        string            `json:"interest"` // high | medium | low
	InterestScore   int               `json:"interest_score"`
	InterestFactors []string          `json:"interest_factors,omitempty"`
	Lifecycle       string            `json:"lifecycle"` // new | active | changed | historical
}

// IPInfo is an enriched IP address.
type IPInfo struct {
	IP           string   `json:"ip"`
	Version      string   `json:"version"` // IPv4 | IPv6
	Hostnames    []string `json:"hostnames,omitempty"`
	ASN          string   `json:"asn,omitempty"`
	ASName       string   `json:"as_name,omitempty"`
	Prefix       string   `json:"prefix,omitempty"`
	RIR          string   `json:"rir,omitempty"`
	Allocated    string   `json:"allocated,omitempty"`
	Organization string   `json:"organization,omitempty"`
	ISP          string   `json:"isp,omitempty"`
	Country      string   `json:"country,omitempty"`
	Region       string   `json:"region,omitempty"`
	City         string   `json:"city,omitempty"`
	Continent    string   `json:"continent,omitempty"`
	ReverseDNS   string   `json:"reverse_dns,omitempty"`
	Hosting      bool     `json:"hosting"`
	Provider     string   `json:"provider,omitempty"`      // inferred
	ProviderKind string   `json:"provider_kind,omitempty"` // cloud | cdn | hosting | ...
	Sources      []string `json:"sources,omitempty"`
}

// CertInfo is one certificate observed in Certificate Transparency logs.
type CertInfo struct {
	ID           int64     `json:"id"`
	Serial       string    `json:"serial,omitempty"`
	Issuer       string    `json:"issuer"`
	IssuerOrg    string    `json:"issuer_org,omitempty"`
	CommonName   string    `json:"common_name,omitempty"`
	SANs         []string  `json:"sans"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	ValidityDays int       `json:"validity_days"`
	Wildcard     bool      `json:"wildcard"`
	LoggedAt     time.Time `json:"logged_at,omitempty"`
	ExpiryStatus string    `json:"expiry_status"` // expired | lt7 | lt14 | lt30 | ok
	Indicators   []string  `json:"indicators,omitempty"`
	Source       string    `json:"source"`
}

// CertSummary aggregates certificate health over every certificate seen,
// including any not individually listed.
type CertSummary struct {
	Total      int     `json:"total"`
	Listed     int     `json:"listed"`
	Valid      int     `json:"valid"`
	Expired    int     `json:"expired"`
	Lt7        int     `json:"expiring_7d"`
	Lt14       int     `json:"expiring_14d"`
	Lt30       int     `json:"expiring_30d"`
	Wildcard   int     `json:"wildcard"`
	Issuers    []Count `json:"issuers,omitempty"`
	OldestSeen string  `json:"oldest_seen,omitempty"`
}

// DNSSECInfo describes the domain's DNSSEC posture.
type DNSSECInfo struct {
	Enabled    bool         `json:"enabled"`   // DS published in the parent zone
	Signed     bool         `json:"signed"`    // RRSIGs returned for the zone
	Validated  bool         `json:"validated"` // validating resolver set the AD flag
	Status     string       `json:"status"`    // human summary
	DS         []DSRecord   `json:"ds,omitempty"`
	Keys       []DNSKEYInfo `json:"dnskeys,omitempty"`
	Algorithms []string     `json:"algorithms,omitempty"`
	Error      string       `json:"error,omitempty"`
}

type DSRecord struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  string `json:"algorithm"`
	DigestType string `json:"digest_type"`
}

type DNSKEYInfo struct {
	KeyTag    uint16 `json:"key_tag"`
	Algorithm string `json:"algorithm"`
	Role      string `json:"role"` // KSK | ZSK
	Flags     uint16 `json:"flags"`
}

// CAAInfo is the parsed CAA policy.
type CAAInfo struct {
	Present   bool        `json:"present"`
	Records   []CAARecord `json:"records,omitempty"`
	Issue     []string    `json:"issue,omitempty"`
	IssueWild []string    `json:"issuewild,omitempty"`
	Iodef     []string    `json:"iodef,omitempty"`
	Posture   string      `json:"posture"` // none | restrictive | permissive | ...
	Notes     []string    `json:"notes,omitempty"`
}

type CAARecord struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// EmailSecurity groups the email-authentication posture.
type EmailSecurity struct {
	SPF            SPFInfo     `json:"spf"`
	DMARC          DMARCInfo   `json:"dmarc"`
	DKIM           DKIMInfo    `json:"dkim"`
	MTASTS         MTASTSInfo  `json:"mta_sts"`
	TLSRPT         TLSRPTInfo  `json:"tls_rpt"`
	MailProviders  []string    `json:"mail_providers,omitempty"` // inferred
	Score          int         `json:"score"`
	MaxScore       int         `json:"max_score"`
	ScoreBreakdown []ScoreItem `json:"score_breakdown"`
}

type ScoreItem struct {
	Control string `json:"control"`
	Points  int    `json:"points"`
	Max     int    `json:"max"`
	Reason  string `json:"reason"`
}

type SPFInfo struct {
	Present     bool           `json:"present"`
	Raw         string         `json:"raw,omitempty"`
	RecordCount int            `json:"record_count"`
	Valid       bool           `json:"valid"`
	Mechanisms  []SPFMechanism `json:"mechanisms,omitempty"`
	All         string         `json:"all,omitempty"` // e.g. "-all"
	Policy      string         `json:"policy,omitempty"`
	Redirect    string         `json:"redirect,omitempty"`
	LookupCount int            `json:"lookup_count"`
	Senders     []string       `json:"senders,omitempty"` // inferred services
	Issues      []string       `json:"issues,omitempty"`
}

type SPFMechanism struct {
	Qualifier string `json:"qualifier"` // + - ~ ?
	Type      string `json:"type"`
	Value     string `json:"value,omitempty"`
}

type DMARCInfo struct {
	Present         bool     `json:"present"`
	Raw             string   `json:"raw,omitempty"`
	Valid           bool     `json:"valid"`
	Policy          string   `json:"policy,omitempty"`
	SubdomainPolicy string   `json:"subdomain_policy,omitempty"`
	Pct             int      `json:"pct"`
	RUA             []string `json:"rua,omitempty"`
	RUF             []string `json:"ruf,omitempty"`
	ADKIM           string   `json:"adkim,omitempty"`
	ASPF            string   `json:"aspf,omitempty"`
	FO              string   `json:"fo,omitempty"`
	RI              string   `json:"ri,omitempty"`
	Posture         string   `json:"posture,omitempty"`
	Issues          []string `json:"issues,omitempty"`
}

type DKIMInfo struct {
	Checked []string       `json:"selectors_checked"`
	Found   []DKIMSelector `json:"found,omitempty"`
}

type DKIMSelector struct {
	Selector string `json:"selector"`
	Raw      string `json:"raw"`
	KeyType  string `json:"key_type,omitempty"`
	KeyBits  int    `json:"key_bits,omitempty"`
	Flags    string `json:"flags,omitempty"`
	Service  string `json:"service,omitempty"` // inferred from selector name
	Revoked  bool   `json:"revoked"`
}

type MTASTSInfo struct {
	Present bool   `json:"present"`
	Raw     string `json:"raw,omitempty"`
	ID      string `json:"id,omitempty"`
	Note    string `json:"note,omitempty"`
}

type TLSRPTInfo struct {
	Present bool     `json:"present"`
	Raw     string   `json:"raw,omitempty"`
	RUA     []string `json:"rua,omitempty"`
}

// ServerInfo describes an authoritative nameserver or MX host.
type ServerInfo struct {
	Hostname     string   `json:"hostname"`
	Priority     int      `json:"priority,omitempty"` // MX only
	IPs          []string `json:"ips,omitempty"`
	ASN          string   `json:"asn,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Country      string   `json:"country,omitempty"`
	Provider     string   `json:"provider,omitempty"` // inferred
}

// ProviderUse is an inferred third-party / cloud / CDN relationship.
type ProviderUse struct {
	Category string   `json:"category"` // Cloud | CDN | Email | DNS | SaaS ...
	Name     string   `json:"name"`
	Hosts    int      `json:"hosts"`
	Evidence []string `json:"evidence"`
}

// DanglingIndicator flags a CNAME that may point at a deprovisioned resource.
// It is an indicator for verification, never a confirmed takeover.
type DanglingIndicator struct {
	Hostname string `json:"hostname"`
	CNAME    string `json:"cname"`
	Service  string `json:"service,omitempty"`
	Reason   string `json:"reason"`
}

// Aggregates are the headline attack-surface metrics.
type Aggregates struct {
	Subdomains      int        `json:"subdomains"`
	Resolving       int        `json:"resolving"`
	UniqueIPs       int        `json:"unique_ips"`
	IPv4            int        `json:"ipv4"`
	IPv6            int        `json:"ipv6"`
	ASNs            int        `json:"asns"`
	Countries       int        `json:"countries"`
	Certificates    int        `json:"certificates"`
	HistoricalHosts int        `json:"historical_hosts"`
	HistoricalIPs   int        `json:"historical_ips"`
	HighInterest    int        `json:"high_interest"`
	ByCloud         []Count    `json:"by_cloud,omitempty"`
	ByCountry       []Count    `json:"by_country,omitempty"`
	ByRole          []Count    `json:"by_role,omitempty"`
	ByASN           []ASNCount `json:"by_asn,omitempty"`
}

type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type ASNCount struct {
	ASN       string   `json:"asn"`
	Name      string   `json:"name"`
	Hosts     int      `json:"hosts"`
	IPs       int      `json:"ips"`
	Countries []string `json:"countries,omitempty"`
	Provider  string   `json:"provider,omitempty"`
}

// ChangeSet is the difference between two scans of the same target.
type ChangeSet struct {
	PreviousScan time.Time     `json:"previous_scan"`
	PreviousFile string        `json:"previous_file,omitempty"`
	Summary      ChangeSummary `json:"summary"`
	Events       []ChangeEvent `json:"events,omitempty"`
}

type ChangeSummary struct {
	SubdomainsAdded   int `json:"subdomains_added"`
	SubdomainsRemoved int `json:"subdomains_removed"`
	HostsChanged      int `json:"hosts_changed"`
	IPsAdded          int `json:"ips_added"`
	IPsRemoved        int `json:"ips_removed"`
	CertsAdded        int `json:"certificates_added"`
	CertsRemoved      int `json:"certificates_removed"`
	DNSChanges        int `json:"dns_changes"`
	ProviderChanges   int `json:"provider_changes"`
	Unchanged         int `json:"unchanged_hosts"`
}

type ChangeEvent struct {
	Category string `json:"category"` // subdomain | ip | dns | certificate | provider
	Action   string `json:"action"`   // added | removed | changed
	Key      string `json:"key"`
	Old      string `json:"old,omitempty"`
	New      string `json:"new,omitempty"`
}
