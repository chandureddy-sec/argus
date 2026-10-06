package whois

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// RDAPRecord contains parsed registration intelligence.
type RDAPRecord struct {
	Domain       string    `json:"domain"`
	Registrar    string    `json:"registrar"`
	CreatedDate  time.Time `json:"created_date,omitempty"`
	ExpiryDate   time.Time `json:"expiry_date,omitempty"`
	UpdatedDate  time.Time `json:"updated_date,omitempty"`
	Nameservers  []string  `json:"nameservers"`
	Status       []string  `json:"status"`
	Organization string    `json:"organization,omitempty"`
	Country      string    `json:"country,omitempty"`
}

type rdapResponse struct {
	LdhName string `json:"ldhName"`
	Handle  string `json:"handle"`
	Status  []string `json:"status"`
	Events  []struct {
		EventAction string `json:"eventAction"`
		EventDate   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Roles     []string `json:"roles"`
		VCardArray []any    `json:"vcardArray"`
	} `json:"entities"`
	Nameservers []struct {
		LdhName string `json:"ldhName"`
	} `json:"nameservers"`
}

// Client performs RDAP queries.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient returns a new RDAP client with safe defaults.
func NewClient(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		baseURL: "https://rdap.org/domain/",
	}
}

// Lookup queries the RDAP gateway for domain ownership and registration data.
func (c *Client) Lookup(ctx context.Context, domain string) (*RDAPRecord, error) {
	cleanDomain := strings.TrimSpace(strings.ToLower(domain))
	url := c.baseURL + cleanDomain

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create RDAP request: %w", err)
	}
	req.Header.Set("User-Agent", "ReconX/1.0 (+https://github.com/reconx/reconx)")
	req.Header.Set("Accept", "application/rdap+json, application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RDAP lookup failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("RDAP record not found for domain %s", cleanDomain)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RDAP server responded with status: %s", resp.Status)
	}

	var raw rdapResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to parse RDAP response: %w", err)
	}

	record := &RDAPRecord{
		Domain:      cleanDomain,
		Status:      raw.Status,
		Nameservers: make([]string, 0),
	}

	// Parse events (registration, expiration, last update)
	for _, event := range raw.Events {
		t, err := time.Parse(time.RFC3339, event.EventDate)
		if err != nil {
			// Try ISO8601 without seconds/colons fallback if any
			continue
		}
		switch event.EventAction {
		case "registration":
			record.CreatedDate = t
		case "expiration":
			record.ExpiryDate = t
		case "last changed", "last update":
			record.UpdatedDate = t
		}
	}

	// Parse nameservers
	for _, ns := range raw.Nameservers {
		if ns.LdhName != "" {
			record.Nameservers = append(record.Nameservers, strings.ToLower(ns.LdhName))
		}
	}

	// Extract registrar and entity info from vcards
	for _, entity := range raw.Entities {
		isRegistrar := false
		for _, r := range entity.Roles {
			if r == "registrar" {
				isRegistrar = true
				break
			}
		}

		// Extract fn (formatted name) from vcardArray
		if len(entity.VCardArray) > 1 {
			if items, ok := entity.VCardArray[1].([]any); ok {
				for _, item := range items {
					if fields, ok := item.([]any); ok && len(fields) >= 4 {
						propName, _ := fields[0].(string)
						propVal, _ := fields[3].(string)

						if isRegistrar && propName == "fn" && record.Registrar == "" {
							record.Registrar = propVal
						}
						if !isRegistrar && propName == "org" && record.Organization == "" {
							record.Organization = propVal
						}
						if propName == "adr" && record.Country == "" {
							// adr field 6 often contains country
							if len(fields) > 3 {
								if adrSlice, ok := fields[3].([]any); ok && len(adrSlice) > 6 {
									if country, ok := adrSlice[6].(string); ok {
										record.Country = country
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if record.Registrar == "" {
		record.Registrar = "Unknown / Redacted"
	}

	return record, nil
}
