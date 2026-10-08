package keystore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Result is the outcome of checking a key against its service.
type Result struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Endpoints the checks call; overridden in tests. Each is a cheap,
// account-level request — none of them touches a scan target.
var (
	githubRateURL   = "https://api.github.com/rate_limit"
	urlscanQuotaURL = "https://urlscan.io/user/quotas/"
	certspotterURL  = "https://api.certspotter.com/v1/issuances?domain=example.com"
)

// Verify checks one key value with its service.
func Verify(ctx context.Context, name, value string) Result {
	k, ok := Lookup(name)
	if !ok {
		return Result{Name: name, Detail: "unknown key"}
	}
	res := Result{Name: k.Name}
	if value == "" {
		res.Detail = "not set"
		return res
	}
	client := &http.Client{Timeout: 15 * time.Second}

	var req *http.Request
	switch k.Name {
	case "github":
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, githubRateURL, nil)
		req.Header.Set("Authorization", "Bearer "+value)
		req.Header.Set("Accept", "application/vnd.github+json")
	case "urlscan":
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, urlscanQuotaURL, nil)
		req.Header.Set("API-Key", value)
	case "certspotter":
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, certspotterURL, nil)
		req.Header.Set("Authorization", "Bearer "+value)
	}
	req.Header.Set("User-Agent", "ReconX/1.0 key-check")

	resp, err := client.Do(req)
	if err != nil {
		res.Detail = "could not reach the service: " + err.Error()
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case http.StatusOK:
		res.OK = true
		res.Detail = "valid"
		if d := quotaDetail(k.Name, body); d != "" {
			res.Detail += " · " + d
		}
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest:
		// urlscan.io answers a malformed or unknown key with 400.
		res.Detail = fmt.Sprintf("rejected (%d) — check the key is correct and not expired", resp.StatusCode)
		if msg := errorMessage(body); msg != "" {
			res.Detail += ": " + msg
		}
	case http.StatusTooManyRequests:
		// The key authenticated but the account is rate-limited right now.
		res.OK = true
		res.Detail = "valid, but rate-limited right now (429)"
	default:
		res.Detail = fmt.Sprintf("unexpected HTTP %d", resp.StatusCode)
	}
	return res
}

// errorMessage extracts a short reason from a JSON error body
// ({"message": …} or {"description": …}), if there is one.
func errorMessage(body []byte) string {
	var r struct {
		Message     string `json:"message"`
		Description string `json:"description"`
	}
	if json.Unmarshal(body, &r) != nil {
		return ""
	}
	msg := r.Message
	if msg == "" {
		msg = r.Description
	}
	if len(msg) > 160 {
		msg = msg[:160] + "…"
	}
	return msg
}

// quotaDetail pulls a remaining-quota figure out of a successful response.
func quotaDetail(name string, body []byte) string {
	switch name {
	case "github":
		var r struct {
			Resources struct {
				CodeSearch struct {
					Limit     int `json:"limit"`
					Remaining int `json:"remaining"`
				} `json:"code_search"`
			} `json:"resources"`
		}
		if json.Unmarshal(body, &r) == nil && r.Resources.CodeSearch.Limit > 0 {
			return fmt.Sprintf("code search %d/%d per minute left", r.Resources.CodeSearch.Remaining, r.Resources.CodeSearch.Limit)
		}
	case "urlscan":
		var r struct {
			Limits struct {
				Search struct {
					Day struct {
						Limit     int `json:"limit"`
						Remaining int `json:"remaining"`
					} `json:"day"`
				} `json:"search"`
			} `json:"limits"`
		}
		if json.Unmarshal(body, &r) == nil && r.Limits.Search.Day.Limit > 0 {
			return fmt.Sprintf("search %d/%d per day left", r.Limits.Search.Day.Remaining, r.Limits.Search.Day.Limit)
		}
	}
	return ""
}
