package headers

import (
	"regexp"
	"strings"

	"reconx/pkg/models"
)

// crossOriginIsolation checks the three cross-origin isolation headers.
//
//   - Cross-Origin-Opener-Policy (COOP) keeps cross-origin windows from holding
//     a reference to this page (tabnabbing, XS-Leaks via window handles).
//   - Cross-Origin-Resource-Policy (CORP) stops other origins from embedding
//     this response with no-cors requests (Spectre-style side channels).
//   - Cross-Origin-Embedder-Policy (COEP) is only needed for cross-origin
//     isolation (SharedArrayBuffer, high-resolution timers), so its absence
//     is informational rather than a weakness.
//
// Values are matched case-insensitively and quoted-string parameters such as
// report-to="x" are ignored.
func crossOriginIsolation(h map[string]string) []models.HeaderFinding {
	var out []models.HeaderFinding

	coop, hasCOOP := h["cross-origin-opener-policy"]
	switch v := policyToken(coop); {
	case !hasCOOP:
		out = append(out, models.HeaderFinding{Header: "Cross-Origin-Opener-Policy", Severity: "LOW",
			Note: "Missing COOP — cross-origin windows opened from or opening this page keep a reference to it (same-origin recommended)"})
	case v == "same-origin" || v == "same-origin-allow-popups" || v == "noopener-allow-popups":
		out = append(out, models.HeaderFinding{Header: "Cross-Origin-Opener-Policy", Present: true, Value: coop, Severity: "INFO",
			Note: "COOP is " + v})
	case v == "unsafe-none":
		out = append(out, models.HeaderFinding{Header: "Cross-Origin-Opener-Policy", Present: true, Value: coop, Severity: "LOW",
			Note: "COOP is unsafe-none (the default) — no opener isolation"})
	default:
		out = append(out, models.HeaderFinding{Header: "Cross-Origin-Opener-Policy", Present: true, Value: coop, Severity: "LOW",
			Note: "Unrecognised COOP value — browsers ignore it and fall back to unsafe-none"})
	}

	corp, hasCORP := h["cross-origin-resource-policy"]
	switch v := policyToken(corp); {
	case !hasCORP:
		out = append(out, models.HeaderFinding{Header: "Cross-Origin-Resource-Policy", Severity: "LOW",
			Note: "Missing CORP — other sites can embed this response with no-cors requests (same-origin or same-site recommended)"})
	case v == "same-origin" || v == "same-site":
		out = append(out, models.HeaderFinding{Header: "Cross-Origin-Resource-Policy", Present: true, Value: corp, Severity: "INFO",
			Note: "CORP is " + v})
	case v == "cross-origin":
		out = append(out, models.HeaderFinding{Header: "Cross-Origin-Resource-Policy", Present: true, Value: corp, Severity: "INFO",
			Note: "CORP is cross-origin — any site may embed this resource (expected for public CDNs/APIs, not for pages)"})
	default:
		out = append(out, models.HeaderFinding{Header: "Cross-Origin-Resource-Policy", Present: true, Value: corp, Severity: "LOW",
			Note: "Unrecognised CORP value — browsers ignore it"})
	}

	coep, hasCOEP := h["cross-origin-embedder-policy"]
	switch v := policyToken(coep); {
	case !hasCOEP:
		out = append(out, models.HeaderFinding{Header: "Cross-Origin-Embedder-Policy", Severity: "INFO",
			Note: "COEP absent — page is not cross-origin isolated (only needed for SharedArrayBuffer / precise timers)"})
	case v == "require-corp" || v == "credentialless":
		note := "COEP is " + v
		if policyToken(coop) == "same-origin" {
			note += "; with COOP same-origin the page is cross-origin isolated"
		}
		out = append(out, models.HeaderFinding{Header: "Cross-Origin-Embedder-Policy", Present: true, Value: coep, Severity: "INFO", Note: note})
	case v == "unsafe-none":
		out = append(out, models.HeaderFinding{Header: "Cross-Origin-Embedder-Policy", Present: true, Value: coep, Severity: "INFO",
			Note: "COEP is unsafe-none (the default)"})
	default:
		out = append(out, models.HeaderFinding{Header: "Cross-Origin-Embedder-Policy", Present: true, Value: coep, Severity: "LOW",
			Note: "Unrecognised COEP value — browsers ignore it"})
	}
	return out
}

// versionRe matches a product version such as "nginx/1.18.0" or "PHP/7.4.3".
var versionRe = regexp.MustCompile(`[A-Za-z][\w.-]*/\d+(\.\d+)+`)

// disclosureAndCORS flags headers that reveal software versions and CORS
// responses that let any origin read the page. Only headers actually present
// produce a finding, so a hardened server adds nothing to the table.
func disclosureAndCORS(h map[string]string) []models.HeaderFinding {
	var out []models.HeaderFinding

	if v, ok := h["server"]; ok && versionRe.MatchString(v) {
		out = append(out, models.HeaderFinding{Header: "Server", Present: true, Value: v, Severity: "LOW",
			Note: "Server header discloses a software version — helps attackers match known CVEs"})
	}
	for _, name := range []string{"x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"} {
		if v, ok := h[name]; ok && strings.TrimSpace(v) != "" {
			out = append(out, models.HeaderFinding{Header: canonical(name), Present: true, Value: v, Severity: "LOW",
				Note: canonical(name) + " discloses the application stack — remove it in production"})
		}
	}

	acao, ok := h["access-control-allow-origin"]
	if !ok {
		return out
	}
	acao = strings.TrimSpace(acao)
	creds := strings.EqualFold(strings.TrimSpace(h["access-control-allow-credentials"]), "true")
	switch {
	case acao == "*" && creds:
		// Browsers refuse this combination, but it shows intent to allow
		// credentialed cross-origin reads and often hides origin reflection.
		out = append(out, models.HeaderFinding{Header: "Access-Control-Allow-Origin", Present: true, Value: acao, Severity: "MEDIUM",
			Note: "CORS allows any origin together with credentials — browsers block this pair, but check whether the origin is reflected instead"})
	case acao == "*":
		out = append(out, models.HeaderFinding{Header: "Access-Control-Allow-Origin", Present: true, Value: acao, Severity: "LOW",
			Note: "CORS allows any origin to read this response (fine for public data, not for user-specific pages)"})
	case strings.EqualFold(acao, "null"):
		out = append(out, models.HeaderFinding{Header: "Access-Control-Allow-Origin", Present: true, Value: acao, Severity: "MEDIUM",
			Note: "CORS trusts the \"null\" origin, which sandboxed iframes and file:// pages can send"})
	default:
		note := "CORS allows " + acao
		if creds {
			note += " with credentials"
		}
		out = append(out, models.HeaderFinding{Header: "Access-Control-Allow-Origin", Present: true, Value: acao, Severity: "INFO", Note: note})
	}
	return out
}

// policyToken returns the policy keyword of a COOP/COEP/CORP value, lowercased
// and without parameters (e.g. `same-origin; report-to="x"` → same-origin).
func policyToken(v string) string {
	v, _, _ = strings.Cut(v, ";")
	return strings.ToLower(strings.Trim(strings.TrimSpace(v), `"`))
}

func canonical(lower string) string {
	parts := strings.Split(lower, "-")
	for i, p := range parts {
		switch p {
		case "x":
			parts[i] = "X"
		case "aspnet":
			parts[i] = "AspNet"
		case "aspnetmvc":
			parts[i] = "AspNetMvc"
		default:
			if p != "" {
				parts[i] = strings.ToUpper(p[:1]) + p[1:]
			}
		}
	}
	return strings.Join(parts, "-")
}
