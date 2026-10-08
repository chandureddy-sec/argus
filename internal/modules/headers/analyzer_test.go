package headers

import "testing"

func byHeader(t *testing.T, hdrs map[string]string) map[string][]string {
	t.Helper()
	hf, _ := AnalyzeHeaders(hdrs)
	out := map[string][]string{}
	for _, f := range hf {
		out[f.Header] = append(out[f.Header], f.Severity+": "+f.Note)
	}
	return out
}

func sev(t *testing.T, m map[string][]string, header, want string) {
	t.Helper()
	got := m[header]
	if len(got) == 0 {
		t.Fatalf("%s: no finding", header)
	}
	if got[0][:len(want)] != want {
		t.Errorf("%s = %q, want severity %s", header, got[0], want)
	}
}

func TestCrossOriginIsolationMissing(t *testing.T) {
	m := byHeader(t, map[string]string{})
	sev(t, m, "Cross-Origin-Opener-Policy", "LOW")
	sev(t, m, "Cross-Origin-Resource-Policy", "LOW")
	sev(t, m, "Cross-Origin-Embedder-Policy", "INFO")
	if _, ok := m["Access-Control-Allow-Origin"]; ok {
		t.Error("absent CORS header should add no finding")
	}
}

func TestCrossOriginIsolationGood(t *testing.T) {
	m := byHeader(t, map[string]string{
		"Cross-Origin-Opener-Policy":   `Same-Origin; report-to="coop"`,
		"Cross-Origin-Resource-Policy": "same-site",
		"Cross-Origin-Embedder-Policy": "require-corp",
	})
	sev(t, m, "Cross-Origin-Opener-Policy", "INFO")
	sev(t, m, "Cross-Origin-Resource-Policy", "INFO")
	sev(t, m, "Cross-Origin-Embedder-Policy", "INFO")
	if want := "INFO: COEP is require-corp; with COOP same-origin the page is cross-origin isolated"; m["Cross-Origin-Embedder-Policy"][0] != want {
		t.Errorf("COEP note = %q", m["Cross-Origin-Embedder-Policy"][0])
	}
}

func TestCrossOriginIsolationBadValues(t *testing.T) {
	m := byHeader(t, map[string]string{
		"Cross-Origin-Opener-Policy":   "unsafe-none",
		"Cross-Origin-Resource-Policy": "everyone",
		"Cross-Origin-Embedder-Policy": "bogus",
	})
	sev(t, m, "Cross-Origin-Opener-Policy", "LOW")
	sev(t, m, "Cross-Origin-Resource-Policy", "LOW")
	sev(t, m, "Cross-Origin-Embedder-Policy", "LOW")
}

func TestDisclosureAndCORS(t *testing.T) {
	m := byHeader(t, map[string]string{
		"Server":                           "nginx/1.18.0 (Ubuntu)",
		"X-Powered-By":                     "PHP/7.4.3",
		"Access-Control-Allow-Origin":      "*",
		"Access-Control-Allow-Credentials": "true",
	})
	sev(t, m, "Server", "LOW")
	sev(t, m, "X-Powered-By", "LOW")
	sev(t, m, "Access-Control-Allow-Origin", "MEDIUM")

	m = byHeader(t, map[string]string{"Server": "cloudflare", "Access-Control-Allow-Origin": "null"})
	if _, ok := m["Server"]; ok {
		t.Error("versionless Server header flagged")
	}
	sev(t, m, "Access-Control-Allow-Origin", "MEDIUM")

	m = byHeader(t, map[string]string{"Access-Control-Allow-Origin": "https://app.example.com"})
	sev(t, m, "Access-Control-Allow-Origin", "INFO")
}

func TestMediumCORSBecomesFinding(t *testing.T) {
	_, findings := AnalyzeHeaders(map[string]string{"Access-Control-Allow-Origin": "null"})
	for _, f := range findings {
		if f.Title == "Access-Control-Allow-Origin Issue" {
			return
		}
	}
	t.Error("MEDIUM CORS header not promoted to a security finding")
}

func TestCanonical(t *testing.T) {
	for in, want := range map[string]string{"x-powered-by": "X-Powered-By", "x-aspnet-version": "X-AspNet-Version"} {
		if got := canonical(in); got != want {
			t.Errorf("canonical(%q) = %q, want %q", in, got, want)
		}
	}
}
