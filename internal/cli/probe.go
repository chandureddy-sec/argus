package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	tlsinspect "reconx/internal/modules/tls"
	"reconx/internal/modules/httprobe"
	"reconx/internal/modules/techdetect"
	"reconx/internal/modules/headers"
	"reconx/internal/target"
	"reconx/internal/ui"
	"reconx/pkg/models"
)

var (
	probeTargetFlag string
	probeNoTLS      bool
)

var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Active HTTP probe: TLS, headers, tech stack, redirect chain, and security analysis",
	Long: `Probe connects directly to the target and collects:
  - TLS/SSL certificate details (cipher, validity, SANs)
  - HTTP response headers and cookies
  - Redirect chain
  - Web technology fingerprint (server, CDN, WAF, CMS)
  - Security header analysis with severity scoring

Requires explicit authorization to use against any target.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		raw := probeTargetFlag
		if raw == "" && len(args) > 0 {
			raw = args[0]
		}
		if raw == "" {
			return fmt.Errorf("target is required: use --target <domain/IP> or pass as argument")
		}

		parsed, err := target.Parse(raw)
		if err != nil {
			return fmt.Errorf("invalid target: %w", err)
		}
		host := parsed.Value

		if err := ensureAuthorized(host); err != nil {
			return err
		}

		activeResult := &models.ActiveReconResult{}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if !silent {
			fmt.Printf("\n")
			ui.PrintBanner(Version)
			ui.PrintSectionHeader("PROBE", host)
			fmt.Printf("\n[*] Target: %s | Mode: Active (direct connection)\n\n", host)
		}

		// ── TLS Inspection ──────────────────────────────────────────────────────
		if !probeNoTLS {
			if !silent {
				fmt.Printf("[1/3] TLS/SSL Certificate Analysis...\n")
			}
			tlsInfo, err := tlsinspect.Inspect(ctx, host)
			if err != nil {
				if !silent {
					fmt.Printf("[!] TLS inspection failed: %v\n\n", err)
				}
			} else {
				activeResult.TLS = tlsInfo
				if silent {
					fmt.Printf("TLS\t%s\t%s\t%s\texpires:%s\n",
						host, tlsInfo.TLSVersion, tlsInfo.CipherSuite, tlsInfo.NotAfter.Format("2006-01-02"))
				} else {
					expiryStr := fmt.Sprintf("%d days (%s)", tlsInfo.DaysUntilExpiry, tlsInfo.NotAfter.Format("2006-01-02"))
					if tlsInfo.IsExpired {
						expiryStr = "EXPIRED (" + tlsInfo.NotAfter.Format("2006-01-02") + ")"
					}
					tlsHeaders := []string{"Field", "Value"}
					tlsRows := [][]string{
						{"Subject / CN", tlsInfo.Subject},
						{"Issuer", tlsInfo.Issuer},
						{"TLS Version", tlsInfo.TLSVersion},
						{"Cipher Suite", tlsInfo.CipherSuite},
						{"Validity", expiryStr},
						{"Self-Signed", fmt.Sprintf("%v", tlsInfo.IsSelfSigned)},
						{"HSTS Header", map[bool]string{true: tlsInfo.HSTSHeader, false: "Not set"}[tlsInfo.HSTSHeader != ""]},
						{"SANs", strings.Join(tlsInfo.SANs, ", ")},
					}
					ui.PrintTable(tlsHeaders, tlsRows)
				}
			}
		}

		// ── HTTP Probe ───────────────────────────────────────────────────────────
		if !silent {
			fmt.Printf("[2/3] HTTP Probe & Technology Fingerprint...\n")
		}
		probeResult, err := httprobe.Probe(ctx, host)
		if err != nil {
			if !silent {
				fmt.Printf("[!] HTTP probe failed: %v\n\n", err)
			}
		} else {
			activeResult.HTTPProbe = probeResult

			// Tech detection (uses probe result, no extra requests)
			tech := techdetect.Detect(probeResult)
			activeResult.TechStack = tech

			if silent {
				fmt.Printf("HTTP\t%s\t%d\t%s\t%dms\n",
					probeResult.FinalURL, probeResult.StatusCode,
					probeResult.Server, probeResult.ResponseTime)
			} else {
				httpHeaders := []string{"Field", "Value"}
				httpRows := [][]string{
					{"Final URL", probeResult.FinalURL},
					{"Status", fmt.Sprintf("%d", probeResult.StatusCode)},
					{"Page Title", map[bool]string{true: probeResult.Title, false: "-"}[probeResult.Title != ""]},
					{"Response Time", fmt.Sprintf("%dms", probeResult.ResponseTime)},
					{"Redirect Chain", strings.Join(probeResult.RedirectChain, " → ")},
				}
				ui.PrintTable(httpHeaders, httpRows)

				techHeaders := []string{"Component", "Detected"}
				techRows := [][]string{
					{"Web Server", map[bool]string{true: tech.WebServer, false: "-"}[tech.WebServer != ""]},
					{"Language / Runtime", map[bool]string{true: tech.Language, false: "-"}[tech.Language != ""]},
					{"Framework", map[bool]string{true: tech.Framework, false: "-"}[tech.Framework != ""]},
					{"CDN", map[bool]string{true: tech.CDN, false: "-"}[tech.CDN != ""]},
					{"WAF", map[bool]string{true: tech.WAF, false: "-"}[tech.WAF != ""]},
					{"CMS", map[bool]string{true: tech.CMS, false: "-"}[tech.CMS != ""]},
				}
				if len(tech.OtherTechs) > 0 {
					techRows = append(techRows, []string{"Other", strings.Join(tech.OtherTechs, ", ")})
				}
				fmt.Printf("\n[*] Technology Stack:\n")
				ui.PrintTable(techHeaders, techRows)

				// Cookies
				if len(probeResult.Cookies) > 0 {
					fmt.Printf("\n[*] Cookies (%d):\n", len(probeResult.Cookies))
					cookieHeaders := []string{"Name", "Secure", "HttpOnly", "SameSite"}
					cookieRows := make([][]string, 0, len(probeResult.Cookies))
					for _, c := range probeResult.Cookies {
						cookieRows = append(cookieRows, []string{
							c.Name,
							fmt.Sprintf("%v", c.Secure),
							fmt.Sprintf("%v", c.HTTPOnly),
							map[bool]string{true: c.SameSite, false: "-"}[c.SameSite != ""],
						})
					}
					ui.PrintTable(cookieHeaders, cookieRows)
				}
			}

			// ── Security Header Analysis ──────────────────────────────────────────
			if !silent {
				fmt.Printf("\n[3/3] Security Header Analysis...\n")
			}
			headerFindings, findings := headers.AnalyzeHeaders(probeResult.Headers)
			findings = append(findings, headers.AnalyzeCookies(probeResult.Cookies)...)
			activeResult.HeaderChecks = headerFindings
			activeResult.Findings = findings

			if silent {
				for _, f := range findings {
					fmt.Printf("FINDING\t%s\t%s\t%s\n", f.Severity, f.Category, f.Title)
				}
			} else {
				hdrHeaders := []string{"Security Header", "Present", "Severity", "Assessment"}
				hdrRows := make([][]string, 0, len(headerFindings))
				for _, hf := range headerFindings {
					presentStr := "✓"
					if !hf.Present {
						presentStr = "✗"
					}
					val := hf.Note
					if hf.Value != "" && len(hf.Value) < 50 {
						val = hf.Value
					}
					hdrRows = append(hdrRows, []string{hf.Header, presentStr, hf.Severity, val})
				}
				ui.PrintTable(hdrHeaders, hdrRows)

				if len(findings) > 0 {
					fmt.Printf("\n[!] Security Findings (%d):\n", len(findings))
					fHeaders := []string{"Severity", "Category", "Finding"}
					fRows := make([][]string, 0, len(findings))
					for _, f := range findings {
						fRows = append(fRows, []string{f.Severity, f.Category, f.Title})
					}
					ui.PrintTable(fHeaders, fRows)
				}
			}
		}

		scanReport := &models.ScanReport{
			Target:      parsed,
			Timestamp:   time.Now().UTC(),
			ActiveRecon: activeResult,
		}
		savedPaths, saveErr := saveActiveReportBundle("probe", scanReport)

		if !silent {
			if saveErr != nil {
				fmt.Printf("\n[!] Report save had errors: %v\n", saveErr)
			}
			for _, p := range savedPaths {
				fmt.Printf("[+] Saved: %s\n", p)
			}
			fmt.Printf("[+] Probe complete for %s\n\n", host)
		}
		return nil
	},
}

func init() {
	probeCmd.Flags().StringVarP(&probeTargetFlag, "target", "t", "", "target domain or IP to probe")
	probeCmd.Flags().BoolVar(&probeNoTLS, "no-tls", false, "skip TLS certificate inspection")
	addActiveAuthFlags(probeCmd.Flags())
}
