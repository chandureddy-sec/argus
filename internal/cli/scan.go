package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"reconx/internal/archive"
	"reconx/internal/dns"
	"reconx/internal/orchestrator"
	reporter "reconx/internal/report"
	"reconx/internal/storage"
	"reconx/internal/target"
	"reconx/internal/threatlens"
	"reconx/internal/ui"
	"reconx/internal/whois"
	"reconx/pkg/models"
)

var (
	scanDomain      string
	scanTarget      string
	scanPassive     bool
	scanActive      bool
	scanBrowser     bool
	scanPorts       bool
	scanNmap        bool
	scanNmapProfile string
	scanNmapPorts   string
	scanNmapArgs    string
	scanOutput      string
	scanJSON        string
	scanHTML        string
	scanMD          string
	scanArchiveRaw  bool
	scanThreatLens  string
	scanTLP         string
	scanTLBudget    int
	scanTLAssets    bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Full reconnaissance: passive OSINT by default; add --active for direct-to-target probing",
	RunE: func(cmd *cobra.Command, args []string) error {
		rawTarget := scanDomain
		if rawTarget == "" {
			rawTarget = scanTarget
		}
		if rawTarget == "" && len(args) > 0 {
			rawTarget = args[0]
		}
		if rawTarget == "" {
			return fmt.Errorf("target is required: use --domain <domain> or provide target as argument")
		}

		parsedTarget, err := target.Parse(rawTarget)
		if err != nil {
			return fmt.Errorf("invalid target: %w", err)
		}

		if scanActive {
			if err := ensureAuthorized(parsedTarget.Value); err != nil {
				return err
			}
		}
		tlCfg, useTL, err := threatlensConfig(scanThreatLens, scanTLP, scanTLBudget)
		if err != nil {
			return err // checked before scanning, not after minutes of work
		}
		if scanTLAssets && !useTL {
			return fmt.Errorf("--threatlens-assets needs --threatlens")
		}

		startTime := time.Now()

		slog.Info("commencing full passive reconnaissance",
			slog.String("target", parsedTarget.Value),
			slog.String("type", string(parsedTarget.Type)),
		)

		report := &models.ScanReport{
			Target:    parsedTarget,
			Timestamp: time.Now().UTC(),
		}

		// Passive phase budget: 8 subdomain sources plus enrichment stages, each
		// with its own shorter budget, so one slow source cannot starve the rest.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		var rawArchive *archive.Archive
		if scanArchiveRaw && parsedTarget.Type == models.TargetTypeDomain {
			autoJSON, _, _ := reportPaths(scanOutput, "", "", "", parsedTarget.Value, startTime)
			name := strings.TrimSuffix(filepath.Base(autoJSON), ".json")
			a, err := openRawArchive(firstNonEmptyStr(scanOutput, "reports"), name, parsedTarget.Value)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Raw-response archive unavailable: %v\n", err)
			} else {
				rawArchive, ctx = a, archive.WithArchive(ctx, a)
			}
		}

		headerTitle := "FULL PASSIVE RECONNAISSANCE"
		modeLabel := "100% Passive OSINT"
		if scanActive {
			headerTitle = "FULL RECONNAISSANCE (PASSIVE + ACTIVE)"
			modeLabel = "Passive OSINT + Active direct-to-target"
		}
		if !silent {
			ui.PrintBanner(Version)
			ui.PrintSectionHeader("SCAN", fmt.Sprintf("%s: %s (%s)", headerTitle, parsedTarget.Value, parsedTarget.Type))
			ui.PrintInfo(fmt.Sprintf("Target: %s | Mode: %s | Started: %s\n",
				parsedTarget.Value, modeLabel, startTime.Format("2006-01-02 15:04:05")))
		}

		// ── 1. WHOIS / RDAP ───────────────────────────────────────────────────────────
		if parsedTarget.Type == models.TargetTypeDomain {
			if !silent {
				ui.PrintSectionHeader("1/6", "WHOIS / RDAP Domain Registration")
			}
			rdapClient := whois.NewClient(10 * time.Second)
			rdapRec, err := rdapClient.Lookup(ctx, parsedTarget.Value)
			if err == nil {
				report.RDAP = rdapRec
				if !silent {
					createdStr := "-"
					if !rdapRec.CreatedDate.IsZero() {
						createdStr = rdapRec.CreatedDate.Format("2006-01-02")
					}
					expiryStr := "-"
					if !rdapRec.ExpiryDate.IsZero() {
						expiryStr = rdapRec.ExpiryDate.Format("2006-01-02")
					}
					updatedStr := "-"
					if !rdapRec.UpdatedDate.IsZero() {
						updatedStr = rdapRec.UpdatedDate.Format("2006-01-02")
					}
					nsDisplay := strings.Join(rdapRec.Nameservers, ", ")
					if nsDisplay == "" {
						nsDisplay = "-"
					}
					statusDisplay := strings.Join(rdapRec.Status, ", ")
					if statusDisplay == "" {
						statusDisplay = "-"
					}
					headers := []string{"Registration Attribute", "Value"}
					rows := [][]string{
						{"Registrar", rdapRec.Registrar},
						{"Registrant Org", rdapRec.Organization},
						{"Country", rdapRec.Country},
						{"Creation Date", createdStr},
						{"Expiration Date", expiryStr},
						{"Last Updated", updatedStr},
						{"Authoritative NS", nsDisplay},
						{"Domain Status", statusDisplay},
					}
					ui.PrintTable(headers, rows)
				}
			} else {
				slog.Warn("RDAP lookup unavailable", slog.String("error", err.Error()))
			}
		}

		// ── 2. DNS Records ────────────────────────────────────────────────────────────
		if parsedTarget.Type == models.TargetTypeDomain {
			if !silent {
				ui.PrintSectionHeader("2/6", "DNS Infrastructure Records")
			}
			dnsResolver := dns.NewResolver(nil, 5*time.Second)
			dnsRes, err := dnsResolver.Lookup(ctx, parsedTarget.Value)
			if err == nil {
				report.DNS = dnsRes
				if !silent {
					headers := []string{"Type", "Name", "TTL", "Value"}
					rows := make([][]string, 0, len(dnsRes.Records))
					for _, r := range dnsRes.Records {
						rows = append(rows, []string{r.Type, r.Name, fmt.Sprintf("%d", r.TTL), r.Value})
					}
					ui.PrintTable(headers, rows)

					// Mail Security
					fmt.Printf("\n[*] Email Security Posture:\n")
					spfStatus := "NOT CONFIGURED — vulnerable to spoofing"
					spfAssessment := "⚠ Misconfigured"
					if dnsRes.SecurityRecords.SPF != "" {
						spfStatus = dnsRes.SecurityRecords.SPF
						if strings.Contains(spfStatus, "-all") {
							spfAssessment = "✓ Strong (HardFail -all)"
						} else if strings.Contains(spfStatus, "~all") {
							spfAssessment = "~ Moderate (SoftFail ~all)"
						} else {
							spfAssessment = "⚠ Weak (+all or ?all)"
						}
					}
					dmarcStatus := "NOT CONFIGURED — domain can be impersonated"
					dmarcAssessment := "⚠ Missing"
					if dnsRes.SecurityRecords.DMARC != "" {
						dmarcStatus = dnsRes.SecurityRecords.DMARC
						if strings.Contains(dmarcStatus, "p=reject") {
							dmarcAssessment = "✓ Strong (p=reject)"
						} else if strings.Contains(dmarcStatus, "p=quarantine") {
							dmarcAssessment = "~ Moderate (p=quarantine)"
						} else if strings.Contains(dmarcStatus, "p=none") {
							dmarcAssessment = "⚠ Monitoring Only (p=none)"
						}
					}
					secHeaders := []string{"Control", "Policy", "Assessment"}
					secRows := [][]string{
						{"SPF", spfStatus, spfAssessment},
						{"DMARC", dmarcStatus, dmarcAssessment},
					}
					ui.PrintTable(secHeaders, secRows)
				}
			} else {
				slog.Warn("DNS resolution failed", slog.String("error", err.Error()))
			}
		}

		// ── 3. Passive Subdomain Enumeration ─────────────────────────────────────────
		var hostnamesToResolve []string
		var provStatuses []orchestrator.ProviderStatus
		if parsedTarget.Type == models.TargetTypeDomain {
			if !silent {
				fmt.Printf("\n[3/6] Passive Subdomain Discovery (%d OSINT sources)...\n", len(getSubdomainProviders()))
			}
			rawSubdomains, normalizedAssets, subHostnames, statuses := gatherSubdomains(ctx, parsedTarget)
			provStatuses = statuses
			report.Subdomains = rawSubdomains
			report.Assets = normalizedAssets

			if !silent {
				fmt.Printf("[+] %d unique subdomains from %d raw results.\n", len(normalizedAssets), len(rawSubdomains))
				fmt.Printf("[*] Providers: %s\n", providerStatusLine(provStatuses))
				printSkipped(provStatuses)
				fmt.Println()
				displayCount := len(normalizedAssets)
				if displayCount > 25 {
					displayCount = 25
				}
				headers := []string{"#", "Subdomain", "Sources", "Confidence"}
				rows := make([][]string, 0, displayCount)
				for i := 0; i < displayCount; i++ {
					rows = append(rows, []string{
						fmt.Sprintf("%d", i+1),
						normalizedAssets[i].Asset,
						strings.Join(normalizedAssets[i].Sources, ", "),
						fmt.Sprintf("%.2f", normalizedAssets[i].Confidence),
					})
				}
				ui.PrintTable(headers, rows)
				if len(normalizedAssets) > 25 {
					fmt.Printf("... and %d additional subdomains (all saved to reports).\n", len(normalizedAssets)-25)
				}
			}
			hostnamesToResolve = subHostnames
		}

		// ── 4. Attack Surface Correlation ─────────────────────────────────────────────
		if len(hostnamesToResolve) > 0 {
			if !silent {
				fmt.Printf("\n[4/6] Attack Surface Correlation & Infrastructure Mapping...\n")
				fmt.Printf("[*] Bulk-resolving %d hostnames & querying ASN/BGP routing...\n", len(hostnamesToResolve))
			}
			graph, uniqueIPs := gatherPassiveIntel(ctx, report, provStatuses, nil, nil)
			report.Correlation = graph

			if !silent {
				fmt.Printf("[+] %d of %d hosts resolve in DNS, to %d unique IPs.\n\n",
					graph.LiveAssets, graph.TotalAssets, len(uniqueIPs))

				displayLimit := len(graph.Nodes)
				if displayLimit > 30 {
					displayLimit = 30
				}
				headers := []string{"#", "Subdomain", "Status", "Resolved IP(s)", "Cloud / Provider", "ASN / Org"}
				rows := make([][]string, 0, displayLimit)
				for i := 0; i < displayLimit; i++ {
					node := graph.Nodes[i]
					status := "NO DNS"
					if node.IsAlive {
						status = "RESOLVES"
					}
					ipDisplay := "-"
					if len(node.ResolvedIPs) > 0 {
						ipDisplay = strings.Join(node.ResolvedIPs, ", ")
						if len(ipDisplay) > 28 {
							ipDisplay = ipDisplay[:25] + "..."
						}
					}
					asnDisplay := node.ASN
					if asnDisplay == "" {
						asnDisplay = node.Organization
					}
					if asnDisplay == "" {
						asnDisplay = "-"
					}
					cloudDisplay := node.CloudProvider
					if cloudDisplay == "" {
						cloudDisplay = "-"
					}
					rows = append(rows, []string{
						fmt.Sprintf("%d", i+1),
						node.Hostname,
						status,
						ipDisplay,
						cloudDisplay,
						asnDisplay,
					})
				}
				ui.PrintTable(headers, rows)
				if len(graph.Nodes) > 30 {
					fmt.Printf("... and %d more assets (all in JSON/HTML reports).\n", len(graph.Nodes)-30)
				}
				printRoutingConflicts(report.Intel)
				printExposure(report.Intel)
			}
		}

		closeRawArchive(rawArchive, report, func(msg string) {
			if !silent {
				fmt.Printf("[*] %s\n", msg)
			}
		})

		// ── 4.5 Active Recon (opt-in via --active; authorized above) ───────────────────
		if scanActive && parsedTarget.Type == models.TargetTypeDomain {
			if !silent {
				fmt.Printf("\n[*] Active recon enabled — probing %s directly (TLS, HTTP, headers, crawl)...\n", parsedTarget.Value)
			}
			// Active modules (crawl, headless browser) can run well past the
			// passive budget, so give them a dedicated, longer context.
			actCtx, actCancel := context.WithTimeout(context.Background(), 4*time.Minute)
			report.ActiveRecon = runActiveReconGather(actCtx, parsedTarget.Value)
			if scanPorts {
				report.ActiveRecon.OpenPorts = runPortScanGather(actCtx, parsedTarget.Value)
			}
			report.WebMap = runWebMapGather(actCtx, parsedTarget.Value, scanBrowser, 2, 25)
			actCancel()

			if scanNmap {
				if !silent {
					fmt.Printf("[*] Running nmap (%s profile) — this can take several minutes...\n", firstNonEmptyStr(scanNmapProfile, "quick"))
				}
				// nmap (aggressive/full) can run far longer than the other
				// active modules, so give it its own generous context.
				nmapCtx, nmapCancel := context.WithTimeout(context.Background(), 60*time.Minute)
				nm := runNmapGather(nmapCtx, parsedTarget.Value, ScanOptions{
					NmapProfile: scanNmapProfile, NmapPorts: scanNmapPorts, NmapArgs: scanNmapArgs,
				})
				nmapCancel()
				report.ActiveRecon.Nmap = nm
				if nm != nil && nm.Available {
					if open := nm.OpenPortsLegacy(); len(open) > 0 {
						report.ActiveRecon.OpenPorts = open
					}
					if !silent {
						printNmapResult(nm, parsedTarget.Value)
					}
				} else if nm != nil && !silent {
					fmt.Printf("[!] nmap unavailable: %s\n", nm.Unavailable)
				}
			}

			if !silent {
				tech := "-"
				if report.ActiveRecon != nil && report.ActiveRecon.TechStack != nil && report.ActiveRecon.TechStack.WebServer != "" {
					tech = report.ActiveRecon.TechStack.WebServer
				}
				findingCount := 0
				if report.ActiveRecon != nil {
					findingCount = len(report.ActiveRecon.Findings)
				}
				pages, forms, apis := 0, 0, 0
				if report.WebMap != nil {
					pages, forms, apis = report.WebMap.TotalPages, len(report.WebMap.Forms), len(report.WebMap.APIs)
				}
				portsMsg := ""
				if scanPorts && report.ActiveRecon != nil {
					portsMsg = fmt.Sprintf(" | open ports: %d", len(report.ActiveRecon.OpenPorts))
				}
				fmt.Printf("[+] Active recon done — server: %s | security findings: %d | crawled: %d pages, %d forms, %d APIs%s\n",
					tech, findingCount, pages, forms, apis, portsMsg)
			}
		}

		// ── 4.9 ThreatLens (opt-in via --threatlens) ──────────────────────────────────
		if useTL {
			if !silent {
				fmt.Printf("\n[*] Asking ThreatLens (%s) about %d hosts/IPs...\n", tlCfg.URL, len(threatlens.Values(report)))
			}
			ti := gatherThreatIntel(context.Background(), report, tlCfg)
			if !silent {
				printThreatIntel(ti)
			}
			if scanTLAssets {
				importAssets(report, tlCfg, silent)
			}
		}

		// ── 5. SQLite Storage & Drift Detection ───────────────────────────────────────
		if !silent {
			fmt.Printf("\n[5/6] Saving scan to local database & checking for drift...\n")
		}
		driftMsg := "First scan of this target recorded in local database."
		db, err := storage.Open("")
		if err == nil {
			defer db.Close()
			diff, saveErr := db.SaveScan(ctx, parsedTarget, report.Correlation, time.Since(startTime))
			if saveErr == nil && diff != nil {
				if len(diff.NewAssets) > 0 {
					driftMsg = fmt.Sprintf("DRIFT DETECTED: %d new assets appeared since %s!",
						len(diff.NewAssets), diff.PreviousScanTime.Format("2006-01-02 15:04"))
				} else {
					driftMsg = fmt.Sprintf("No drift detected since last scan (%s).",
						diff.PreviousScanTime.Format("2006-01-02 15:04"))
				}
			}
		}
		if !silent {
			fmt.Printf("[*] %s\n", driftMsg)
		}

		// ── 6. Multi-Format Report Generation ────────────────────────────────────────
		if !silent {
			fmt.Printf("\n[6/6] Generating reports...\n")
		}
		jsonPath, htmlPath, mdPath := reportPaths(scanOutput, scanJSON, scanHTML, scanMD, parsedTarget.Value, startTime)
		var writeErrs []string
		for _, p := range []string{jsonPath, htmlPath, mdPath} {
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				writeErrs = append(writeErrs, err.Error())
			}
		}
		if jsonData, err := json.MarshalIndent(report, "", "  "); err != nil {
			writeErrs = append(writeErrs, "JSON: "+err.Error())
		} else if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
			writeErrs = append(writeErrs, "JSON: "+err.Error())
		}
		if err := reporter.GenerateHTML(report, htmlPath); err != nil {
			writeErrs = append(writeErrs, "HTML: "+err.Error())
		}
		if err := reporter.GenerateMarkdown(report, mdPath); err != nil {
			writeErrs = append(writeErrs, "Markdown: "+err.Error())
		}
		for _, e := range writeErrs {
			fmt.Fprintf(os.Stderr, "[!] Report not written: %s\n", e)
		}

		// ── Summary ───────────────────────────────────────────────────────────────────
		elapsed := time.Since(startTime).Round(time.Millisecond)
		if !silent {
			dnsCount := 0
			if report.DNS != nil {
				dnsCount = len(report.DNS.Records)
			}
			liveCount := 0
			if report.Correlation != nil {
				liveCount = report.Correlation.LiveAssets
			}
			fmt.Printf("\n================================================================================\n")
			fmt.Printf(" ✓ SCAN COMPLETE: %s\n", parsedTarget.Value)
			fmt.Printf("================================================================================\n")
			sumHeaders := []string{"Metric", "Result"}
			sumRows := [][]string{
				{"Execution Time", elapsed.String()},
				{"DNS Records", fmt.Sprintf("%d", dnsCount)},
				{"Subdomains Discovered", fmt.Sprintf("%d", len(report.Assets))},
				{"Live Hosts", fmt.Sprintf("%d", liveCount)},
				{"Attack Surface Drift", driftMsg},
				{"JSON Report", jsonPath},
				{"HTML Report", htmlPath},
				{"Markdown Report", mdPath},
			}
			ui.PrintTable(sumHeaders, sumRows)
			fmt.Println()
		}

		return nil
	},
}

func init() {
	scanCmd.Flags().StringVarP(&scanDomain, "domain", "d", "", "target domain to scan")
	scanCmd.Flags().StringVarP(&scanTarget, "target", "t", "", "target domain, IP, CIDR, or org to scan")
	scanCmd.Flags().BoolVar(&scanPassive, "passive", true, "run purely passive OSINT gathering (default)")
	scanCmd.Flags().BoolVar(&scanActive, "active", false, "also run active direct-to-target recon after the passive phase (requires --authorize)")
	scanCmd.Flags().BoolVar(&scanBrowser, "browser", false, "with --active, capture live XHR/fetch API calls via a headless browser (requires Chrome)")
	scanCmd.Flags().BoolVar(&scanPorts, "ports", false, "with --active, also TCP-scan the common ports on the target")
	scanCmd.Flags().BoolVar(&scanNmap, "nmap", false, "with --active, run an nmap scan (service/version + scripts) if nmap is installed")
	scanCmd.Flags().StringVar(&scanNmapProfile, "nmap-profile", "quick", "nmap profile: quick | aggressive | full")
	scanCmd.Flags().StringVar(&scanNmapPorts, "nmap-ports", "", "port spec for nmap -p (e.g. \"1-1024,8080\")")
	scanCmd.Flags().StringVar(&scanNmapArgs, "nmap-args", "", "raw nmap flags (overrides --nmap-profile), e.g. \"-A --script vuln\"")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "directory for auto-named reports (default \"reports\"); --json/--html/--md paths override it")
	scanCmd.Flags().StringVar(&scanJSON, "json", "", "export results to JSON file (auto-generated if omitted)")
	scanCmd.Flags().StringVar(&scanHTML, "html", "", "export results to HTML report (auto-generated if omitted)")
	scanCmd.Flags().StringVar(&scanMD, "md", "", "export results to Markdown file (auto-generated if omitted)")
	scanCmd.Flags().BoolVar(&scanArchiveRaw, "archive-raw", false, "save every raw third-party HTTP response of the passive phase (with a manifest) under <output>/raw/")
	scanCmd.Flags().StringVar(&scanThreatLens, "threatlens", "", "check the scan's hosts and IPs against a ThreatLens server: --threatlens=<url>, or --threatlens alone to use RECONX_THREATLENS_URL (key: RECONX_THREATLENS_API_KEY or 'reconx keys set threatlens')")
	scanCmd.Flags().Lookup("threatlens").NoOptDefVal = threatlensFlagEnv
	scanCmd.Flags().StringVar(&scanTLP, "threatlens-tlp", "TLP:GREEN", "TLP of the scan's values sent to ThreatLens (TLP:AMBER/RED: no third-party lookups at all)")
	scanCmd.Flags().BoolVar(&scanTLAssets, "threatlens-assets", false, "also import this scan into ThreatLens as YOUR OWN assets and tech stack (only for targets you own)")
	scanCmd.Flags().IntVar(&scanTLBudget, "threatlens-budget", 0, "max metered provider calls ThreatLens may spend per 100 values (0 = server default)")
	addActiveAuthFlags(scanCmd.Flags())
}

// reportPaths returns where the JSON, HTML and Markdown reports are written.
// Explicit per-format paths win; otherwise files are auto-named
// recon_<target>_<timestamp>.<ext> inside outDir (default "reports").
func reportPaths(outDir, jsonPath, htmlPath, mdPath, target string, now time.Time) (string, string, string) {
	if outDir == "" {
		outDir = "reports"
	}
	safe := strings.NewReplacer("/", "_", ":", "_", "\\", "_").Replace(target)
	auto := func(explicit, ext string) string {
		if explicit != "" {
			return explicit
		}
		return filepath.Join(outDir, fmt.Sprintf("recon_%s_%s.%s", safe, now.Format("20060102_150405"), ext))
	}
	return auto(jsonPath, "json"), auto(htmlPath, "html"), auto(mdPath, "md")
}
