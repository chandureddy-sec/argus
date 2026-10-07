package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"reconx/internal/dns"
	"reconx/internal/orchestrator"
	reporter "reconx/internal/report"
	"reconx/internal/storage"
	"reconx/internal/target"
	"reconx/internal/ui"
	"reconx/internal/whois"
	"reconx/pkg/models"
)

const Banner = `
================================================================================
  ____                             __  __
 |  _ \  ___   ___  ___   _ __     \ \/ /
 | |_) |/ _ \ / __|/ _ \ | '_ \     \  / 
 |  _ <|  __/| (__| (_) || | | |    /  \ 
 |_| \_\\___| \___|\___/ |_| |_|   /_/\_\
 
 Automated Passive Reconnaissance Framework (Windows & Kali Linux)
 Version: %s | Mode: 100%% Passive OSINT (Zero Intrusive Probes)
================================================================================
`

// StartInteractiveMode starts the interactive terminal UI.
func StartInteractiveMode() {
	reader := bufio.NewReader(os.Stdin)

	for {
		ui.PrintStartupMenu(Version, "example.com", "passive", "./reports/example.com")

		input, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		choice := strings.TrimSpace(input)
		if choice == "5" || strings.EqualFold(choice, "exit") || strings.EqualFold(choice, "quit") || strings.EqualFold(choice, "q") {
			fmt.Printf("\n%sExiting ReconX. Happy Hunting!%s\n\n", ui.FgGhostGreen, ui.Reset)
			break
		}

		// If user selected 1, 2, 3 or typed a domain directly:
		var targetDomain string
		if choice == "1" || choice == "2" || choice == "3" {
			fmt.Printf("\n%s>> Enter target domain [e.g. tesla.com]:%s ", ui.FgAqua+ui.Bold, ui.Reset)
			domainInput, _ := reader.ReadString('\n')
			targetDomain = strings.TrimSpace(domainInput)
		} else if strings.Contains(choice, ".") {
			targetDomain = choice
		} else {
			fmt.Printf("%sInvalid choice. Defaulting to full recon.%s\n", ui.FgAmber, ui.Reset)
			fmt.Printf("\n%s>> Enter target domain [e.g. tesla.com]:%s ", ui.FgAqua+ui.Bold, ui.Reset)
			domainInput, _ := reader.ReadString('\n')
			targetDomain = strings.TrimSpace(domainInput)
		}

		if targetDomain == "" {
			continue
		}

		// Run automated reconnaissance
		RunAutomatedRecon(targetDomain)

		fmt.Printf("\n%s[?] Scan another target? (y/N):%s ", ui.FgGhostGreen, ui.Reset)
		ans, _ := reader.ReadString('\n')
		cleanAns := strings.TrimSpace(strings.ToLower(ans))
		if cleanAns != "y" && cleanAns != "yes" {
			fmt.Printf("\n%sExiting ReconX. Goodbye!%s\n\n", ui.FgGhostGreen, ui.Reset)
			break
		}
		fmt.Println()
	}
}

// RunAutomatedRecon executes all passive recon modules and prints every section clearly and separately.
func RunAutomatedRecon(rawTarget string) {
	startTime := time.Now()

	// 1. Target Normalization
	parsedTarget, err := target.Parse(rawTarget)
	if err != nil {
		fmt.Printf("\n[!] Error: Invalid target specification: %v\n\n", err)
		return
	}

	report := &models.ScanReport{
		Target:    parsedTarget,
		Timestamp: time.Now().UTC(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ui.PrintSectionTitle("Target Validation", 1)
	targetHeaders := []string{"Field", "Parsed Detail"}
	targetRows := [][]string{
		{"Raw Input", parsedTarget.Original},
		{"Normalized Target", parsedTarget.Value},
		{"Identified Type", string(parsedTarget.Type)},
		{"Analysis Timestamp", report.Timestamp.Format("2006-01-02 15:04:05 UTC")},
	}
	ui.PrintTable(targetHeaders, targetRows)

	// Screen 2: Running Reconnaissance Progress Bar Display
	progressModules := []ui.ModuleStatus{
		{Name: "Target Validation", Progress: 100, Status: "done", Icon: "○"},
		{Name: "DNS Enumeration", Progress: 100, Status: "done", Icon: "◈"},
		{Name: "Subdomain Discovery", Progress: 100, Status: "done", Icon: "⊕"},
		{Name: "Attack Surface Mapping", Progress: 100, Status: "done", Icon: "☊"},
		{Name: "Threat Feeds & RDAP", Progress: 100, Status: "done", Icon: "⊞"},
		{Name: "Vulnerability & Drift", Progress: 100, Status: "done", Icon: "✓"},
	}
	logs := []string{
		fmt.Sprintf("%s[%s]%s %s[INFO]%s Target validated: %s", ui.FgDarkGray, time.Now().Format("15:04:05"), ui.Reset, ui.FgCyan, ui.Reset, parsedTarget.Value),
		fmt.Sprintf("%s[%s]%s %s[ OK ]%s Fetching DNS infrastructure & security records...", ui.FgDarkGray, time.Now().Format("15:04:05"), ui.Reset, ui.FgGreen, ui.Reset),
		fmt.Sprintf("%s[%s]%s %s[ OK ]%s Running multi-source passive subdomain discovery...", ui.FgDarkGray, time.Now().Format("15:04:06"), ui.Reset, ui.FgGreen, ui.Reset),
		fmt.Sprintf("%s[%s]%s %s[ OK ]%s Correlating resolved IP addresses & ASN providers...", ui.FgDarkGray, time.Now().Format("15:04:07"), ui.Reset, ui.FgGreen, ui.Reset),
	}
	ui.PrintProgressScreen(progressModules, logs)

	// 2. Registration & WHOIS / RDAP Intelligence
	if parsedTarget.Type == models.TargetTypeDomain {
		ui.PrintSectionHeader("2", "Domain Registration & Ownership (WHOIS / RDAP)")
		ui.PrintNotice("Querying global RDAP registries...")

		rdapClient := whois.NewClient(10 * time.Second)
		rdapRec, err := rdapClient.Lookup(ctx, parsedTarget.Value)
		if err == nil {
			report.RDAP = rdapRec
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

			whoisHeaders := []string{"Registration Attribute", "Value"}
			whoisRows := [][]string{
				{"Registrar", rdapRec.Registrar},
				{"Registrant Org", rdapRec.Organization},
				{"Country", rdapRec.Country},
				{"Creation Date", createdStr},
				{"Expiration Date", expiryStr},
				{"Last Updated", updatedStr},
				{"Authoritative NS", nsDisplay},
				{"Domain Status", statusDisplay},
			}
			ui.PrintTable(whoisHeaders, whoisRows)
		} else {
			fmt.Printf("[!] RDAP/WHOIS record not available for this target: %v\n", err)
		}
	}

	// 3. DNS Infrastructure Records
	if parsedTarget.Type == models.TargetTypeDomain {
		dnsResolver := dns.NewResolver(nil, 5*time.Second)
		dnsRes, err := dnsResolver.Lookup(ctx, parsedTarget.Value)
		if err == nil && len(dnsRes.Records) > 0 {
			report.DNS = dnsRes
			ui.PrintSectionTitle("DNS Infrastructure Records", len(dnsRes.Records))
			dnsHeaders := []string{"Type", "Name", "TTL", "Resolved Value"}
			dnsRows := make([][]string, 0, len(dnsRes.Records))
			for _, r := range dnsRes.Records {
				dnsRows = append(dnsRows, []string{
					r.Type,
					r.Name,
					fmt.Sprintf("%d", r.TTL),
					r.Value,
				})
			}
			ui.PrintTable(dnsHeaders, dnsRows)

			// 4. Mail Security & Defensive Posture
			ui.PrintSectionTitle("Email Security & Authentication", 2)
			secHeaders := []string{"Security Protocol", "Configured Policy", "Risk Assessment"}

			spfStatus := "NOT CONFIGURED"
			if dnsRes.SecurityRecords.SPF != "" {
				spfStatus = dnsRes.SecurityRecords.SPF
			}
			spfAssessment := "Misconfigured"
			if strings.Contains(spfStatus, "-all") {
				spfAssessment = "Strong"
			} else if strings.Contains(spfStatus, "~all") {
				spfAssessment = "Moderate"
			} else if dnsRes.SecurityRecords.SPF != "" {
				spfAssessment = "Weak"
			}

			dmarcStatus := "NOT CONFIGURED"
			if dnsRes.SecurityRecords.DMARC != "" {
				dmarcStatus = dnsRes.SecurityRecords.DMARC
			}
			dmarcAssessment := "Missing"
			if strings.Contains(dmarcStatus, "p=reject") {
				dmarcAssessment = "Strong"
			} else if strings.Contains(dmarcStatus, "p=quarantine") {
				dmarcAssessment = "Moderate"
			} else if strings.Contains(dmarcStatus, "p=none") {
				dmarcAssessment = "Monitoring Only"
			}

			secRows := [][]string{
				{"SPF (Sender Policy Framework)", spfStatus, spfAssessment},
				{"DMARC Authentication", dmarcStatus, dmarcAssessment},
			}
			ui.PrintTable(secHeaders, secRows)
		} else {
			fmt.Printf("%s[!] No DNS records could be resolved for %s%s\n", ui.FgOrange, parsedTarget.Value, ui.Reset)
		}
	} else if parsedTarget.Type == models.TargetTypeIPv4 || parsedTarget.Type == models.TargetTypeIPv6 {
		// Reverse DNS for IP
		names, err := net.LookupAddr(parsedTarget.Value)
		if err == nil && len(names) > 0 {
			ui.PrintSectionTitle("Reverse DNS (PTR) Resolution", len(names))
			ptrHeaders := []string{"IP Address", "Hostname (PTR)"}
			ptrRows := [][]string{
				{parsedTarget.Value, strings.Join(names, ", ")},
			}
			ui.PrintTable(ptrHeaders, ptrRows)
		} else {
			ui.PrintSectionTitle("Reverse DNS (PTR) Resolution", 0)
			fmt.Printf("  %sNo PTR records found for IP %s%s\n", ui.FgMuted, parsedTarget.Value, ui.Reset)
		}
	}

	// 5. Passive Subdomain Enumeration & Normalization
	var hostnamesToResolve []string
	var provStatuses []orchestrator.ProviderStatus
	if parsedTarget.Type == models.TargetTypeDomain {
		rawSubdomains, normalizedAssets, subHostnames, statuses := gatherSubdomains(ctx, parsedTarget)
		provStatuses = statuses
		report.Subdomains = rawSubdomains
		report.Assets = normalizedAssets

		ui.PrintSectionTitle("Discovered Subdomains", len(normalizedAssets))
		fmt.Printf("  %s[providers: %s]%s\n", ui.FgMuted, providerStatusLine(provStatuses), ui.Reset)

		displayCount := len(normalizedAssets)
		if displayCount > 25 {
			displayCount = 25
		}

		subHeaders := []string{"#", "Subdomain", "Status", "Sources"}
		subRows := make([][]string, 0, displayCount)
		for i := 0; i < displayCount; i++ {
			subRows = append(subRows, []string{
				fmt.Sprintf("%d", i+1),
				normalizedAssets[i].Asset,
				"discovered", // not yet resolved — liveness comes from DNS below
				strings.Join(normalizedAssets[i].Sources, ", "),
			})
		}
		ui.PrintTable(subHeaders, subRows)

		if len(normalizedAssets) > 25 {
			fmt.Printf("  %s... and %d additional subdomains.%s\n", ui.FgMuted, len(normalizedAssets)-25, ui.Reset)
		}

		hostnamesToResolve = subHostnames
	}

	// 6. Phase 4: Attack Surface Correlation (IP Resolution, ASN, Cloud / CDN Provider)
	if len(hostnamesToResolve) > 0 {
		graph, _ := gatherPassiveIntel(ctx, report, provStatuses, nil, nil)
		report.Correlation = graph

		ui.PrintSectionTitle("Discovered Subdomains with Resolved IP", graph.LiveAssets)

		corrHeaders := []string{"#", "Subdomain", "Status", "IP Address", "Cloud / Service"}
		corrRows := make([][]string, 0, 25)

		displayLimit := len(graph.Nodes)
		if displayLimit > 25 {
			displayLimit = 25
		}

		for i := 0; i < displayLimit; i++ {
			node := graph.Nodes[i]
			status := "NO DNS"
			if node.IsAlive {
				status = "RESOLVES" // DNS only; passive mode makes no HTTP request
			}

			ipDisplay := "-"
			if len(node.ResolvedIPs) > 0 {
				ipDisplay = node.ResolvedIPs[0]
			}

			cloudDisplay := node.CloudProvider
			if cloudDisplay == "" {
				cloudDisplay = "-"
			}

			corrRows = append(corrRows, []string{
				fmt.Sprintf("%d", i+1),
				node.Hostname,
				status,
				ipDisplay,
				cloudDisplay,
			})
		}
		ui.PrintTable(corrHeaders, corrRows)

		if len(graph.Nodes) > 25 {
			fmt.Printf("\n... and %d more correlated assets (all recorded in JSON report).\n", len(graph.Nodes)-25)
		}
	}

	// 7. Phase 5: SQLite Storage & Attack Surface Drift Detection
	var driftMsg = "First scan of target recorded in local database."
	db, err := storage.Open("")
	if err == nil {
		defer db.Close()
		diff, saveErr := db.SaveScan(ctx, parsedTarget, report.Correlation, time.Since(startTime))
		if saveErr == nil && diff != nil {
			if len(diff.NewAssets) > 0 {
				driftMsg = fmt.Sprintf("DRIFT DETECTED: %d new subdomains appeared since previous scan (%s)!",
					len(diff.NewAssets), diff.PreviousScanTime.Format("2006-01-02 15:04"))
			} else {
				driftMsg = fmt.Sprintf("No attack-surface drift detected since previous scan (%s).",
					diff.PreviousScanTime.Format("2006-01-02 15:04"))
			}
		}
	}
	ui.PrintNotice(driftMsg)

	// 8. Phase 6: Multi-Format Report Generation (JSON, HTML, Markdown)
	_ = os.MkdirAll("reports", 0755)
	safeName := strings.ReplaceAll(parsedTarget.Value, "/", "_")
	safeName = strings.ReplaceAll(safeName, ":", "_")
	timestampStr := time.Now().Format("20060102_150405")

	jsonReportPath := filepath.Join("reports", fmt.Sprintf("recon_%s_%s.json", safeName, timestampStr))
	htmlReportPath := filepath.Join("reports", fmt.Sprintf("recon_%s_%s.html", safeName, timestampStr))
	mdReportPath := filepath.Join("reports", fmt.Sprintf("recon_%s_%s.md", safeName, timestampStr))

	// JSON Export
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err == nil {
		_ = os.WriteFile(jsonReportPath, jsonData, 0644)
	}

	// HTML Export
	_ = reporter.GenerateHTML(report, htmlReportPath)

	// Markdown Export
	_ = reporter.GenerateMarkdown(report, mdReportPath)

	// Final Recon Summary & Trophy Completion Box (Screen 5 & Screen 6)
	elapsed := time.Since(startTime).Round(time.Millisecond)

	// Findings summary table (Screen 5)
	var findingsRows [][]string
	if report.DNS != nil && report.DNS.SecurityRecords.SPF == "" {
		findingsRows = append(findingsRows, []string{"HIGH", "Missing SPF email authentication", parsedTarget.Value})
	}
	if report.DNS != nil && report.DNS.SecurityRecords.DMARC == "" {
		findingsRows = append(findingsRows, []string{"HIGH", "Missing DMARC anti-spoofing policy", parsedTarget.Value})
	}
	if report.Correlation != nil {
		for _, n := range report.Correlation.Nodes {
			if strings.Contains(n.Hostname, "admin") || strings.Contains(n.Hostname, "api") || strings.Contains(n.Hostname, "dev") || strings.Contains(n.Hostname, "staging") {
				findingsRows = append(findingsRows, []string{"MEDIUM", "Exposed internal/admin/dev service", n.Hostname})
			}
			if len(findingsRows) >= 6 {
				break
			}
		}
	}
	if len(findingsRows) > 0 {
		ui.PrintFindingsTitle("Security Posture Findings", len(findingsRows))
		findingHeaders := []string{"Severity", "Finding Description", "Target Host"}
		ui.PrintTable(findingHeaders, findingsRows)
	}

	// Completion Card (Screen 6)
	subCount := len(report.Assets)
	liveCount := 0
	if report.Correlation != nil {
		liveCount = report.Correlation.LiveAssets
	}
	ui.PrintCompletionCard(parsedTarget.Value, subCount, liveCount, elapsed.String(), "reports/")
}
