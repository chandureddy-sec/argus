package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"reconx/internal/modules/apicapture"
	"reconx/internal/modules/crawler"
	"reconx/internal/modules/jsanalysis"
	"reconx/internal/target"
	"reconx/internal/ui"
	"reconx/pkg/models"
)

var (
	webmapTargetFlag   string
	webmapMaxDepth     int
	webmapMaxPages     int
	webmapNoJS         bool
	webmapNoCrawl      bool
	webmapBrowser      bool
)

var webmapCmd = &cobra.Command{
	Use:   "webmap",
	Short: "Web mapping: crawl pages, detect forms, APIs, auth endpoints, and analyze JavaScript",
	Long: `WebMap performs a controlled BFS crawl of the target website (same-origin by
default) and produces a detailed web application map including:
  - Crawled pages with status codes and titles
  - HTML forms with field analysis and CSRF detection
  - Login / authentication form classification
  - File upload and download point discovery
  - API endpoint discovery (JS pattern matching, plus live XHR/fetch capture via --browser)
  - JavaScript file analysis: secret detection and source-map leaks
  - robots.txt / sitemap.xml / security.txt parsing

Requires explicit authorization to use against any target.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		raw := webmapTargetFlag
		if raw == "" && len(args) > 0 {
			raw = args[0]
		}
		if raw == "" {
			return fmt.Errorf("target is required: use --target <domain> or pass as argument")
		}

		parsed, err := target.Parse(raw)
		if err != nil {
			return fmt.Errorf("invalid target: %w", err)
		}
		host := parsed.Value
		rootURL := "https://" + host

		if err := ensureAuthorized(host); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		if !silent {
			fmt.Printf("\n")
			ui.PrintBanner(Version)
			ui.PrintSectionHeader("WEBMAP", host)
			fmt.Printf("\n[*] Target: %s | Depth: %d | Max Pages: %d\n\n", rootURL, webmapMaxDepth, webmapMaxPages)
		}

		// ── Well-Known Files ─────────────────────────────────────────────────────
		if !silent {
			fmt.Printf("[1/3] Fetching robots.txt / sitemap.xml / security.txt...\n")
		}
		var jsFindings []models.JSFinding
		wellKnown := crawler.FetchWellKnown(ctx, rootURL)
		if !silent {
			wkHeaders := []string{"File", "Status"}
			wkRows := [][]string{
				{"robots.txt", map[bool]string{true: fmt.Sprintf("Found (%d bytes)", len(wellKnown.RobotsTxt)), false: "Not found"}[wellKnown.RobotsTxt != ""]},
				{"sitemap.xml", map[bool]string{true: fmt.Sprintf("%d URL(s) discovered", len(wellKnown.SitemapURLs)), false: "Not found"}[len(wellKnown.SitemapURLs) > 0]},
				{"security.txt", map[bool]string{true: fmt.Sprintf("Found (%d bytes)", len(wellKnown.SecurityTxt)), false: "Not found"}[wellKnown.SecurityTxt != ""]},
			}
			ui.PrintTable(wkHeaders, wkRows)
			if wellKnown.RobotsTxt != "" {
				fmt.Printf("\n  robots.txt preview:\n")
				lines := strings.Split(wellKnown.RobotsTxt, "\n")
				for i, l := range lines {
					if i >= 10 {
						fmt.Printf("    ... (%d more lines)\n", len(lines)-10)
						break
					}
					fmt.Printf("    %s\n", l)
				}
			}
			fmt.Println()
		}

		// ── Crawl ────────────────────────────────────────────────────────────────
		var crawlResult *crawler.Result
		if !webmapNoCrawl {
			if !silent {
				fmt.Printf("[2/3] Crawling website (depth=%d, max=%d pages)...\n", webmapMaxDepth, webmapMaxPages)
			}
			opts := crawler.Options{
				MaxDepth:   webmapMaxDepth,
				MaxPages:   webmapMaxPages,
				Timeout:    15 * time.Second,
				UserAgent:  "ReconX/2.0 (security assessment; authorized)",
				SameOrigin: true,
			}
			crawlResult, err = crawler.Crawl(ctx, rootURL, opts)
			if err != nil {
				fmt.Printf("[!] Crawl error: %v\n", err)
			}
		}

		// ── Headless Browser API Capture (opt-in) ────────────────────────────────
		if webmapBrowser {
			if !silent {
				fmt.Printf("[*] Launching headless browser to capture live XHR/fetch API calls...\n")
			}
			captured, capErr := apicapture.Capture(ctx, rootURL, apicapture.DefaultOptions())
			if capErr != nil && !silent {
				fmt.Printf("[!] Browser capture unavailable: %v\n", capErr)
			}
			if len(captured) > 0 {
				if crawlResult == nil {
					crawlResult = &crawler.Result{}
				}
				before := len(crawlResult.APIs)
				crawlResult.APIs = mergeAPIEndpoints(crawlResult.APIs, captured)
				if !silent {
					fmt.Printf("[+] Captured %d live API endpoint(s) via network interception (%d new).\n\n",
						len(captured), len(crawlResult.APIs)-before)
				}
			}
		}

		if crawlResult != nil && !silent {
			fmt.Printf("[+] Crawled %d pages | %d forms | %d APIs discovered | %d scripts\n\n",
				len(crawlResult.Pages), len(crawlResult.Forms),
				len(crawlResult.APIs), len(crawlResult.ScriptURLs))

			// Pages summary
			if len(crawlResult.Pages) > 0 {
				fmt.Printf("[*] Crawled Pages:\n")
				pageHeaders := []string{"#", "URL", "Status", "Title"}
				pageRows := make([][]string, 0)
				displayLimit := len(crawlResult.Pages)
				if displayLimit > 20 {
					displayLimit = 20
				}
				for i := 0; i < displayLimit; i++ {
					p := crawlResult.Pages[i]
					urlDisplay := p.URL
					if len(urlDisplay) > 60 {
						urlDisplay = urlDisplay[:57] + "..."
					}
					title := p.Title
					if len(title) > 40 {
						title = title[:37] + "..."
					}
					pageRows = append(pageRows, []string{
						fmt.Sprintf("%d", i+1),
						urlDisplay,
						fmt.Sprintf("%d", p.StatusCode),
						map[bool]string{true: title, false: "-"}[title != ""],
					})
				}
				ui.PrintTable(pageHeaders, pageRows)
				if len(crawlResult.Pages) > 20 {
					fmt.Printf("  ... and %d more pages.\n", len(crawlResult.Pages)-20)
				}
				fmt.Println()
			}

			// Forms summary
			if len(crawlResult.Forms) > 0 {
				fmt.Printf("[*] Discovered Forms (%d):\n", len(crawlResult.Forms))
				formHeaders := []string{"#", "Page", "Action", "Method", "Type", "CSRF"}
				formRows := make([][]string, 0, len(crawlResult.Forms))
				for i, f := range crawlResult.Forms {
					formType := "Form"
					if f.IsLogin {
						formType = "LOGIN"
					} else if f.IsFileUpload {
						formType = "FILE UPLOAD"
					}
					pageURL := f.PageURL
					if len(pageURL) > 35 {
						pageURL = "..." + pageURL[len(pageURL)-32:]
					}
					action := f.Action
					if len(action) > 35 {
						action = "..." + action[len(action)-32:]
					}
					formRows = append(formRows, []string{
						fmt.Sprintf("%d", i+1),
						pageURL,
						action,
						f.Method,
						formType,
						fmt.Sprintf("%v", f.HasCSRFToken),
					})
				}
				ui.PrintTable(formHeaders, formRows)
				fmt.Println()
			}

			// API endpoints
			if len(crawlResult.APIs) > 0 {
				fmt.Printf("[*] Discovered API Endpoints (%d):\n", len(crawlResult.APIs))
				apiHeaders := []string{"#", "Endpoint URL", "Method", "Source"}
				apiRows := make([][]string, 0, len(crawlResult.APIs))
				displayLimit := len(crawlResult.APIs)
				if displayLimit > 15 {
					displayLimit = 15
				}
				for i := 0; i < displayLimit; i++ {
					a := crawlResult.APIs[i]
					urlDisplay := a.URL
					if len(urlDisplay) > 60 {
						urlDisplay = urlDisplay[:57] + "..."
					}
					apiRows = append(apiRows, []string{
						fmt.Sprintf("%d", i+1),
						urlDisplay,
						map[bool]string{true: a.Method, false: "-"}[a.Method != ""],
						a.Source,
					})
				}
				ui.PrintTable(apiHeaders, apiRows)
				if len(crawlResult.APIs) > 15 {
					fmt.Printf("  ... and %d more endpoints.\n", len(crawlResult.APIs)-15)
				}
				fmt.Println()
			}

			// Download links
			if len(crawlResult.DownloadLinks) > 0 {
				fmt.Printf("[*] File Download Links (%d): %s\n\n",
					len(crawlResult.DownloadLinks),
					strings.Join(crawlResult.DownloadLinks[:min(3, len(crawlResult.DownloadLinks))], ", "))
			}
		}

		// ── JavaScript Analysis ──────────────────────────────────────────────────
		if !webmapNoJS && crawlResult != nil && len(crawlResult.ScriptURLs) > 0 {
			if !silent {
				fmt.Printf("[3/3] JavaScript Analysis (%d scripts)...\n", len(crawlResult.ScriptURLs))
			}
			jsCtx, jsCancel := context.WithTimeout(ctx, 60*time.Second)
			defer jsCancel()

			jsFindings = jsanalysis.AnalyzeScripts(jsCtx, crawlResult.ScriptURLs, host)

			if !silent {
				if len(jsFindings) > 0 {
					jsHeaders := []string{"Script", "3rd Party", "Secrets Found", "Source Map"}
					jsRows := make([][]string, 0, len(jsFindings))
					for _, jf := range jsFindings {
						urlDisplay := jf.ScriptURL
						if len(urlDisplay) > 55 {
							urlDisplay = "..." + urlDisplay[len(urlDisplay)-52:]
						}
						secretsStr := "-"
						if len(jf.Secrets) > 0 {
							secretsStr = strings.Join(jf.Secrets, ", ")
						}
						sourceMapStr := "-"
						if jf.SourceMapURL != "" {
							sourceMapStr = map[bool]string{true: "REACHABLE ⚠", false: "Not reachable"}[jf.SourceMapReachable]
						}
						jsRows = append(jsRows, []string{
							urlDisplay,
							fmt.Sprintf("%v", jf.IsThirdParty),
							secretsStr,
							sourceMapStr,
						})
					}
					ui.PrintTable(jsHeaders, jsRows)
				} else {
					fmt.Printf("[+] No scripts analyzed (all fetch failed or empty).\n")
				}
				fmt.Println()
			} else {
				for _, jf := range jsFindings {
					if len(jf.Secrets) > 0 || jf.SourceMapReachable {
						fmt.Printf("JS\t%s\t%s\tsourcemap:%v\n",
							jf.ScriptURL,
							strings.Join(jf.Secrets, ","),
							jf.SourceMapReachable)
					}
				}
			}
		} else if !webmapNoJS && !silent {
			fmt.Printf("[3/3] No JavaScript files to analyze.\n\n")
		}

		// ── Assemble & persist result ────────────────────────────────────────────
		result := &models.WebMapResult{
			RobotsTxt:   wellKnown.RobotsTxt,
			SitemapURLs: wellKnown.SitemapURLs,
			SecurityTxt: wellKnown.SecurityTxt,
			JSFindings:  jsFindings,
		}
		if crawlResult != nil {
			result.CrawledPages = crawlResult.Pages
			result.Forms = crawlResult.Forms
			result.APIs = crawlResult.APIs
			result.TotalPages = len(crawlResult.Pages)
		}

		scanReport := &models.ScanReport{
			Target:    parsed,
			Timestamp: time.Now().UTC(),
			WebMap:    result,
		}
		savedPaths, saveErr := saveActiveReportBundle("webmap", scanReport)

		if !silent {
			if saveErr != nil {
				fmt.Printf("[!] Report save had errors: %v\n", saveErr)
			}
			for _, p := range savedPaths {
				fmt.Printf("[+] Saved: %s\n", p)
			}
			fmt.Printf("[+] Web mapping complete for %s\n\n", host)
		}
		return nil
	},
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	webmapCmd.Flags().StringVarP(&webmapTargetFlag, "target", "t", "", "target domain to map")
	webmapCmd.Flags().IntVar(&webmapMaxDepth, "depth", 3, "maximum crawl depth")
	webmapCmd.Flags().IntVar(&webmapMaxPages, "max-pages", 50, "maximum number of pages to crawl")
	webmapCmd.Flags().BoolVar(&webmapNoJS, "no-js", false, "skip JavaScript analysis")
	webmapCmd.Flags().BoolVar(&webmapNoCrawl, "no-crawl", false, "skip crawling (only fetch well-known files)")
	webmapCmd.Flags().BoolVar(&webmapBrowser, "browser", false, "use a headless browser to capture real XHR/fetch API calls (requires Chrome)")
	addActiveAuthFlags(webmapCmd.Flags())
}
