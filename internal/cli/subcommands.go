package cli

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"reconx/internal/dns"
	"reconx/internal/enrich"
	"reconx/internal/providers"
	"reconx/internal/providers/alienvault"
	"reconx/internal/providers/anubis"
	"reconx/internal/providers/certspotter"
	"reconx/internal/providers/crtsh"
	"reconx/internal/providers/githubcode"
	"reconx/internal/providers/hackertarget"
	"reconx/internal/providers/urlscan"
	"reconx/internal/providers/wayback"
	"reconx/internal/target"
	"reconx/internal/ui"
)

var (
	subDomainFlag  string
	dnsDomainFlag  string
	certDomainFlag string
	ipTargetFlag   string
	histDomainFlag string
)

func getSubdomainProviders() []providers.Provider {
	return []providers.Provider{
		crtsh.NewProvider(20 * time.Second),
		alienvault.NewProvider(15 * time.Second),
		hackertarget.NewProvider(15 * time.Second),
		anubis.NewProvider(15 * time.Second),
		wayback.NewProvider(15 * time.Second),
		urlscan.NewProvider(15 * time.Second),
		certspotter.NewProvider(15 * time.Second),
		githubcode.NewProvider(15 * time.Second),
	}
}

var subdomainsCmd = &cobra.Command{
	Use:   "subdomains",
	Short: "Enumerate subdomains using concurrent passive OSINT sources (crt.sh, AlienVault, HackerTarget, Anubis)",
	RunE: func(cmd *cobra.Command, args []string) error {
		raw := subDomainFlag
		if raw == "" && len(args) > 0 {
			raw = args[0]
		}
		if raw == "" {
			return fmt.Errorf("domain is required: use --domain <domain> or pass as argument")
		}

		t, err := target.Parse(raw)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()

		_, assets, _, _ := gatherSubdomains(ctx, t)

		if silent {
			for _, a := range assets {
				fmt.Println(a.Asset)
			}
			return nil
		}

		ui.PrintBanner(Version)
		ui.PrintSectionHeader("SUBDOMAINS", fmt.Sprintf("Passive Subdomain Discovery for %s (Ensemble OSINT)", t.Value))
		headers := []string{"#", "Subdomain", "Source(s)", "Confidence"}
		rows := make([][]string, 0, len(assets))
		for i, a := range assets {
			rows = append(rows, []string{
				fmt.Sprintf("%d", i+1),
				a.Asset,
				strings.Join(a.Sources, ", "),
				fmt.Sprintf("%.2f", a.Confidence),
			})
		}
		ui.PrintTable(headers, rows)
		ui.PrintSuccess(fmt.Sprintf("Total unique subdomains discovered: %d\n", len(assets)))
		return nil
	},
}

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Query DNS records (A, AAAA, MX, NS, TXT, SOA, CAA, SPF, DMARC) for a domain",
	RunE: func(cmd *cobra.Command, args []string) error {
		raw := dnsDomainFlag
		if raw == "" && len(args) > 0 {
			raw = args[0]
		}
		if raw == "" {
			return fmt.Errorf("domain is required: use --domain <domain> or pass as argument")
		}

		t, err := target.Parse(raw)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resolver := dns.NewResolver(nil, 5*time.Second)
		res, err := resolver.Lookup(ctx, t.Value)
		if err != nil {
			return fmt.Errorf("DNS resolution error: %w", err)
		}

		if silent {
			for _, r := range res.Records {
				fmt.Printf("%s\t%s\t%s\n", r.Type, r.Name, r.Value)
			}
			return nil
		}

		fmt.Printf("\n[*] DNS Records for %s:\n", t.Value)
		headers := []string{"Type", "Name", "TTL", "Value"}
		rows := make([][]string, 0, len(res.Records))
		for _, r := range res.Records {
			rows = append(rows, []string{
				r.Type,
				r.Name,
				fmt.Sprintf("%d", r.TTL),
				r.Value,
			})
		}
		ui.PrintTable(headers, rows)

		// Email Security section
		fmt.Printf("\n[*] Mail Security Posture:\n")
		secHeaders := []string{"Protocol", "Configured Policy"}
		secRows := [][]string{
			{"SPF", map[bool]string{true: res.SecurityRecords.SPF, false: "Not Found / Missing"}[res.SecurityRecords.SPF != ""]},
			{"DMARC", map[bool]string{true: res.SecurityRecords.DMARC, false: "Not Found / Missing"}[res.SecurityRecords.DMARC != ""]},
		}
		ui.PrintTable(secHeaders, secRows)
		fmt.Println()

		return nil
	},
}

var certificatesCmd = &cobra.Command{
	Use:   "certificates",
	Short: "Query Certificate Transparency logs for a domain",
	RunE: func(cmd *cobra.Command, args []string) error {
		raw := certDomainFlag
		if raw == "" && len(args) > 0 {
			raw = args[0]
		}
		if raw == "" {
			return fmt.Errorf("domain is required: use --domain <domain> or pass as argument")
		}

		t, err := target.Parse(raw)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()

		provider := crtsh.NewProvider(20 * time.Second)
		results, err := provider.Collect(ctx, *t)
		if err != nil {
			return fmt.Errorf("certificates query failed: %w", err)
		}

		if silent {
			for _, r := range results {
				fmt.Printf("%s\t%s\t%s\n", r.Value, r.Metadata["not_before"], r.Metadata["not_after"])
			}
			return nil
		}

		fmt.Printf("\n[*] Certificate Transparency Logs for %s:\n", t.Value)
		headers := []string{"#", "Identified Name", "Not Before", "Not After"}
		rows := make([][]string, 0, len(results))
		for i, r := range results {
			rows = append(rows, []string{
				fmt.Sprintf("%d", i+1),
				r.Value,
				r.Metadata["not_before"],
				r.Metadata["not_after"],
			})
		}
		ui.PrintTable(headers, rows)
		fmt.Printf("\n[+] Total certificates/names identified: %d\n\n", len(results))
		return nil
	},
}

var ipCmd = &cobra.Command{
	Use:   "ip",
	Short: "Perform passive IP intelligence: ASN, geolocation, cloud provider, PTR lookup",
	RunE: func(cmd *cobra.Command, args []string) error {
		raw := ipTargetFlag
		if raw == "" && len(args) > 0 {
			raw = args[0]
		}
		if raw == "" {
			return fmt.Errorf("target IP is required: use --target <IP/CIDR>")
		}
		parsed, err := target.Parse(raw)
		if err != nil {
			return err
		}

		// Expand CIDR to list of IPs (cap at 16 for display)
		var ips []string
		if parsed.Type == "cidr" {
			_, ipNet, err := net.ParseCIDR(parsed.Value)
			if err == nil {
				for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
					ips = append(ips, ip.String())
					if len(ips) >= 16 {
						break
					}
				}
			}
		} else {
			ips = []string{parsed.Value}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if !silent {
			fmt.Printf("\n[*] IP Intelligence for: %s (%s)\n", parsed.Value, parsed.Type)
		}

		// PTR reverse DNS
		ptrMap := make(map[string]string)
		for _, ip := range ips {
			names, err := net.LookupAddr(ip)
			if err == nil && len(names) > 0 {
				ptrMap[ip] = strings.TrimSuffix(names[0], ".")
			}
		}

		// ASN + Geo enrichment
		enricher := enrich.NewIPEnricher(10 * time.Second)
		intel := enricher.EnrichBatch(ctx, ips)

		if silent {
			for _, ip := range ips {
				if info, ok := intel[ip]; ok {
					fmt.Printf("%s\t%s\t%s\t%s\t%s\n", ip, info.ASN, info.Organization, info.Country, info.CloudProvider)
				} else {
					fmt.Printf("%s\t-\t-\t-\t-\n", ip)
				}
			}
			return nil
		}

		headers := []string{"IP Address", "PTR / Hostname", "ASN", "Organization / ISP", "Country", "City", "Cloud / Hosting"}
		rows := make([][]string, 0, len(ips))
		for _, ip := range ips {
			ptr := ptrMap[ip]
			if ptr == "" {
				ptr = "-"
			}
			if info, ok := intel[ip]; ok {
				asn := info.ASN
				if asn == "" {
					asn = "-"
				}
				org := info.Organization
				if org == "" {
					org = info.ISP
				}
				if org == "" {
					org = "-"
				}
				country := info.Country
				if country == "" {
					country = "-"
				}
				city := info.City
				if city == "" {
					city = "-"
				}
				cloud := info.CloudProvider
				if cloud == "" {
					cloud = "-"
				}
				rows = append(rows, []string{ip, ptr, asn, org, country, city, cloud})
			} else {
				rows = append(rows, []string{ip, ptr, "-", "-", "-", "-", "-"})
			}
		}
		ui.PrintTable(headers, rows)
		fmt.Printf("\n[+] IP intelligence complete for %d address(es).\n\n", len(ips))
		return nil
	},
}

// incrementIP increments an IP address in-place (for CIDR iteration).
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Discover historical endpoints and archived URLs via Wayback Machine CDX",
	RunE: func(cmd *cobra.Command, args []string) error {
		raw := histDomainFlag
		if raw == "" && len(args) > 0 {
			raw = args[0]
		}
		if raw == "" {
			return fmt.Errorf("domain is required: use --domain <domain>")
		}
		parsed, err := target.Parse(raw)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if !silent {
			fmt.Printf("\n[*] Querying Wayback Machine CDX for historical endpoints of %s...\n", parsed.Value)
		}

		provider := wayback.NewProvider(25 * time.Second)
		results, err := provider.Collect(ctx, *parsed)
		if err != nil {
			return fmt.Errorf("wayback history query failed: %w", err)
		}

		if len(results) == 0 {
			fmt.Printf("[!] No historical records found for %s\n", parsed.Value)
			return nil
		}

		if silent {
			for _, r := range results {
				fmt.Println(r.Value)
			}
			return nil
		}

		headers := []string{"#", "Discovered Hostname / Endpoint", "Source", "Confidence"}
		rows := make([][]string, 0, len(results))
		for i, r := range results {
			rows = append(rows, []string{
				fmt.Sprintf("%d", i+1),
				r.Value,
				r.Source,
				fmt.Sprintf("%.2f", r.Confidence),
			})
		}
		ui.PrintTable(headers, rows)
		fmt.Printf("\n[+] Total historical hostnames/endpoints discovered: %d\n\n", len(results))
		return nil
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version and build information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("ReconX version %s\n", Version)
	},
}

func init() {
	subdomainsCmd.Flags().StringVarP(&subDomainFlag, "domain", "d", "", "target domain")
	dnsCmd.Flags().StringVarP(&dnsDomainFlag, "domain", "d", "", "target domain")
	certificatesCmd.Flags().StringVarP(&certDomainFlag, "domain", "d", "", "target domain")
	ipCmd.Flags().StringVarP(&ipTargetFlag, "target", "t", "", "target IP or CIDR")
	historyCmd.Flags().StringVarP(&histDomainFlag, "domain", "d", "", "target domain")
}
