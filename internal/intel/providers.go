package intel

import (
	"strconv"
	"strings"
)

// Provider kinds.
const (
	KindCloud   = "cloud"
	KindCDN     = "cdn"
	KindHosting = "hosting"
	KindEmail   = "email"
	KindDNS     = "dns"
	KindSaaS    = "saas"
)

// Rule describes how to recognize a provider from public evidence. Matches
// are always inferences ("Likely ...") — ASNs, names and CNAME suffixes are
// strong signals, not proof of who operates a resource.
type Rule struct {
	Name     string
	Kind     string
	Category string // display category, e.g. "CDN", "Support", "Email"
	ASNs     []int
	Orgs     []string // lower-case substrings of the IP owner / ISP name
	CNAMEs   []string // suffixes of CNAME targets
	MX       []string // suffixes of MX hosts
	NS       []string // substrings of nameserver hosts
	SPF      []string // suffixes of SPF include domains
	// Dangling marks services where a CNAME to a deleted resource can be
	// re-registered by someone else (indicator only; never verified actively).
	Dangling bool
}

var catalog = []Rule{
	// CDN / edge (checked before clouds: CNAME evidence is more specific)
	{Name: "Cloudflare", Kind: KindCDN, Category: "CDN / Edge", ASNs: []int{13335, 209242}, Orgs: []string{"cloudflare"}, CNAMEs: []string{".cdn.cloudflare.net", ".cloudflare.net"}, NS: []string{".ns.cloudflare.com"}},
	{Name: "Amazon CloudFront", Kind: KindCDN, Category: "CDN / Edge", CNAMEs: []string{".cloudfront.net"}, Dangling: true},
	{Name: "Akamai", Kind: KindCDN, Category: "CDN / Edge", ASNs: []int{20940, 16625, 16702, 21342, 32787, 35994}, Orgs: []string{"akamai"}, CNAMEs: []string{".edgekey.net", ".edgesuite.net", ".akamaiedge.net", ".akamaized.net", ".akamaihd.net", ".akadns.net"}, NS: []string{".akam.net"}},
	{Name: "Fastly", Kind: KindCDN, Category: "CDN / Edge", ASNs: []int{54113}, Orgs: []string{"fastly"}, CNAMEs: []string{".fastly.net", ".fastlylb.net"}, Dangling: true},
	{Name: "Azure Front Door", Kind: KindCDN, Category: "CDN / Edge", CNAMEs: []string{".azurefd.net", ".azureedge.net", ".afd.azureedge.net"}, Dangling: true},
	{Name: "Imperva", Kind: KindCDN, Category: "CDN / WAF", ASNs: []int{19551}, Orgs: []string{"incapsula", "imperva"}, CNAMEs: []string{".incapdns.net", ".impervadns.net"}},
	{Name: "Sucuri", Kind: KindCDN, Category: "CDN / WAF", ASNs: []int{30148}, Orgs: []string{"sucuri"}, CNAMEs: []string{".sucuri.net"}},
	{Name: "StackPath", Kind: KindCDN, Category: "CDN / Edge", Orgs: []string{"stackpath", "highwinds"}, CNAMEs: []string{".stackpathdns.com", ".hwcdn.net"}},
	{Name: "Bunny CDN", Kind: KindCDN, Category: "CDN / Edge", CNAMEs: []string{".b-cdn.net"}},
	{Name: "Google Cloud CDN", Kind: KindCDN, Category: "CDN / Edge", CNAMEs: []string{".cdn.cloud.google.com"}},

	// Clouds (specific services before the generic provider entry)
	{Name: "AWS S3", Kind: KindCloud, Category: "Storage", CNAMEs: []string{".s3.amazonaws.com", "s3-website.", "s3-website-"}, Dangling: true},
	{Name: "AWS", Kind: KindCloud, Category: "Cloud", ASNs: []int{16509, 14618, 8987, 39111}, Orgs: []string{"amazon", "aws"}, CNAMEs: []string{".amazonaws.com", ".elb.amazonaws.com", ".awsglobalaccelerator.com", ".elasticbeanstalk.com"}, NS: []string{"awsdns-"}},
	{Name: "Azure", Kind: KindCloud, Category: "Cloud", ASNs: []int{8075, 8068, 8069}, Orgs: []string{"microsoft", "azure"}, CNAMEs: []string{".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net", ".blob.core.windows.net", ".azure-api.net", ".azurecontainer.io", ".azurestaticapps.net"}, NS: []string{"azure-dns."}, Dangling: true},
	{Name: "Google Cloud", Kind: KindCloud, Category: "Cloud", ASNs: []int{15169, 396982, 19527, 36040, 43515}, Orgs: []string{"google"}, CNAMEs: []string{".appspot.com", ".googleusercontent.com", ".run.app", ".storage.googleapis.com", "ghs.googlehosted.com", ".web.app", ".firebaseapp.com"}, NS: []string{"googledomains.com", "ns-cloud-"}},
	{Name: "Oracle Cloud", Kind: KindCloud, Category: "Cloud", ASNs: []int{31898}, Orgs: []string{"oracle"}, CNAMEs: []string{".oraclecloud.com"}},
	{Name: "IBM Cloud", Kind: KindCloud, Category: "Cloud", ASNs: []int{36351}, Orgs: []string{"softlayer", "ibm cloud"}},
	{Name: "Alibaba Cloud", Kind: KindCloud, Category: "Cloud", ASNs: []int{45102, 37963}, Orgs: []string{"alibaba", "aliyun"}, CNAMEs: []string{".aliyuncs.com"}},
	{Name: "DigitalOcean", Kind: KindHosting, Category: "Hosting", ASNs: []int{14061}, Orgs: []string{"digitalocean"}, CNAMEs: []string{".ondigitalocean.app"}, NS: []string{".digitalocean.com"}},
	{Name: "Linode (Akamai)", Kind: KindHosting, Category: "Hosting", ASNs: []int{63949}, Orgs: []string{"linode"}, NS: []string{".linode.com"}},
	{Name: "Vultr", Kind: KindHosting, Category: "Hosting", ASNs: []int{20473}, Orgs: []string{"vultr", "choopa"}},
	{Name: "Hetzner", Kind: KindHosting, Category: "Hosting", ASNs: []int{24940, 213230}, Orgs: []string{"hetzner"}},
	{Name: "OVHcloud", Kind: KindHosting, Category: "Hosting", ASNs: []int{16276}, Orgs: []string{"ovh"}},
	{Name: "Hostinger", Kind: KindHosting, Category: "Hosting", ASNs: []int{47583}, Orgs: []string{"hostinger"}},
	{Name: "GoDaddy", Kind: KindHosting, Category: "Hosting", ASNs: []int{26496, 398101}, Orgs: []string{"godaddy"}, NS: []string{"domaincontrol.com"}, MX: []string{".secureserver.net"}, SPF: []string{"secureserver.net"}},

	// Platform / SaaS hosting reachable by CNAME
	{Name: "Vercel", Kind: KindSaaS, Category: "Web Hosting", CNAMEs: []string{".vercel-dns.com", ".vercel.app"}, Orgs: []string{"vercel"}},
	{Name: "Netlify", Kind: KindSaaS, Category: "Web Hosting", CNAMEs: []string{".netlify.app", ".netlify.com"}, Dangling: true},
	{Name: "GitHub Pages", Kind: KindSaaS, Category: "Web Hosting", ASNs: []int{36459}, Orgs: []string{"github"}, CNAMEs: []string{".github.io"}, Dangling: true},
	{Name: "Heroku", Kind: KindSaaS, Category: "Web Hosting", CNAMEs: []string{".herokuapp.com", ".herokudns.com", ".herokussl.com"}, Dangling: true},
	{Name: "WP Engine", Kind: KindSaaS, Category: "Web Hosting", CNAMEs: []string{".wpengine.com", ".wpenginepowered.com"}},
	{Name: "Pantheon", Kind: KindSaaS, Category: "Web Hosting", CNAMEs: []string{".pantheonsite.io"}, Dangling: true},
	{Name: "Webflow", Kind: KindSaaS, Category: "Web Hosting", CNAMEs: []string{".webflow.io", "proxy-ssl.webflow.com", "proxy.webflow.com"}},
	{Name: "Squarespace", Kind: KindSaaS, Category: "Web Hosting", CNAMEs: []string{".squarespace.com"}},
	{Name: "Wix", Kind: KindSaaS, Category: "Web Hosting", CNAMEs: []string{".wixdns.net", ".wix.com"}},
	{Name: "Surge", Kind: KindSaaS, Category: "Web Hosting", CNAMEs: []string{".surge.sh"}, Dangling: true},
	{Name: "Bitbucket", Kind: KindSaaS, Category: "Web Hosting", CNAMEs: []string{".bitbucket.io"}, Dangling: true},
	{Name: "Ghost", Kind: KindSaaS, Category: "Web Hosting", CNAMEs: []string{".ghost.io"}, Dangling: true},
	{Name: "Shopify", Kind: KindSaaS, Category: "E-commerce", CNAMEs: []string{".myshopify.com", "shops.myshopify.com"}, Dangling: true},
	{Name: "Zendesk", Kind: KindSaaS, Category: "Support", CNAMEs: []string{".zendesk.com"}, SPF: []string{"mail.zendesk.com"}, Dangling: true},
	{Name: "Freshdesk", Kind: KindSaaS, Category: "Support", CNAMEs: []string{".freshdesk.com"}, SPF: []string{"freshdesk.com", "fdspfinclude.freshemail.io"}},
	{Name: "Help Scout", Kind: KindSaaS, Category: "Support", CNAMEs: []string{".helpscoutdocs.com"}, SPF: []string{"helpscoutemail.com"}, Dangling: true},
	{Name: "Intercom", Kind: KindSaaS, Category: "Support", CNAMEs: []string{".intercom.help", "custom.intercom.help"}, SPF: []string{"intercom.io"}},
	{Name: "Atlassian Statuspage", Kind: KindSaaS, Category: "Status Page", CNAMEs: []string{".stspg-customer.com", ".statuspage.io"}},
	{Name: "Atlassian", Kind: KindSaaS, Category: "Collaboration", CNAMEs: []string{".atlassian.net"}, SPF: []string{"_spf.atlassian.net"}},
	{Name: "ReadMe", Kind: KindSaaS, Category: "Documentation", CNAMEs: []string{".readme.io", ".readmessl.com"}, Dangling: true},
	{Name: "GitBook", Kind: KindSaaS, Category: "Documentation", CNAMEs: []string{".gitbook.io", "hosting.gitbook.com"}},
	{Name: "HubSpot", Kind: KindSaaS, Category: "Marketing", CNAMEs: []string{".hubspot.net", ".hs-sites.com", ".hubspotpagebuilder.com"}, SPF: []string{"hubspotemail.net"}},
	{Name: "Marketo", Kind: KindSaaS, Category: "Marketing", CNAMEs: []string{".mktoweb.com", ".marketo.com"}, SPF: []string{"mktomail.com"}},
	{Name: "Unbounce", Kind: KindSaaS, Category: "Marketing", CNAMEs: []string{".unbouncepages.com"}, Dangling: true},
	{Name: "Salesforce", Kind: KindSaaS, Category: "CRM", CNAMEs: []string{".force.com", ".salesforce.com", ".my.site.com"}, SPF: []string{"_spf.salesforce.com"}},
	{Name: "Okta", Kind: KindSaaS, Category: "Identity", CNAMEs: []string{".okta.com", ".oktapreview.com"}},
	{Name: "Auth0", Kind: KindSaaS, Category: "Identity", CNAMEs: []string{".auth0.com", ".edge.tenants.auth0.com"}},

	// Email
	{Name: "Google Workspace", Kind: KindEmail, Category: "Email", MX: []string{".google.com", ".googlemail.com"}, SPF: []string{"_spf.google.com"}},
	{Name: "Microsoft 365", Kind: KindEmail, Category: "Email", MX: []string{".mail.protection.outlook.com", ".outlook.com"}, SPF: []string{"spf.protection.outlook.com"}},
	{Name: "Zoho Mail", Kind: KindEmail, Category: "Email", MX: []string{".zoho.com", ".zoho.in", ".zoho.eu", ".zohomail.com"}, SPF: []string{"zoho.com", "zoho.in", "zoho.eu"}},
	{Name: "Proton Mail", Kind: KindEmail, Category: "Email", MX: []string{".protonmail.ch"}, SPF: []string{"_spf.protonmail.ch"}},
	{Name: "Fastmail", Kind: KindEmail, Category: "Email", MX: []string{".messagingengine.com"}, SPF: []string{"spf.messagingengine.com"}},
	{Name: "Proofpoint", Kind: KindEmail, Category: "Email Security", MX: []string{".pphosted.com", ".ppe-hosted.com"}, SPF: []string{"pphosted.com"}},
	{Name: "Mimecast", Kind: KindEmail, Category: "Email Security", MX: []string{".mimecast.com"}, SPF: []string{"mimecast.com"}},
	{Name: "Barracuda", Kind: KindEmail, Category: "Email Security", MX: []string{".barracudanetworks.com"}, SPF: []string{"barracudanetworks.com"}},
	{Name: "Cisco Secure Email", Kind: KindEmail, Category: "Email Security", MX: []string{".iphmx.com"}, SPF: []string{"iphmx.com"}},
	{Name: "Amazon SES", Kind: KindEmail, Category: "Email Delivery", MX: []string{".amazonaws.com"}, SPF: []string{"amazonses.com"}},
	{Name: "SendGrid", Kind: KindEmail, Category: "Email Delivery", SPF: []string{"sendgrid.net"}},
	{Name: "Mailgun", Kind: KindEmail, Category: "Email Delivery", MX: []string{".mailgun.org"}, SPF: []string{"mailgun.org"}},
	{Name: "Mailchimp", Kind: KindEmail, Category: "Email Delivery", SPF: []string{"servers.mcsv.net", "spf.mandrillapp.com"}},
	{Name: "Postmark", Kind: KindEmail, Category: "Email Delivery", SPF: []string{"spf.mtasv.net"}},
	{Name: "SparkPost", Kind: KindEmail, Category: "Email Delivery", SPF: []string{"sparkpostmail.com"}},
	{Name: "Brevo", Kind: KindEmail, Category: "Email Delivery", SPF: []string{"spf.brevo.com", "spf.sendinblue.com"}},

	// DNS hosting
	{Name: "AWS Route 53", Kind: KindDNS, Category: "DNS", NS: []string{"awsdns-"}},
	{Name: "Azure DNS", Kind: KindDNS, Category: "DNS", NS: []string{"azure-dns."}},
	{Name: "Google Cloud DNS", Kind: KindDNS, Category: "DNS", NS: []string{"googledomains.com", "ns-cloud-"}},
	{Name: "NS1", Kind: KindDNS, Category: "DNS", NS: []string{".nsone.net"}},
	{Name: "UltraDNS", Kind: KindDNS, Category: "DNS", NS: []string{"ultradns."}},
	{Name: "DNS Made Easy", Kind: KindDNS, Category: "DNS", NS: []string{"dnsmadeeasy.com"}},
	{Name: "DNSimple", Kind: KindDNS, Category: "DNS", NS: []string{"dnsimple.com"}},
	{Name: "Namecheap", Kind: KindDNS, Category: "DNS", NS: []string{"registrar-servers.com"}},
	{Name: "Hostinger DNS", Kind: KindDNS, Category: "DNS", NS: []string{"dns-parking.com"}},
	{Name: "ERNET India", Kind: KindDNS, Category: "DNS", NS: []string{".ernet.in"}},
}

// MatchCNAME returns the provider whose CNAME suffix matches target.
func MatchCNAME(target string) *Rule {
	t := strings.ToLower(strings.TrimSuffix(target, "."))
	for i := range catalog {
		for _, suf := range catalog[i].CNAMEs {
			// Patterns ending in "." or "-" match anywhere (e.g. regional S3
			// website endpoints); all others are suffix matches.
			if strings.HasSuffix(t, suf) || (strings.ContainsAny(suf[len(suf)-1:], ".-") && strings.Contains(t, suf)) {
				return &catalog[i]
			}
		}
	}
	return nil
}

// MatchIP returns the provider for an IP from its ASN ("AS13335 ..." or
// "13335") and owner names. ASN matches take precedence over name matches.
func MatchIP(asn string, names ...string) *Rule {
	if n := asnNumber(asn); n > 0 {
		for i := range catalog {
			for _, a := range catalog[i].ASNs {
				if a == n {
					return &catalog[i]
				}
			}
		}
	}
	joined := strings.ToLower(strings.Join(names, " "))
	if strings.TrimSpace(joined) == "" {
		return nil
	}
	for i := range catalog {
		if catalog[i].Kind == KindEmail || catalog[i].Kind == KindDNS {
			continue
		}
		for _, o := range catalog[i].Orgs {
			if strings.Contains(joined, o) {
				return &catalog[i]
			}
		}
	}
	return nil
}

// MatchMX returns the email provider for an MX host.
func MatchMX(host string) *Rule {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for i := range catalog {
		for _, suf := range catalog[i].MX {
			if strings.HasSuffix(h, suf) {
				return &catalog[i]
			}
		}
	}
	return nil
}

// MatchNS returns the DNS provider for a nameserver host.
func MatchNS(host string) *Rule {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	// Prefer dedicated DNS products over the parent cloud entry.
	for _, kind := range []string{KindDNS, ""} {
		for i := range catalog {
			if kind != "" && catalog[i].Kind != kind {
				continue
			}
			for _, sub := range catalog[i].NS {
				if strings.Contains(h, sub) {
					return &catalog[i]
				}
			}
		}
	}
	return nil
}

// MatchSPFInclude returns the sending service for an SPF include domain.
func MatchSPFInclude(domain string) *Rule {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	for i := range catalog {
		for _, suf := range catalog[i].SPF {
			if d == suf || strings.HasSuffix(d, "."+suf) {
				return &catalog[i]
			}
		}
	}
	return nil
}

// asnNumber extracts the number from "AS13335 Cloudflare, Inc." or "13335".
func asnNumber(asn string) int {
	s := strings.TrimSpace(asn)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "AS"), "as")
	if i := strings.IndexAny(s, " \t,"); i >= 0 {
		s = s[:i]
	}
	n, _ := strconv.Atoi(s)
	return n
}
