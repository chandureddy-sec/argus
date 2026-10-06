package cli

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// Active-recon authorization flags. These are attached to every command that
// sends traffic directly to a target (probe, portscan, webmap) and to
// `scan --active`. Active recon is refused unless the operator asserts
// authorization, either via --authorize or the RECONX_AUTHORIZE=1 env var.
var (
	authorizeFlag bool
	scopeFileFlag string
)

// addActiveAuthFlags registers the authorization flags on an active command.
func addActiveAuthFlags(flags interface {
	BoolVar(p *bool, name string, value bool, usage string)
	StringVar(p *string, name, value, usage string)
}) {
	flags.BoolVar(&authorizeFlag, "authorize", false,
		"confirm you have written authorization to actively scan the target (required for active recon)")
	flags.StringVar(&scopeFileFlag, "scope", "",
		"optional scope file (one host/domain/CIDR per line); the target must match an entry")
}

// ensureAuthorized gates all active, traffic-sending recon. It returns a
// non-nil error that should abort the command when authorization is absent or
// the target falls outside a supplied scope file.
func ensureAuthorized(host string) error {
	authorized := authorizeFlag || os.Getenv("RECONX_AUTHORIZE") == "1"
	if !authorized {
		return fmt.Errorf(
			"active recon against %q is refused: this command sends traffic directly to the target.\n"+
				"   Only run it against systems you are authorized to test.\n"+
				"   Re-run with --authorize (or set RECONX_AUTHORIZE=1) to confirm you have permission,\n"+
				"   optionally restricting targets with --scope <file>.", host)
	}

	if scopeFileFlag != "" {
		inScope, err := targetInScope(host, scopeFileFlag)
		if err != nil {
			return fmt.Errorf("scope check failed: %w", err)
		}
		if !inScope {
			return fmt.Errorf("target %q is not listed in scope file %q; refusing to scan out-of-scope target", host, scopeFileFlag)
		}
	}
	return nil
}

// targetInScope reports whether host matches any entry in the scope file.
// Entries may be an exact host, a parent domain (matches its subdomains),
// or a CIDR block (matched when host is an IP inside it). Blank lines and
// lines beginning with '#' are ignored.
func targetInScope(host, scopeFile string) (bool, error) {
	f, err := os.Open(scopeFile)
	if err != nil {
		return false, err
	}
	defer f.Close()

	host = strings.ToLower(strings.TrimSpace(host))
	hostIP := net.ParseIP(host)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		entry := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}

		// CIDR entry: match when the target is an IP inside the block.
		if _, ipNet, cidrErr := net.ParseCIDR(entry); cidrErr == nil {
			if hostIP != nil && ipNet.Contains(hostIP) {
				return true, nil
			}
			continue
		}

		// Exact host match, or parent-domain match (entry covers subdomains).
		if host == entry || strings.HasSuffix(host, "."+entry) {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}
