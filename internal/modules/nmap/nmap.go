// Package nmap drives the real nmap binary for authorized active scanning and
// parses its XML output into the ReconX model. It never reimplements nmap: if
// nmap is not installed, scanning is reported as unavailable rather than
// silently degraded. All scanning here is intrusive and must only run against
// authorized targets, behind the caller's authorization gate.
package nmap

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"reconx/pkg/models"
)

// Profiles select a predefined set of nmap flags.
const (
	ProfileQuick      = "quick"      // -sV -sC: service/version + default scripts
	ProfileAggressive = "aggressive" // -A: version, scripts, OS detection, traceroute
	ProfileFull       = "full"       // -sV -p-: service detection on all 65535 ports
	ProfileCustom     = "custom"     // caller supplies all flags via Options.Args
)

// Options configures a scan.
type Options struct {
	Profile string        // one of the Profile constants; defaults to quick
	Ports   string        // nmap -p port spec (e.g. "1-1024,8080"); empty = profile default
	Args    []string      // for ProfileCustom: the full flag list passed to nmap
	Timeout time.Duration // overall wall-clock bound; 0 = profile default
}

// windowsInstallPaths are the default nmap locations to check when it is not on
// PATH (the installer does not always update the current shell's PATH).
var windowsInstallPaths = []string{
	`C:\Program Files (x86)\Nmap\nmap.exe`,
	`C:\Program Files\Nmap\nmap.exe`,
}

// FindBinary locates the nmap executable, returning "" if it cannot be found.
func FindBinary() string {
	if p, err := exec.LookPath("nmap"); err == nil {
		return p
	}
	if runtime.GOOS == "windows" {
		for _, p := range windowsInstallPaths {
			if _, err := exec.LookPath(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// Available reports whether nmap can be run.
func Available() bool { return FindBinary() != "" }

// profileArgs returns the nmap flags and a sensible default timeout for a profile.
func profileArgs(opts Options) (args []string, timeout time.Duration, profile string) {
	switch opts.Profile {
	case ProfileAggressive:
		// -A = OS detection, version detection, script scanning, traceroute.
		return []string{"-A", "-Pn", "-T4"}, 20 * time.Minute, ProfileAggressive
	case ProfileFull:
		return []string{"-sV", "-Pn", "-T4", "-p-"}, 60 * time.Minute, ProfileFull
	case ProfileCustom:
		return append([]string{}, opts.Args...), 30 * time.Minute, ProfileCustom
	default:
		return []string{"-sV", "-sC", "-Pn", "-T4"}, 10 * time.Minute, ProfileQuick
	}
}

// Run executes nmap against host and returns the parsed result. A non-nil
// *models.NmapResult is returned even on failure, with Available/Unavailable
// describing why, so callers can surface the reason in a report.
func Run(ctx context.Context, host string, opts Options) (*models.NmapResult, error) {
	bin := FindBinary()
	if bin == "" {
		return &models.NmapResult{
			Available:   false,
			Unavailable: "nmap is not installed or not on PATH. Install it (e.g. `winget install Insecure.Nmap`) and re-run.",
		}, nil
	}

	args, defTimeout, profile := profileArgs(opts)
	if opts.Ports != "" && opts.Profile != ProfileFull {
		args = append(args, "-p", opts.Ports)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defTimeout
	}
	// -oX - streams XML to stdout; keep the human summary out of it.
	full := append([]string{"-oX", "-"}, args...)
	full = append(full, host)

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, bin, full...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	err := cmd.Run()

	res := &models.NmapResult{
		Available: true,
		Profile:   profile,
		Command:   "nmap " + strings.Join(full, " "),
	}
	for _, w := range splitLines(stderr.String()) {
		res.Warnings = append(res.Warnings, w)
	}

	if parseErr := parseXML(stdout.String(), res); parseErr != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			res.Available = false
			res.Unavailable = fmt.Sprintf("nmap exceeded the %s time limit for the %s profile", timeout, profile)
			return res, nil
		}
		if err != nil {
			res.Available = false
			res.Unavailable = "nmap failed: " + firstNonEmpty(strings.TrimSpace(stderr.String()), err.Error())
			return res, nil
		}
		return res, fmt.Errorf("parsing nmap output: %w", parseErr)
	}

	res.ElapsedSec = time.Since(start).Seconds()
	derivePrivilege(res)
	return res, nil
}

// derivePrivilege infers whether nmap had raw-packet privileges, from the scan
// type it chose and any fallback warnings it printed.
func derivePrivilege(res *models.NmapResult) {
	res.Privileged = res.ScanType == "syn" || res.ScanType == "ack" || len(res.OSMatches) > 0
	for _, w := range res.Warnings {
		lw := strings.ToLower(w)
		if strings.Contains(lw, "requires root") || strings.Contains(lw, "requires privileges") ||
			strings.Contains(lw, "operation not permitted") || strings.Contains(lw, "superuser privileges") {
			res.Privileged = false
		}
	}
}

// ── XML parsing ───────────────────────────────────────────────────────────────

type xmlRun struct {
	Version  string      `xml:"version,attr"`
	Args     string      `xml:"args,attr"`
	ScanInfo xmlScanInfo `xml:"scaninfo"`
	Hosts    []xmlHost   `xml:"host"`
	RunStats xmlRunStats `xml:"runstats"`
}

type xmlScanInfo struct {
	Type string `xml:"type,attr"`
}

type xmlRunStats struct {
	Finished struct {
		Elapsed float64 `xml:"elapsed,attr"`
		Summary string  `xml:"summary,attr"`
		TimeStr string  `xml:"timestr,attr"`
	} `xml:"finished"`
}

type xmlHost struct {
	StartTime int64 `xml:"starttime,attr"`
	Status    struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr   string `xml:"addr,attr"`
		Type   string `xml:"addrtype,attr"`
		Vendor string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports      []xmlPort    `xml:"ports>port"`
	OS         []xmlOSMatch `xml:"os>osmatch"`
	HostScript []xmlScript  `xml:"hostscript>script"`
}

type xmlPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"state"`
	Service struct {
		Name      string   `xml:"name,attr"`
		Product   string   `xml:"product,attr"`
		Version   string   `xml:"version,attr"`
		ExtraInfo string   `xml:"extrainfo,attr"`
		Tunnel    string   `xml:"tunnel,attr"`
		Conf      int      `xml:"conf,attr"`
		CPE       []string `xml:"cpe"`
	} `xml:"service"`
	Scripts []xmlScript `xml:"script"`
}

type xmlOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy int    `xml:"accuracy,attr"`
	Class    []struct {
		Vendor string `xml:"vendor,attr"`
		Family string `xml:"osfamily,attr"`
	} `xml:"osclass"`
}

type xmlScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

func parseXML(data string, res *models.NmapResult) error {
	data = strings.TrimSpace(data)
	if data == "" {
		return errors.New("empty nmap output")
	}
	var run xmlRun
	if err := xml.Unmarshal([]byte(data), &run); err != nil {
		return err
	}
	res.Version = run.Version
	res.ScanType = run.ScanInfo.Type
	res.ElapsedSec = run.RunStats.Finished.Elapsed
	res.Summary = run.RunStats.Finished.Summary

	if len(run.Hosts) == 0 {
		res.HostState = "down"
		return nil
	}
	h := run.Hosts[0]
	res.HostState = h.Status.State
	if h.StartTime > 0 {
		res.StartedAt = time.Unix(h.StartTime, 0).UTC()
	}
	for _, a := range h.Addresses {
		res.Addresses = append(res.Addresses, models.NmapAddr{Addr: a.Addr, Type: a.Type, Vendor: a.Vendor})
	}
	for _, n := range h.Hostnames {
		res.Hostnames = append(res.Hostnames, n.Name)
	}
	for _, p := range h.Ports {
		np := models.NmapPort{
			Port:       p.PortID,
			Protocol:   p.Protocol,
			State:      p.State.State,
			Reason:     p.State.Reason,
			Service:    p.Service.Name,
			Product:    p.Service.Product,
			Version:    p.Service.Version,
			ExtraInfo:  p.Service.ExtraInfo,
			Tunnel:     p.Service.Tunnel,
			Confidence: p.Service.Conf,
		}
		for _, c := range p.Service.CPE {
			if c = strings.TrimSpace(c); c != "" {
				np.CPE = append(np.CPE, c)
			}
		}
		for _, s := range p.Scripts {
			np.Scripts = append(np.Scripts, models.NmapScript{ID: s.ID, Output: strings.TrimSpace(s.Output)})
		}
		res.Ports = append(res.Ports, np)
	}
	for _, m := range h.OS {
		om := models.NmapOSMatch{Name: m.Name, Accuracy: m.Accuracy}
		if len(m.Class) > 0 {
			om.Vendor = m.Class[0].Vendor
			om.Family = m.Class[0].Family
		}
		res.OSMatches = append(res.OSMatches, om)
	}
	for _, s := range h.HostScript {
		res.HostScripts = append(res.HostScripts, models.NmapScript{ID: s.ID, Output: strings.TrimSpace(s.Output)})
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// splitLines returns non-empty, de-noised stderr lines (nmap prints progress
// and privilege notices there).
func splitLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "Starting Nmap") || strings.HasPrefix(ln, "Nmap scan report") {
			continue
		}
		out = append(out, ln)
	}
	return out
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// ValidateArgs rejects nmap flags that would break XML capture or write files,
// for the custom-args passthrough. It is a guardrail, not a security boundary;
// the authorization gate is the caller's responsibility.
func ValidateArgs(args []string) error {
	for _, a := range args {
		switch {
		case a == "-oX" || a == "-oN" || a == "-oG" || a == "-oA" || a == "-oS":
			return fmt.Errorf("output flag %q is managed by ReconX; remove it", a)
		case strings.HasPrefix(a, "--stylesheet"):
			return fmt.Errorf("%q is not allowed", a)
		case a == "--resume" || a == "--iflist":
			return fmt.Errorf("%q is not supported via ReconX", a)
		}
	}
	return nil
}

// ParsePortCount is a small helper for callers that want to show how many ports
// a spec covers (best-effort; returns 0 when unknown).
func ParsePortCount(spec string) int {
	if spec == "" {
		return 0
	}
	n := 0
	for _, part := range strings.Split(spec, ",") {
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, _ := strconv.Atoi(strings.TrimSpace(lo))
			b, _ := strconv.Atoi(strings.TrimSpace(hi))
			if b >= a && a > 0 {
				n += b - a + 1
			}
		} else if _, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			n++
		}
	}
	return n
}
