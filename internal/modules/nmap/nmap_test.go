package nmap

import (
	"testing"

	"reconx/pkg/models"
)

const sampleXML = `<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -oX - -A -Pn host" start="1791307556" version="7.80">
<scaninfo type="syn" protocol="tcp" numservices="1000"/>
<host starttime="1791307560">
<status state="up" reason="user-set"/>
<address addr="45.33.32.156" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Dell Inc."/>
<hostnames><hostname name="scanme.example.org" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:8.9p1</cpe></service><script id="ssh-hostkey" output="2048 aa:bb (RSA)"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Apache httpd" version="2.4.7" tunnel="ssl" conf="10"/></port>
<port protocol="tcp" portid="3306"><state state="filtered" reason="no-response"/><service name="mysql" method="table" conf="3"/></port>
</ports>
<os><osmatch name="Linux 5.0 - 5.4" accuracy="95"><osclass type="general purpose" vendor="Linux" osfamily="Linux"/></osmatch></os>
<hostscript><script id="smb-os-discovery" output="OS: Windows"/></hostscript>
</host>
<runstats><finished elapsed="12.34" summary="Nmap done; 1 host up"/></runstats>
</nmaprun>`

func TestParseXML(t *testing.T) {
	res := &models.NmapResult{Available: true}
	if err := parseXML(sampleXML, res); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Version != "7.80" || res.ScanType != "syn" || res.HostState != "up" {
		t.Errorf("header: version=%q scanType=%q state=%q", res.Version, res.ScanType, res.HostState)
	}
	if res.Summary != "Nmap done; 1 host up" || res.ElapsedSec != 12.34 {
		t.Errorf("runstats: %q %v", res.Summary, res.ElapsedSec)
	}
	if len(res.Addresses) != 2 || res.Addresses[1].Vendor != "Dell Inc." {
		t.Errorf("addresses: %+v", res.Addresses)
	}
	if len(res.Hostnames) != 1 || res.Hostnames[0] != "scanme.example.org" {
		t.Errorf("hostnames: %v", res.Hostnames)
	}
	if len(res.Ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(res.Ports))
	}
	ssh := res.Ports[0]
	if ssh.Port != 22 || ssh.State != "open" || ssh.Service != "ssh" || ssh.Product != "OpenSSH" {
		t.Errorf("ssh port: %+v", ssh)
	}
	if ssh.VersionString() != "OpenSSH 8.9p1 Ubuntu (Ubuntu Linux; protocol 2.0)" {
		t.Errorf("version string: %q", ssh.VersionString())
	}
	if len(ssh.CPE) != 1 || ssh.CPE[0] != "cpe:/a:openbsd:openssh:8.9p1" {
		t.Errorf("cpe: %v", ssh.CPE)
	}
	if len(ssh.Scripts) != 1 || ssh.Scripts[0].ID != "ssh-hostkey" {
		t.Errorf("port script: %+v", ssh.Scripts)
	}
	if res.Ports[1].Tunnel != "ssl" {
		t.Errorf("tunnel not parsed: %+v", res.Ports[1])
	}
	if len(res.OSMatches) != 1 || res.OSMatches[0].Accuracy != 95 || res.OSMatches[0].Family != "Linux" {
		t.Errorf("os: %+v", res.OSMatches)
	}
	if len(res.HostScripts) != 1 || res.HostScripts[0].ID != "smb-os-discovery" {
		t.Errorf("host script: %+v", res.HostScripts)
	}

	derivePrivilege(res)
	if !res.Privileged {
		t.Errorf("syn scan + OS match should be detected as privileged")
	}
	open := res.OpenPortsLegacy()
	if len(open) != 2 {
		t.Errorf("expected 2 open ports in legacy projection, got %d", len(open))
	}
}

func TestDerivePrivilegeFallback(t *testing.T) {
	res := &models.NmapResult{ScanType: "connect", Warnings: []string{"You requested a scan type which requires root privileges."}}
	derivePrivilege(res)
	if res.Privileged {
		t.Errorf("connect scan with privilege warning must be unprivileged")
	}
}

func TestProfileArgs(t *testing.T) {
	cases := map[string]string{ProfileQuick: "-sC", ProfileAggressive: "-A", ProfileFull: "-p-"}
	for profile, want := range cases {
		args, _, got := profileArgs(Options{Profile: profile})
		if got != profile {
			t.Errorf("profile name: got %q want %q", got, profile)
		}
		found := false
		for _, a := range args {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("profile %s args %v missing %q", profile, args, want)
		}
	}
}

func TestValidateArgs(t *testing.T) {
	if err := ValidateArgs([]string{"-sV", "--script", "vuln"}); err != nil {
		t.Errorf("valid args rejected: %v", err)
	}
	if err := ValidateArgs([]string{"-oX", "out.xml"}); err == nil {
		t.Errorf("output flag should be rejected")
	}
}

func TestParsePortCount(t *testing.T) {
	if n := ParsePortCount("1-1024,8080,8443"); n != 1026 {
		t.Errorf("port count = %d, want 1026", n)
	}
}
