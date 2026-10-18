"""Write every shape of generated rule to a folder, for checks by the real
engines (CI runs ``suricata -T`` on the output; ADR 0020).

usage: python scripts/detection_samples.py OUTDIR
"""

from __future__ import annotations

import sys
from pathlib import Path

from threatlens.detect import rules as gen

# Synthetic values (documentation ranges and example domains) covering every
# rule shape, including characters Suricata needs escaped.
SAMPLES = [
    gen.Ioc(1, "ipv4-addr", "203.0.113.7", 76, "TLP:CLEAR", ("botnet-c2",), ("feodo",)),
    gen.Ioc(2, "ipv4-net", "198.51.100.0/24", 70, "TLP:GREEN", ("drop",), ("spamhaus_drop",)),
    gen.Ioc(3, "ipv6-addr", "2001:db8::7", 70, "TLP:CLEAR", ("tor",), ("tor_exits",)),
    gen.Ioc(4, "domain-name", "evil-c2.example", 80, "TLP:CLEAR", ("botnet-c2",), ("threatfox",)),
    gen.Ioc(
        5, "url", 'http://bad.example:8080/a;b"c|d\\e.sh?x=1', 72, "TLP:CLEAR", ("malware-distribution",), ()
    ),
    gen.Ioc(6, "url", "https://login-bank.example/verify", 66, "TLP:CLEAR", ("phishing",), ("openphish",)),
    gen.Ioc(
        7,
        "file-sha256",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        90,
        "TLP:AMBER",
        ("qakbot",),
        (),
    ),
]


def main(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    suricata = gen.suricata_rules(SAMPLES, author="Argus CI")
    lines = [ln for r in suricata for ln in r.body.splitlines() if ln and not ln.startswith("#")]
    (out / "argus.rules").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    for r in gen.yara_rules(SAMPLES, author="Argus CI"):
        (out / r.name).write_text(r.body, encoding="utf-8", newline="\n")
    for r in gen.sigma_rules(SAMPLES, author="Argus CI", base_url="https://argus.example"):
        (out / r.name).write_text(r.body, encoding="utf-8", newline="\n")
    (out / "argus_rules.xml").write_text(gen.wazuh_rules("Argus CI").body, encoding="utf-8", newline="\n")
    print(f"{len(lines)} Suricata rules and the other formats written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "detection-samples")))
