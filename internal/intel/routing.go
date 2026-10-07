package intel

import (
	"fmt"
	"strings"

	"reconx/internal/enrich"
	"reconx/pkg/models"
)

// CompareRouting cross-checks RIPEstat's routing view of an IP against Team
// Cymru's. Both derive from BGP collectors but are independent pipelines, so
// a mismatch (e.g. a recent re-announcement, a MOAS prefix, or one source
// lagging) is worth surfacing. hasCymru is false when Cymru had no answer.
func CompareRouting(r *enrich.RoutingInfo, cymru PrefixInfo, hasCymru bool) *models.RoutingCheck {
	rc := &models.RoutingCheck{
		Source: "ripestat", Holder: r.Holder, Prefix: r.Prefix,
		Announced: r.Announced, RIR: r.RIR, Upstreams: r.Upstreams,
	}
	for _, a := range r.ASNs {
		rc.ASNs = append(rc.ASNs, "AS"+strings.TrimPrefix(strings.ToUpper(a), "AS"))
	}
	if !hasCymru {
		rc.Agreement = "ripestat-only"
		return rc
	}

	cymruASN := "AS" + strings.TrimPrefix(strings.ToUpper(cymru.ASN), "AS")
	if cymru.ASN != "" && len(rc.ASNs) > 0 && !contains(rc.ASNs, cymruASN) {
		rc.Conflicts = append(rc.Conflicts, fmt.Sprintf("Origin ASN: Team Cymru %s vs RIPEstat %s", cymruASN, strings.Join(rc.ASNs, "/")))
	}
	if cymru.Prefix != "" && rc.Prefix != "" && cymru.Prefix != rc.Prefix {
		rc.Conflicts = append(rc.Conflicts, fmt.Sprintf("Prefix: Team Cymru %s vs RIPEstat %s", cymru.Prefix, rc.Prefix))
	}
	if cymru.RIR != "" && rc.RIR != "" && normRIR(cymru.RIR) != normRIR(rc.RIR) {
		rc.Conflicts = append(rc.Conflicts, fmt.Sprintf("RIR: Team Cymru %s vs RIPEstat %s", strings.ToUpper(cymru.RIR), rc.RIR))
	}
	rc.Agreement = "agree"
	if len(rc.Conflicts) > 0 {
		rc.Agreement = "disagree"
	}
	return rc
}

// normRIR folds registry spellings together: Team Cymru writes "RIPENCC",
// RIPEstat "RIPE NCC"; LACNIC/AFRINIC vary similarly.
func normRIR(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '_' || r == '.' {
			return -1
		}
		return r
	}, strings.ToUpper(s))
}
