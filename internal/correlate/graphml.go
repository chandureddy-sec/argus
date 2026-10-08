package correlate

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"reconx/pkg/models"
)

// WriteGraphML writes the graph in GraphML, which Gephi, yEd, Cytoscape and
// Maltego (via import) open directly. Node kind, detail, flags and weight and
// edge relation and evidence are exported as attributes.
func WriteGraphML(g *models.InfraGraph, w io.Writer) error {
	if g == nil {
		return fmt.Errorf("no graph")
	}
	esc := func(s string) string {
		var b strings.Builder
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	var sb strings.Builder
	sb.WriteString(xml.Header)
	sb.WriteString(`<graphml xmlns="http://graphml.graphdrawing.org/xmlns">` + "\n")
	for _, k := range []struct{ id, on, name, typ string }{
		{"label", "node", "label", "string"},
		{"kind", "node", "kind", "string"},
		{"detail", "node", "detail", "string"},
		{"flags", "node", "flags", "string"},
		{"weight", "node", "weight", "int"},
		{"rel", "edge", "relation", "string"},
		{"evidence", "edge", "evidence", "string"},
	} {
		fmt.Fprintf(&sb, `  <key id="%s" for="%s" attr.name="%s" attr.type="%s"/>`+"\n", k.id, k.on, k.name, k.typ)
	}
	fmt.Fprintf(&sb, `  <graph id="%s" edgedefault="directed">`+"\n", esc(g.Target))
	for _, n := range g.Nodes {
		fmt.Fprintf(&sb, `    <node id="%s"><data key="label">%s</data><data key="kind">%s</data><data key="detail">%s</data><data key="flags">%s</data><data key="weight">%d</data></node>`+"\n",
			esc(n.ID), esc(n.Label), esc(n.Kind), esc(n.Detail), esc(strings.Join(n.Flags, ",")), n.Weight)
	}
	for i, e := range g.Edges {
		fmt.Fprintf(&sb, `    <edge id="e%d" source="%s" target="%s"><data key="rel">%s</data><data key="evidence">%s</data></edge>`+"\n",
			i, esc(e.From), esc(e.To), esc(e.Rel), esc(e.Evidence))
	}
	sb.WriteString("  </graph>\n</graphml>\n")
	_, err := io.WriteString(w, sb.String())
	return err
}
