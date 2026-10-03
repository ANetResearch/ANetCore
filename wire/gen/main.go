// Command gen renders docs/wire-keys.md from wire/registry.json (CORE-S7).
//
//	go run ./wire/gen            # rewrite docs/wire-keys.md
//	go run ./wire/gen -check     # exit 1 when docs/wire-keys.md is not up to date
//
// Run it from the ANetCore module root. The test beside it fails when the committed document
// differs from what the registry renders, so a registry change and its document travel together.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/ANetResearch/ANetCore/wire"
)

// DocPath is the generated document, relative to the module root.
const DocPath = "docs/wire-keys.md"

func main() {
	check := flag.Bool("check", false, "only compare; exit 1 when the document is stale")
	out := flag.String("o", DocPath, "output path")
	flag.Parse()
	r, err := wire.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	doc := Render(r)
	if *check {
		have, err := os.ReadFile(*out)
		if err != nil || !bytes.Equal(have, doc) {
			fmt.Fprintf(os.Stderr, "%s is not up to date: run go run ./wire/gen\n", *out)
			os.Exit(1)
		}
		return
	}
	if err := os.WriteFile(*out, doc, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type doc struct{ b bytes.Buffer }

func (d *doc) p(format string, args ...any) { fmt.Fprintf(&d.b, format+"\n", args...) }

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	if s == "" {
		return "—"
	}
	return s
}

func code(s string) string {
	if s == "" || s == "-" {
		return "—"
	}
	return "`" + strings.ReplaceAll(s, "|", `\|`) + "`"
}

func codes(list []string) string {
	if len(list) == 0 {
		return "—"
	}
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = code(s)
	}
	return strings.Join(out, ", ")
}

var groupTitles = []struct{ id, title string }{
	{"envelope", "Sealed envelope"},
	{"body", "Message bodies"},
	{"keys", "Encryption key set"},
	{"kel", "Key event log and witness notices"},
	{"directory", "Directory"},
	{"evidence", "Evidence, reviews and liabilities"},
	{"c1", "C1 (anet ↔ ANetLink) and capability effects"},
	{"carried", "Carried signed objects"},
	{"tsir", "Task documents"},
	{"local", "Local files"},
	{"module", "ANet module objects"},
}

func presence(k *wire.Key) string {
	switch k.Req {
	case "must":
		return "required"
	case "may":
		return "optional"
	case "cond":
		return "if " + k.Cond
	}
	return k.Req
}

func keyType(k *wire.Key) string {
	t := code(k.Type)
	if k.Size != 0 {
		t += " (" + strconv.Itoa(k.Size) + " bytes)"
	}
	if k.Value != "" {
		t += " = " + code(k.Value)
	}
	return t
}

func keyNum(k *wire.Key) string {
	if k.To > k.N {
		return fmt.Sprintf("%d–%d", k.N, k.To)
	}
	return strconv.Itoa(k.N)
}

func keyspace(o *wire.Object) string {
	switch o.Keyspace {
	case wire.KeyspaceCritical:
		return "keys 0–63 must be understood; keys ≥ 64 may be ignored but stay covered"
	case wire.KeyspaceClosed:
		return "closed: every unregistered key is refused"
	case wire.KeyspaceDerived:
		return "built and hashed or signed, never decoded"
	}
	return o.Keyspace
}

func fields(d *doc, title string, b *wire.Body) {
	if b == nil {
		return
	}
	if b.Raw != "" {
		d.p("%s: %s", title, b.Raw)
		d.p("")
		return
	}
	if len(b.Alt) > 0 {
		for _, alt := range b.Alt {
			fields(d, title+" ("+alt.When+")", alt)
		}
		return
	}
	note := ""
	if b.Partial {
		note = " (only the members this version adds or changes)"
	}
	if b.Strict {
		note += "; decoded strictly: an unknown member is 400 `bad_request`"
	}
	if len(b.Fields) == 0 {
		d.p("%s%s: as in wire 2.", title, note)
		d.p("")
		return
	}
	d.p("%s%s:", title, note)
	d.p("")
	d.p("| Member | Type | Presence | Notes |")
	d.p("|---|---|---|---|")
	var walk func(prefix string, fs []*wire.Field)
	walk = func(prefix string, fs []*wire.Field) {
		for _, f := range fs {
			typ := f.Type
			if len(f.Values) > 0 {
				typ += ": " + codes(f.Values)
			}
			pres := map[string]string{"must": "required", "may": "optional", "cond": "conditional"}[f.Req]
			d.p("| %s | %s | %s | %s |", code(prefix+f.Name), typ, cell(pres), cell(f.Note))
			walk(prefix+f.Name+".", f.Fields)
		}
	}
	walk("", b.Fields)
	d.p("")
}

// Render returns the document for r.
func Render(r *wire.Registry) []byte {
	d := &doc{}
	d.p("# anet %s wire keys", r.Release)
	d.p("")
	d.p("<!-- Generated from wire/registry.json by `go run ./wire/gen`. Do not edit by hand. -->")
	d.p("")
	d.p("This is the register of everything anet %s puts on the wire or under a signature: key numbers and", r.Release)
	d.p("types of every CBOR object, domain-separation labels, relayauth actions, reason codes, the hub API,")
	d.p("the control-plane fields other components rely on, A2A metadata keys and evidence events.")
	d.p("`wire/registry.json` is the source; `TestWireRegistry` in each repository checks the code against it.")
	d.p("")
	d.p("Key numbers, labels, actions and codes are never reused: a removed key is *retired* and refused when")
	d.p("present; a *reserved* key has never been assigned and is refused too. CBOR is CoreDet (RFC 8949 §4.2")
	d.p("deterministic encoding, no tags); signed bodies travel as byte strings holding their CoreDet encoding.")
	d.p("")

	d.p("## Versions")
	d.p("")
	d.p("| | Layer | %s | Where | Constant |", r.Release)
	d.p("|---|---|---|---|---|")
	for _, v := range r.Versions {
		d.p("| %s | %s | %s | %s | %s |", v.ID, cell(v.Layer), cell(v.Value), cell(v.Where), cell(v.Const))
	}
	d.p("")

	d.p("## Objects")
	d.p("")
	d.p("Types: `uint`, `int`, `tstr`, `bstr`, `bool`, `float`, `any`, `map`; `<X>` is object X; `bstr<X>` a byte")
	d.p("string holding CoreDet(X); `[T]` an array of T. Objects marked *typed* carry their type tag in key 0.")
	d.p("")
	for _, g := range groupTitles {
		var objs []*wire.Object
		for _, o := range r.Objects {
			if o.Group == g.id {
				objs = append(objs, o)
			}
		}
		if len(objs) == 0 {
			continue
		}
		d.p("### %s", g.title)
		d.p("")
		for _, o := range objs {
			d.p("#### %s", o.Name)
			d.p("")
			d.p("%s", o.Desc)
			d.p("")
			var facts []string
			if o.Tag != "" {
				facts = append(facts, "typed `"+o.Tag+"`")
			}
			facts = append(facts, keyspace(o))
			if o.Carried {
				facts = append(facts, "name carried over from 0.2.1")
			}
			d.p("*%s.*", strings.Join(facts, "; "))
			d.p("")
			if len(o.Keys) == 0 {
				d.p("No keys: the empty map.")
				d.p("")
				continue
			}
			d.p("| Key | Name | Type | Presence | Notes |")
			d.p("|---|---|---|---|---|")
			for _, k := range o.Keys {
				if k.Status != wire.StatusActive {
					note := k.Note
					if k.Was != "" {
						note = strings.TrimSpace("was `" + k.Was + "`. " + note)
					}
					d.p("| %s | — | — | %s | %s |", keyNum(k), k.Status, cell(note))
					continue
				}
				d.p("| %s | %s | %s | %s | %s |", keyNum(k), code(k.Name), keyType(k), cell(presence(k)), cell(k.Note))
			}
			d.p("")
			for _, s := range o.Shapes {
				nums := make([]string, len(s.Keys))
				for i, n := range s.Keys {
					nums[i] = strconv.Itoa(n)
				}
				d.p("- Shape: %s — keys %s.", s.When, strings.Join(nums, ", "))
			}
			if len(o.Shapes) > 0 {
				d.p("")
			}
		}
	}

	d.p("## Labels and type tags")
	d.p("")
	d.p("Classes: A = typed CoreDet map (key 0 is the tag); B = prefix string `label || 0x00 || fields`;")
	d.p("C = KDF, HPKE or MAC context; text = relayauth text preimage. Labels are ASCII bytes, no length")
	d.p("prefix, no trailing NUL.")
	d.p("")
	d.p("| | Label | Class | Construction | Key | Vectors |")
	d.p("|---|---|---|---|---|---|")
	for _, t := range r.Tags {
		cls := t.Class
		if t.Local {
			cls += " (local)"
		}
		d.p("| %s | %s | %s | %s | %s | %s |", t.ID, codes(t.Values), cell(cls), cell(t.Build), cell(t.Key), cell(t.Golden))
	}
	d.p("")

	d.p("## relayauth actions")
	d.p("")
	d.p("Preimage: `%s` + action + `/` + aid + `/` + hubAID + `/` + decimal(ts) + `/` + base64url(SHA-256(method || 0x00 || pathAndQuery || 0x00 || body)).", r.Relayauth.Prefix)
	d.p("")
	d.p("| Action | Route | Signer | Status |")
	d.p("|---|---|---|---|")
	for _, a := range r.Relayauth.Actions {
		d.p("| %s | %s | %s | %s |", code(a.Name), cell(a.Route), cell(a.Signer), a.Status)
	}
	d.p("")

	d.p("## Hub API (wire %d)", r.HubAPI.Wire)
	d.p("")
	d.p("Binary values in JSON are base64url without padding, except public hashes (64 lowercase hex).")
	d.p("Every error body is `{\"reason\": <code>, \"error\": <one English sentence>, …}`.")
	d.p("")
	d.p("### Headers")
	d.p("")
	d.p("| Header | Direction | Where | Value |")
	d.p("|---|---|---|---|")
	for _, h := range r.HubAPI.Headers {
		d.p("| %s | %s | %s | %s |", code(h.Name), cell(h.Dir), cell(h.Where), cell(h.Value))
	}
	d.p("")
	d.p("### Endpoints")
	d.p("")
	for _, e := range r.HubAPI.Endpoints {
		d.p("#### `%s %s`", e.Method, e.Path)
		d.p("")
		d.p("Authentication: %s.", e.Auth)
		d.p("")
		fields(d, "Request", e.Request)
		fields(d, "Response", e.Response)
		if len(e.Reasons) > 0 {
			d.p("Codes: %s.", codes(e.Reasons))
			d.p("")
		}
		if e.Note != "" {
			d.p("%s.", strings.TrimSuffix(e.Note, "."))
			d.p("")
		}
	}
	d.p("Removed: %s.", strings.Join(r.HubAPI.Removed, "; "))
	d.p("")

	d.p("## p2p frames (v %d)", r.P2P.Version)
	d.p("")
	d.p("| Op | Direction | Members | Optional | Notes |")
	d.p("|---|---|---|---|---|")
	for _, f := range r.P2P.Frames {
		d.p("| %s | %s | %s | %s | %s |", code(f.Op), cell(f.Dir), codes(f.Fields), codes(f.May), cell(f.Note))
	}
	d.p("")
	d.p("Removed: %s.", strings.Join(r.P2P.Removed, ", "))
	d.p("")

	d.p("## Control plane")
	d.p("")
	d.p("The local bearer-authenticated API of the daemon. Only the members several components rely on are")
	d.p("registered. Binary values are standard base64.")
	d.p("")
	for _, c := range r.Control {
		d.p("### %s", c.Route)
		d.p("")
		fields(d, "Request", c.Request)
		fields(d, "Response", c.Response)
		if c.Note != "" {
			d.p("%s.", strings.TrimSuffix(c.Note, "."))
			d.p("")
		}
	}

	d.p("## A2A URIs")
	d.p("")
	d.p("| URI | Where | Status | Notes |")
	d.p("|---|---|---|---|")
	for _, u := range r.URIs {
		d.p("| %s | %s | %s | %s |", code(u.URI), cell(u.Where), u.Status, cell(u.Note))
	}
	d.p("")

	d.p("## Metadata keys")
	d.p("")
	d.p("`e2e`: inside the sealed body, between peers. `local`: on what this node projects to its own clients")
	d.p("(local A2A, control plane, MCP); a local-only key is never sent to a peer and never read from one.")
	d.p("")
	d.p("| Key | Where | Value | Status | Notes |")
	d.p("|---|---|---|---|---|")
	for _, m := range r.Metadata {
		where := strings.Join(m.Where, ", ")
		if m.LocalOnly {
			where += " (local only)"
		}
		val := m.ValueType
		if len(m.Values) > 0 {
			val += ": " + strings.Join(m.Values, ", ")
		}
		d.p("| %s | %s | %s | %s | %s |", code(m.Key), cell(where), cell(val), m.Status, cell(m.Note))
	}
	d.p("")

	d.p("## TaskDoc contexts")
	d.p("")
	d.p("| Key | Format | Visibility | Presence | Notes |")
	d.p("|---|---|---|---|---|")
	for _, c := range r.Contexts {
		d.p("| %s | %s | %s | %s | %s |", code(c.Key), c.Format, c.Visibility, c.Req, cell(c.Note))
	}
	d.p("")

	d.p("## Evidence events")
	d.p("")
	d.p("| Event | Status | Payload | Notes |")
	d.p("|---|---|---|---|")
	for _, e := range r.Events {
		d.p("| %s | %s | %s | %s |", code(e.Type), e.Status, codes(e.Payload), cell(e.Note))
	}
	d.p("")
	d.p("ael records:")
	d.p("")
	d.p("| Type | Version | Payload | Status |")
	d.p("|---|---|---|---|")
	for _, a := range r.AEL {
		d.p("| %s | %d | %s | %s |", code(a.Type), a.VersionMajor, codes(a.Payload), a.Status)
	}
	d.p("")

	d.p("## Reason codes")
	d.p("")
	d.p("Seal reasons are kebab-case and only counted and logged. Wire and user codes match")
	d.p("`^[a-z][a-z0-9_]{0,29}$`; one code has one meaning wherever it appears.")
	d.p("")
	d.p("Hub (wire %d):", r.HubAPI.Wire)
	d.p("")
	d.p("| Code | HTTP | Class | Notes |")
	d.p("|---|---|---|---|")
	for _, c := range r.Reasons.Hub {
		d.p("| %s | %d | %s | %s |", code(c.Code), c.Status, c.Class, cell(c.Note))
	}
	d.p("")
	list := func(title string, rs []*wire.Reason) {
		names := make([]string, len(rs))
		for i, c := range rs {
			names[i] = c.Code
		}
		d.p("%s: %s.", title, codes(names))
		d.p("")
	}
	list("Seal", r.Reasons.Seal)
	list("Delivery note", r.Reasons.Note)
	list("C1 (internal to ANetLink; never shown to a user as is)", r.Reasons.C1)
	list("x402 errorReason additions", r.Reasons.X402)
	users := make([]*wire.Reason, len(r.Reasons.User))
	copy(users, r.Reasons.User)
	sort.Slice(users, func(i, j int) bool { return users[i].Code < users[j].Code })
	list("User (the reason table of the daemon; sentences and variants live only there)", users)
	list("Hub operator", r.Reasons.HubOperator)
	d.p("Retired or never introduced (never to be reused):")
	d.p("")
	for _, c := range r.Reasons.Retired {
		d.p("- %s: %s", code(c.Code), c.Note)
	}
	d.p("")

	for _, l := range r.Layouts {
		d.p("## Layout: %s (%d bytes)", l.Name, l.Len)
		d.p("")
		d.p("| Part | Offset | Length | Content |")
		d.p("|---|---|---|---|")
		for _, p := range l.Parts {
			d.p("| %s | %d | %d | %s |", p.Of, p.Off, p.Len, cell(p.What))
		}
		d.p("")
	}

	d.p("## Shared storage")
	d.p("")
	d.p("| Where | Table | Columns | Never | Notes |")
	d.p("|---|---|---|---|---|")
	for _, t := range r.Storage {
		d.p("| %s | %s | %s | %s | %s |", t.Where, code(t.Table), cell(strings.Join(t.Columns, "; ")), codes(t.Never), cell(t.Note))
	}
	d.p("")

	d.p("## Other registered strings")
	d.p("")
	d.p("| String | Class | Status | Notes |")
	d.p("|---|---|---|---|")
	for _, s := range r.Strings {
		d.p("| %s | %s | %s | %s |", code(s.Value), s.Class, s.Status, cell(s.Note))
	}
	d.p("")

	d.p("## Identity-key signers")
	d.p("")
	d.p("Every call of an identity signing method (%s), and every reference that hands one on, is", codes(r.Signers.Methods))
	d.p("made from one of these functions; each signs a typed object, one of the carried untyped ones,")
	d.p("or the relayauth text preimage (L22).")
	d.p("")
	d.p("| Repository | Function | Signs |")
	d.p("|---|---|---|")
	for _, s := range r.Signers.Calls {
		d.p("| %s | %s | %s |", s.Repo, code(s.Func), cell(s.Signs))
	}
	d.p("")

	d.p("## Fields that must not hold U+0000")
	d.p("")
	d.p("Functions that build a 0x00-separated input refuse a text field holding U+0000:")
	d.p("")
	for _, g := range r.NUL {
		d.p("- %s %s (%s)", g.Repo, g.What, g.Label)
	}
	return d.b.Bytes()
}
