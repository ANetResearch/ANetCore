package wire_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/wire"
	"github.com/ANetResearch/ANetCore/wire/scan"
)

func reg(t *testing.T) *wire.Registry {
	t.Helper()
	r, err := wire.Load()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var (
	typeTagRe = regexp.MustCompile(`^anet\.[a-z0-9.-]+/[0-9]+$`)
	labelRe   = regexp.MustCompile(`^anet-[a-z0-9-]+/v[0-9]+$`)
	codeRe    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,29}$`) // CORE-K19
	sealRe    = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	metaRe    = regexp.MustCompile(`^anet\.[A-Za-z0-9_.]+$`)
	typeRe    = regexp.MustCompile(`^(uint|int|tstr|bstr|bool|float|any|map|null|bstr<[A-Za-z.]+>|<[A-Za-z.]+>|\[.+\]|tuple\(.+\))(\|(uint|int|tstr|bstr|bool|null))*$`)
)

// refs returns the object names a registry type mentions: <X>, bstr<X>, [<X>], [bstr<X>].
func refs(typ string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`<([A-Za-z.]+)>`).FindAllStringSubmatch(typ, -1) {
		out = append(out, m[1])
	}
	return out
}

// CORE-S2 (1): inside an object no key number and no field name appears twice.
func TestRegistryKeysAndNamesAreUnique(t *testing.T) {
	for _, o := range reg(t).Objects {
		names := map[string]int{}
		for _, k := range o.Keys {
			if k.Status != wire.StatusActive {
				continue
			}
			for _, n := range k.Names() {
				if prev, dup := names[n]; dup {
					t.Errorf("%s: name %q is key %d and key %d", o.Name, n, prev, k.N)
				}
				names[n] = k.N
			}
		}
	}
	// key numbers: Parse refuses a repeat; prove it does
	bad := strings.Replace(string(wire.RegistryJSON()),
		`{"n": 2, "name": "to", "type": "tstr", "req": "must", "status": "active", "v02": "tstr", "note": "recipient AID"}`,
		`{"n": 1, "name": "to", "type": "tstr", "req": "must", "status": "active", "v02": "tstr", "note": "recipient AID"}`, 1)
	if bad == string(wire.RegistryJSON()) {
		t.Fatal("test fixture: SealedEnvelope key 2 line not found")
	}
	if _, err := wire.Parse([]byte(bad)); err == nil || !strings.Contains(err.Error(), "key 1 twice") {
		t.Fatalf("a repeated key number parsed: %v", err)
	}
}

// CORE-S2 (2): a reserved or retired key is never also active, and every entry is well formed.
func TestRegistryKeyEntries(t *testing.T) {
	r := reg(t)
	statuses := map[string]bool{wire.StatusActive: true, wire.StatusReserved: true, wire.StatusRetired: true, wire.StatusForbidden: true}
	for _, o := range r.Objects {
		switch o.Keyspace {
		case wire.KeyspaceCritical, wire.KeyspaceClosed, wire.KeyspaceDerived:
		default:
			t.Errorf("%s: keyspace %q", o.Name, o.Keyspace)
		}
		switch o.Class {
		case "A", "D", "plain", "file":
		default:
			t.Errorf("%s: class %q", o.Name, o.Class)
		}
		for _, k := range o.Keys {
			where := o.Name + " key " + itoa(k.N)
			if !statuses[k.Status] {
				t.Errorf("%s: status %q", where, k.Status)
				continue
			}
			if k.N < 0 || k.Last() > 63 {
				t.Errorf("%s: outside 0-63 (keys >= 64 follow the keyspace)", where)
			}
			if k.To != 0 && (k.To <= k.N || k.Status == wire.StatusActive) {
				t.Errorf("%s: a range must be reserved, retired or forbidden and end after it starts", where)
			}
			if k.Status != wire.StatusActive {
				if k.Name != "" || k.Type != "" || k.Req != "" {
					t.Errorf("%s: a %s key has no name, type or presence rule (former name goes in was)", where, k.Status)
				}
				continue
			}
			if k.Name == "" || !typeRe.MatchString(k.Type) {
				t.Errorf("%s: name %q type %q", where, k.Name, k.Type)
			}
			switch k.Req {
			case "must", "may":
			case "cond":
				if k.Cond == "" {
					t.Errorf("%s: conditional without its condition", where)
				}
			default:
				t.Errorf("%s: req %q", where, k.Req)
			}
			if k.Size != 0 && !strings.HasPrefix(k.Type, "bstr") {
				t.Errorf("%s: size on a %s", where, k.Type)
			}
			for _, ref := range refs(k.Type) {
				if r.Object(ref) == nil {
					t.Errorf("%s: type refers to unknown object %q", where, ref)
				}
			}
		}
	}
}

// CORE-S2 (3): in an object that kept its v0.2.1 name, a key number whose type changed was
// retired and a new number assigned; it was never changed in place.
func TestRegistryNoKeyChangesTypeInPlace(t *testing.T) {
	carriedWithHistory := 0
	for _, o := range reg(t).Objects {
		if !o.Carried {
			for _, k := range o.Keys {
				if k.V02 != "" {
					t.Errorf("%s key %d: v02 type on an object that is new in 0.3.0", o.Name, k.N)
				}
			}
			continue
		}
		hist := false
		for _, k := range o.Keys {
			if k.V02 == "" {
				continue
			}
			hist = true
			if k.Status == wire.StatusActive && cborType(k.V02) != cborType(k.Type) {
				t.Errorf("%s key %d (%s): was %s in 0.2.1, is %s now: retire the key and assign a new number", o.Name, k.N, k.Name, k.V02, k.Type)
			}
			if k.Status == wire.StatusReserved {
				t.Errorf("%s key %d: was used in 0.2.1, so it is retired, not reserved", o.Name, k.N)
			}
		}
		if hist {
			carriedWithHistory++
		} else {
			t.Errorf("%s: marked carried but no key records its 0.2.1 type", o.Name)
		}
	}
	if carriedWithHistory < 10 {
		t.Fatalf("only %d carried objects with history; the check is vacuous", carriedWithHistory)
	}
}

// cborType is a registry type with the content annotation of a byte string dropped: bstr<X>
// is a bstr on the wire whatever X is.
func cborType(t string) string {
	return regexp.MustCompile(`bstr<[A-Za-z.]+>`).ReplaceAllString(t, "bstr")
}

// CORE-S2 (4): every label is distinct; within one construction none is a prefix of another;
// type tags and new labels follow their syntax; every typed object's tag is a registered label.
func TestRegistryLabels(t *testing.T) {
	r := reg(t)
	byClass := map[string][]string{}
	for _, tg := range r.Tags {
		for _, v := range tg.Values {
			byClass[tg.Class] = append(byClass[tg.Class], v)
			switch tg.Kind {
			case "typetag":
				if !typeTagRe.MatchString(v) {
					t.Errorf("%s: type tag %q does not match %s", tg.ID, v, typeTagRe)
				}
			case "label":
				if !labelRe.MatchString(v) {
					t.Errorf("%s: label %q does not match %s", tg.ID, v, labelRe)
				}
			case "carried":
				if tg.Since != "0.2.1" {
					t.Errorf("%s: a carried label is from 0.2.1", tg.ID)
				}
			default:
				t.Errorf("%s: kind %q", tg.ID, tg.Kind)
			}
		}
	}
	for class, vs := range byClass {
		sort.Strings(vs)
		for i := range vs {
			for j := range vs {
				if i != j && strings.HasPrefix(vs[j], vs[i]) {
					t.Errorf("class %s: %q is a prefix of %q", class, vs[i], vs[j])
				}
			}
		}
	}
	for _, o := range r.Objects {
		if o.Class == "A" || o.Class == "file" {
			if o.Tag == "" {
				t.Errorf("%s: class %s without a type tag", o.Name, o.Class)
				continue
			}
			if r.Tag(o.Tag) == nil {
				t.Errorf("%s: type tag %q is not in the label table", o.Name, o.Tag)
			}
			k0 := o.Key(0)
			if k0 == nil || k0.Status != wire.StatusActive || k0.Value != o.Tag {
				t.Errorf("%s: key 0 must carry the type tag %q", o.Name, o.Tag)
			}
		} else if o.Tag != "" {
			t.Errorf("%s: class %s with a type tag", o.Name, o.Class)
		}
	}
	// the label table is L1..L43, in order, none missing
	for i, tg := range r.Tags {
		if tg.ID != "L"+itoa(i+1) {
			t.Fatalf("label row %d is %s, want L%d", i, tg.ID, i+1)
		}
	}
	if len(r.Tags) != 43 {
		t.Fatalf("%d label rows, want 43", len(r.Tags))
	}
}

// CORE-S2 (5): reason codes follow CORE-K19, and a code shared between the hub, note and user
// namespaces is one code with one meaning (CORE-K18): every such repeat is declared.
func TestRegistryReasonCodes(t *testing.T) {
	r := reg(t)
	for ns, list := range r.Reasons.Namespaces() {
		if len(list) == 0 {
			t.Errorf("reasons.%s is empty", ns)
		}
		for _, c := range list {
			re := codeRe
			if ns == "seal" {
				re = sealRe
			}
			if !re.MatchString(c.Code) {
				t.Errorf("reasons.%s: %q does not match %s", ns, c.Code, re)
			}
			if ns == "hub" && (c.Status < 400 || c.Status > 599 || c.Class == "") {
				t.Errorf("reasons.hub %s: HTTP status %d, class %q", c.Code, c.Status, c.Class)
			}
		}
	}
	count := map[string]int{}
	for _, ns := range []string{"hub", "note", "user"} {
		for _, c := range r.ReasonCodes(ns) {
			count[c]++
		}
	}
	shared := map[string]bool{}
	for _, c := range r.Reasons.Shared {
		shared[c] = true
		if count[c] < 2 {
			t.Errorf("reasons.shared lists %q, which is in %d namespace(s)", c, count[c])
		}
	}
	for c, n := range count {
		if n > 1 && !shared[c] {
			t.Errorf("%q is in %d of hub, note and user but not declared shared (CORE-K18: one code, one meaning)", c, n)
		}
	}
	for _, c := range r.Reasons.Retired {
		for ns := range r.Reasons.Namespaces() {
			if r.Reason(ns, c.Code) != nil {
				t.Errorf("retired code %q is back in reasons.%s", c.Code, ns)
			}
		}
	}
	// CORE-K28: only codes, never sentence keys or variants, in the user namespace
	for _, c := range r.ReasonCodes("user") {
		if strings.ContainsAny(c, ".:") {
			t.Errorf("reasons.user holds %q: sentence keys and variants live only in the reason table", c)
		}
	}
	// CORE-K21: refusals decided after admission are status messages, never note codes
	for _, c := range []string{"sandbox_unavailable", "budget", "provider_policy"} {
		if r.Reason("note", c) != nil {
			t.Errorf("%q is a note code", c)
		}
	}
	for _, e := range r.HubAPI.Endpoints {
		for _, c := range e.Reasons {
			if r.Reason("hub", c) == nil {
				t.Errorf("%s %s answers %q, which is not a hub code", e.Method, e.Path, c)
			}
		}
	}
}

// CORE-S2 (6): a metadata key has one value type everywhere (CORE-K17), and the local
// projection keys never travel end to end.
func TestRegistryMetadataKeys(t *testing.T) {
	r := reg(t)
	seen := map[string]bool{}
	types := map[string]bool{"string": true, "uint": true, "bool": true, "object": true, "array": true, "any": true}
	for _, m := range r.Metadata {
		if seen[m.Key] {
			t.Errorf("%s twice (one key, one value type)", m.Key)
		}
		seen[m.Key] = true
		if !metaRe.MatchString(m.Key) || !types[m.ValueType] {
			t.Errorf("%s: key or value type %q", m.Key, m.ValueType)
		}
		if m.Status != wire.StatusActive && m.Status != wire.StatusDeleted {
			t.Errorf("%s: status %q", m.Key, m.Status)
		}
		for _, w := range m.Where {
			if m.LocalOnly && w == "e2e" {
				t.Errorf("%s is local-only but listed end to end", m.Key)
			}
		}
	}
	for _, k := range []string{"anet.delivery", "anet.delivery_detail", "anet.delivery_wait", "anet.content_expires_at",
		"anet.payment_note", "anet.spend_check", "anet.deduplicated", "anet.preview", "anet.identity_note"} {
		m := r.MetaKey(k)
		if m == nil || !m.LocalOnly || m.Status != wire.StatusActive {
			t.Errorf("%s must be registered, active and local-only (CORE-K17)", k)
		}
	}
	if m := r.MetaKey("anet.final"); m == nil || m.Status != wire.StatusDeleted {
		t.Error("anet.final must be registered as deleted")
	}
	if r.MetaKey("anet.preview_mode") == nil || r.MetaKey("anet.preview_mode").LocalOnly {
		t.Error("anet.preview_mode is the end-to-end request key")
	}
}

// the owner decision (no-terminal first join) as revision 3 of the core design registers it.
func TestRegistryD13(t *testing.T) {
	r := reg(t)
	idf := r.Object("IdentityFile")
	if k := idf.Key(7); k == nil || k.Name != "local_commit" || k.Type != "bstr" || k.Size != 32 || k.Req != "may" {
		t.Errorf("IdentityFile key 7: %+v", k)
	}
	kdf := r.Object("RecoveryKDF")
	if kdf == nil || len(kdf.Shapes) != 2 {
		t.Fatalf("RecoveryKDF must have exactly two shapes")
	}
	if got := kdf.Shapes[0].Keys; len(got) != 5 || !strings.Contains(kdf.Shapes[0].When, "argon2id") {
		t.Errorf("passphrase shape: %+v", kdf.Shapes[0])
	}
	if got := kdf.Shapes[1].Keys; len(got) != 1 || got[0] != 1 || !strings.Contains(kdf.Shapes[1].When, "local") {
		t.Errorf("local shape: %+v", kdf.Shapes[1])
	}
	if l20 := r.Tag("anet.recovery/1"); l20 == nil || !strings.Contains(l20.Build, "recovery_local.key") || !strings.Contains(l20.Key, "local recovery key") {
		t.Errorf("L20 must name the local recovery key mode")
	}
	if r.Reason("user", "recovery_file_unprotected") == nil {
		t.Error("recovery_file_unprotected missing from reasons.user")
	}
	if r.Reason("user", "recovery_setup_required") != nil {
		t.Error("recovery_setup_required is not introduced")
	}
	retired := false
	for _, c := range r.Reasons.Retired {
		retired = retired || c.Code == "recovery_setup_required"
	}
	if !retired {
		t.Error("recovery_setup_required must be listed so the name is never reused")
	}
	st := r.ControlRoute("/identity/status")
	found := false
	for _, f := range st.Response.Fields {
		if f.Name == "recovery" {
			found = true
			if strings.Join(f.Fields[0].Values, ",") != "none,unprotected,protected" {
				t.Errorf("recovery.state values %v", f.Fields[0].Values)
			}
		}
	}
	if !found {
		t.Error("/identity/status has no recovery")
	}
	hr := r.ControlRoute("/hub-register")
	names := map[string]bool{}
	for _, f := range hr.Request.Fields {
		names[f.Name] = true
	}
	if !names["next_digest"] || !names["unprotected"] {
		t.Error("/hub-register request needs next_digest and unprotected")
	}
	for _, alt := range hr.Response.Alt {
		for _, f := range alt.Fields {
			for _, v := range f.Values {
				if v == "recovery_setup_required" {
					t.Error("recovery_setup_required is not a join state")
				}
			}
		}
	}
}

func TestRegistryActionsAndEndpoints(t *testing.T) {
	r := reg(t)
	seen := map[string]bool{}
	for _, a := range r.Relayauth.Actions {
		if seen[a.Name] {
			t.Errorf("action %q twice", a.Name)
		}
		seen[a.Name] = true
		if a.Status != wire.StatusActive && a.Status != wire.StatusRetired {
			t.Errorf("action %q: status %q", a.Name, a.Status)
		}
	}
	for _, retired := range []string{"send", "p2p", "fedkeys"} {
		if a := r.Action(retired); a == nil || a.Status != wire.StatusRetired {
			t.Errorf("action %q must be retired", retired)
		}
	}
	eps := map[string]bool{}
	for _, e := range r.HubAPI.Endpoints {
		id := e.Method + " " + e.Path
		if eps[id] {
			t.Errorf("endpoint %s twice", id)
		}
		eps[id] = true
		if name, ok := strings.CutPrefix(e.Auth, "relayauth "); ok {
			name = strings.Fields(strings.TrimSuffix(name, ","))[0]
			name = strings.TrimSuffix(name, ",")
			if a := r.Action(name); a == nil || a.Status != wire.StatusActive {
				t.Errorf("%s: authenticated by unknown or retired action %q", id, name)
			}
		}
	}
	for _, a := range r.Relayauth.Actions {
		if a.Status == wire.StatusActive && a.Route != "" && a.Route != "-" && !eps[a.Route] {
			// the routes kept from wire 2 (poll, profile, ...) are not all listed with fields
			if strings.Contains(a.Route, "/fed/v3/") || strings.HasPrefix(a.Name, "fed_") {
				t.Errorf("action %s: route %q is not a registered endpoint", a.Name, a.Route)
			}
		}
	}
}

func TestRegistrySignersAndScanRules(t *testing.T) {
	r := reg(t)
	for _, c := range r.Signers.Calls {
		o := r.Object(c.Signs)
		if o == nil {
			t.Errorf("signer %s signs %q, which is not a registered object", c.Func, c.Signs)
			continue
		}
		// CORE-L9: an identity key signs typed (A) objects, or the carried D objects
		if o.Class != "A" && o.Class != "D" {
			t.Errorf("signer %s signs %s of class %s: an identity signature needs a key-0 type tag", c.Func, o.Name, o.Class)
		}
	}
	if len(r.Signers.Methods) == 0 {
		t.Error("no signing method: the signer scan would see nothing")
	}
	for _, c := range r.Scan.Consts {
		if r.Object(c.Object) == nil {
			t.Errorf("const rule %s*: unknown object %q", c.Prefix, c.Object)
		}
	}
	for _, g := range r.NUL {
		if r.Tag(g.Label) == nil && !hasTagID(r, g.Label) {
			t.Errorf("nul_guard %s: unknown label", g.Label)
		}
	}
	pat := regexp.MustCompile(r.Scan.Pattern)
	vals := map[string]bool{}
	for _, s := range r.Strings {
		if vals[s.Value] {
			t.Errorf("string %q twice", s.Value)
		}
		vals[s.Value] = true
		if !pat.MatchString(s.Value) {
			t.Errorf("string %q does not match the scan pattern", s.Value)
		}
		if st, where := r.StringStatus(s.Value); where != "string ("+s.Class+")" {
			t.Errorf("string %q is also a %s (%s)", s.Value, where, st)
		}
	}
	for _, x := range r.Exempt {
		if x.Match == "regexp" {
			if _, err := regexp.Compile(x.Value); err != nil {
				t.Errorf("exempt %q: %v", x.Value, err)
			}
		}
		// an exemption must not cover a registered label: a one-character change to a label
		// has to fail the scan (CORE-S8), not fall into an exemption
		for _, tg := range r.Tags {
			for _, v := range tg.Values {
				mut := v[:len(v)-1] + "9"
				if exempted(x, mut) {
					t.Errorf("exempt %q covers %q, a one-character change of %s", x.Value, mut, tg.ID)
				}
			}
		}
	}
}

func hasTagID(r *wire.Registry, id string) bool {
	for _, tg := range r.Tags {
		if tg.ID == id {
			return true
		}
	}
	return false
}

func exempted(x *wire.Exempt, v string) bool {
	switch x.Match {
	case "exact":
		return v == x.Value
	case "prefix":
		return strings.HasPrefix(v, x.Value)
	case "regexp":
		return regexp.MustCompile(x.Value).MatchString(v)
	}
	return false
}

// Every transition entry names a v030-todo work item; nothing in it is registered as active.
func TestTransitionEntries(t *testing.T) {
	tr, err := wire.LoadTransition()
	if err != nil {
		t.Fatal(err)
	}
	r := reg(t)
	for _, e := range tr.Entries {
		switch e.Kind {
		case wire.TransString:
			if st, _ := r.StringStatus(e.Value); st == wire.StatusActive {
				t.Errorf("transition string %q is registered and active: delete the entry", e.Value)
			}
		case wire.TransAction:
			if a := r.Action(e.Value); a != nil && a.Status == wire.StatusActive {
				t.Errorf("transition action %q is active: delete the entry", e.Value)
			}
		case wire.TransStruct:
			if len(e.Keys) == 0 {
				t.Errorf("transition struct %s without its keys", e.Go)
			}
		}
		if strings.Contains(e.Todo, "CORE-1)") {
			t.Errorf("%s %s%s: CORE-1 cannot leave work for itself", e.Kind, e.Go, e.Value)
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// repoRoot is the directory holding go.mod above the test's package directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		up := filepath.Dir(dir)
		if up == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = up
	}
}

// TestWireRegistry (CORE-S3, ANetCore): the code of this repository matches the registry.
func TestWireRegistry(t *testing.T) {
	ps, err := scan.Check(scan.Config{Dir: repoRoot(t), Repo: "ANetCore"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		t.Error(p.String())
	}
}
