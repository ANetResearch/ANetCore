// Package wire is the machine-readable register of everything anet puts on the wire or under a
// signature: object key numbers, field names and types, domain-separation labels, relayauth
// actions, reason codes, hub API and control-plane fields, metadata keys and evidence events.
//
// registry.json is the single source. Three kinds of reader use it:
//
//   - registry_test.go checks the register against itself (no duplicate key numbers or labels,
//     no retired key reused, label and code syntax, metadata keys with one value type);
//   - wire/scan checks the code of a repository against the register (every keyasint struct,
//     every seal key constant, every "anet…" string literal, every relayauth action, every
//     call that signs with an identity key);
//   - wire/gen renders docs/wire-keys.md from it.
//
// transition.json lists the v0.2 shapes that are still in the code while the v0.3.0 rewrite is
// under way. Every entry names the work item that removes it (TodoMarker); the list must be
// empty before release.
package wire

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

//go:embed registry.json
var registryJSON []byte

//go:embed transition.json
var transitionJSON []byte

// Format is the value of Registry.Format this package reads.
const Format = "anet-wire-registry/1"

// Registry is registry.json decoded. Slices keep the order of the file, which is the order of
// the generated document.
type Registry struct {
	Format    string       `json:"format"`
	Release   string       `json:"release"`
	About     string       `json:"about"`
	Versions  []*Version   `json:"versions"`
	Objects   []*Object    `json:"objects"`
	Tags      []*Tag       `json:"tags"`
	Relayauth Relayauth    `json:"relayauth"`
	HubAPI    HubAPI       `json:"hub_api"`
	P2P       P2P          `json:"p2p"`
	Control   []*Route     `json:"control"`
	Metadata  []*MetaKey   `json:"metadata"`
	URIs      []*URI       `json:"a2a_uris"`
	Contexts  []*TaskCtx   `json:"taskdoc_contexts"`
	Events    []*Event     `json:"events"`
	AEL       []*AELRecord `json:"ael_records"`
	Reasons   Reasons      `json:"reasons"`
	Layouts   []*Layout    `json:"layouts"`
	Storage   []*Table     `json:"storage"`
	Strings   []*String    `json:"strings"`
	Exempt    []*Exempt    `json:"exempt"`
	Signers   Signers      `json:"signers"`
	Scan      ScanRules    `json:"scan"`
	NUL       []*NULGuard  `json:"nul_guard"`
	objects   map[string]*Object
	tags      map[string]*Tag
	reasonSet map[string]map[string]*Reason
}

// Version is one row of the version table: what changed on one layer and where the constant lives.
type Version struct {
	ID    string `json:"id"`
	Layer string `json:"layer"`
	Value string `json:"value"`
	Where string `json:"where"`
	Const string `json:"const,omitempty"`
}

// Key spaces of an object.
const (
	// KeyspaceCritical: keys 0–63 must be understood (an unregistered one is refused); keys ≥ 64
	// may be ignored but stay under the signature or digest. Outer envelope, Wrap, inner.
	KeyspaceCritical = "critical"
	// KeyspaceClosed: every unregistered key is refused, ≥ 64 included.
	KeyspaceClosed = "closed"
	// KeyspaceDerived: a map that is built, hashed or signed but never decoded from the wire
	// (preimages, HPKE info). It has no negative decoding cases.
	KeyspaceDerived = "derived"
	// KeyspaceExternal: a signed input that is not a CBOR map at all and is defined outside
	// anet (the A2A card JWS signing input, core CORE-S1). It has no keys and no negative
	// decoding cases; it is registered so that the signers can name what they sign.
	KeyspaceExternal = "external"
)

// Key statuses.
const (
	StatusActive    = "active"    // assigned and in use
	StatusReserved  = "reserved"  // never assigned; refused when present; may be assigned later
	StatusRetired   = "retired"   // was in use; refused when present; never assigned again
	StatusForbidden = "forbidden" // never on the wire (preimage-only keys); refused when present
	StatusDeleted   = "deleted"   // (strings, keys, events) removed in this release; must not appear
)

// Object is a CBOR map with integer keys.
type Object struct {
	Name     string   `json:"name"`
	Group    string   `json:"group"`
	Class    string   `json:"class"` // A (typed, key 0 tag), D (carried, untyped, signed), plain, file
	Tag      string   `json:"tag,omitempty"`
	Keyspace string   `json:"keyspace"`
	Carried  bool     `json:"carried,omitempty"` // the object existed under this name in v0.2.1
	Owner    string   `json:"owner"`
	Desc     string   `json:"desc"`
	Keys     []*Key   `json:"keys"`
	Shapes   []*Shape `json:"shapes,omitempty"`
	byNum    map[int]*Key
}

// Shape is one allowed combination of keys of an object that has more than one form.
type Shape struct {
	When string `json:"when"`
	Keys []int  `json:"keys"`
}

// Key is one key number of an object, or a range of them (N..To) with one status.
type Key struct {
	N       int      `json:"n"`
	To      int      `json:"to,omitempty"`
	Name    string   `json:"name,omitempty"`
	Type    string   `json:"type,omitempty"`
	Size    int      `json:"size,omitempty"`
	Value   string   `json:"value,omitempty"`
	Req     string   `json:"req,omitempty"` // must, may, cond
	Cond    string   `json:"cond,omitempty"`
	Status  string   `json:"status"`
	Was     string   `json:"was,omitempty"` // retired: the name it had
	V02     string   `json:"v02,omitempty"` // the type this key number had in v0.2.1 ("" = it did not exist)
	Aliases []string `json:"aliases,omitempty"`
	Note    string   `json:"note,omitempty"`
}

// Last is the last key number a Key covers.
func (k *Key) Last() int {
	if k.To > k.N {
		return k.To
	}
	return k.N
}

// Tag is a domain-separation label or a type tag (one row of the label table; it may carry
// several strings that share a construction).
type Tag struct {
	ID     string   `json:"id"`
	Values []string `json:"values"`
	Class  string   `json:"class"` // A, B, C, D, text, type (inner type), file, carried
	Kind   string   `json:"kind"`  // typetag (anet.<name>/<n>) or label (anet-<name>/v<n>) or carried
	Since  string   `json:"since"` // 0.3.0 or 0.2.1
	Build  string   `json:"build"` // the exact construction
	Key    string   `json:"key"`   // the key the operation uses
	Owner  string   `json:"owner"`
	Golden string   `json:"golden"`
	Local  bool     `json:"local,omitempty"` // only inside this node; never on the wire
}

// Relayauth is the relayauth preimage prefix and the action set.
type Relayauth struct {
	Prefix  string    `json:"prefix"`
	Actions []*Action `json:"actions"`
}

// Action is one relayauth action.
type Action struct {
	Name   string `json:"name"`
	Route  string `json:"route"`
	Signer string `json:"signer"`
	Status string `json:"status"`
	Owner  string `json:"owner"`
}

// HubAPI is wire 3 of the hub HTTP API.
type HubAPI struct {
	Wire      int         `json:"wire"`
	Headers   []*Header   `json:"headers"`
	Endpoints []*Endpoint `json:"endpoints"`
	Removed   []string    `json:"removed"`
}

// Header is one X-ANet-* (or standard) header.
type Header struct {
	Name  string `json:"name"`
	Dir   string `json:"dir"`
	Where string `json:"where"`
	Value string `json:"value"`
	Owner string `json:"owner"`
}

// Endpoint is one hub route. Partial bodies list only the fields wire 3 adds or changes; the
// rest are as in wire 2.
type Endpoint struct {
	Method   string   `json:"method"`
	Path     string   `json:"path"`
	Auth     string   `json:"auth"`
	Request  *Body    `json:"request,omitempty"`
	Response *Body    `json:"response,omitempty"`
	Reasons  []string `json:"reasons,omitempty"`
	Owner    string   `json:"owner"`
	Note     string   `json:"note,omitempty"`
}

// Body is a JSON body: its fields, or (Raw) a non-JSON body.
type Body struct {
	Raw     string   `json:"raw,omitempty"`
	Partial bool     `json:"partial,omitempty"`
	Strict  bool     `json:"strict,omitempty"` // request decoded strictly (unknown member → 400 bad_request)
	Fields  []*Field `json:"fields,omitempty"`
	Alt     []*Body  `json:"alt,omitempty"` // alternative bodies (e.g. register vs check_only)
	When    string   `json:"when,omitempty"`
}

// Field is a JSON member.
type Field struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"` // string, b64url, hex, uint, int, bool, object, array, any, enum
	Req    string   `json:"req"`
	Values []string `json:"values,omitempty"`
	Note   string   `json:"note,omitempty"`
	Fields []*Field `json:"fields,omitempty"`
}

// P2P is p2p frame v3.
type P2P struct {
	Version int      `json:"version"`
	Frames  []*Frame `json:"frames"`
	Removed []string `json:"removed"`
}

// Frame is one p2p frame op in one direction.
type Frame struct {
	Op     string   `json:"op"`
	Dir    string   `json:"dir"`
	Fields []string `json:"fields"`
	May    []string `json:"may,omitempty"`
	Note   string   `json:"note,omitempty"`
}

// Route is a control-plane route or object whose fields several areas or MCP rely on.
type Route struct {
	Route    string `json:"route"`
	Request  *Body  `json:"request,omitempty"`
	Response *Body  `json:"response,omitempty"`
	Owner    string `json:"owner"`
	Note     string `json:"note,omitempty"`
}

// MetaKey is an A2A metadata key (end-to-end in the sealed body, or on the local projection).
type MetaKey struct {
	Key       string   `json:"key"`
	Where     []string `json:"where"` // e2e, local, part, artifact, card, extension
	ValueType string   `json:"value_type"`
	Values    []string `json:"values,omitempty"`
	LocalOnly bool     `json:"local_only,omitempty"`
	Status    string   `json:"status"`
	Owner     string   `json:"owner"`
	Note      string   `json:"note,omitempty"`
}

// URI is an A2A binding or extension URI.
type URI struct {
	URI    string `json:"uri"`
	Where  string `json:"where"`
	Status string `json:"status"`
	Owner  string `json:"owner"`
	Note   string `json:"note,omitempty"`
}

// TaskCtx is a TaskDoc context key anet defines.
type TaskCtx struct {
	Key        string `json:"key"`
	Format     string `json:"format"`
	Visibility string `json:"visibility"`
	Req        string `json:"req"`
	Owner      string `json:"owner"`
	Note       string `json:"note,omitempty"`
}

// Event is an evidence event type of the local evidence chain.
type Event struct {
	Type    string   `json:"type"`
	Status  string   `json:"status"` // active, deleted
	Payload []string `json:"payload,omitempty"`
	Owner   string   `json:"owner"`
	Note    string   `json:"note,omitempty"`
}

// AELRecord is an ael record type a hub or node writes.
type AELRecord struct {
	Type         string   `json:"type"`
	VersionMajor int      `json:"version_major"`
	Payload      []string `json:"payload"`
	Status       string   `json:"status"`
	Owner        string   `json:"owner"`
}

// Reasons are the reason-code namespaces.
type Reasons struct {
	Seal        []*Reason `json:"seal"`
	Hub         []*Reason `json:"hub"`
	Note        []*Reason `json:"note"`
	C1          []*Reason `json:"c1"`
	User        []*Reason `json:"user"`
	HubOperator []*Reason `json:"hub_operator"`
	X402        []*Reason `json:"x402"`
	// Retired lists codes that were in use and must never come back, in any namespace.
	Retired []*Reason `json:"retired"`
	// Shared lists the codes that appear in more than one of hub, note and user with one meaning
	// (CORE-K18); any other cross-namespace repeat is an error.
	Shared []string `json:"shared"`
}

// Reason is one code.
type Reason struct {
	Code   string `json:"code"`
	Status int    `json:"http,omitempty"`
	Class  string `json:"class,omitempty"`
	Owner  string `json:"owner,omitempty"`
	Note   string `json:"note,omitempty"`
}

// Layout is a fixed-size binary layout (the delivery acknowledgement).
type Layout struct {
	Name  string        `json:"name"`
	Len   int           `json:"len"`
	Parts []*LayoutPart `json:"parts"`
	Owner string        `json:"owner"`
}

// LayoutPart is one span of a Layout.
type LayoutPart struct {
	Of   string `json:"of"`
	Off  int    `json:"off"`
	Len  int    `json:"len"`
	What string `json:"what"`
}

// Table is a storage table of the shared storage contract.
type Table struct {
	Where   string   `json:"where"`
	Table   string   `json:"table"`
	Columns []string `json:"columns"`
	Never   []string `json:"never,omitempty"`
	Note    string   `json:"note,omitempty"`
	Owner   string   `json:"owner"`
}

// String is any other registered string that starts with "anet" followed by '-', '.' or '/'.
type String struct {
	Value  string `json:"value"`
	Class  string `json:"class"`
	Status string `json:"status"`
	Note   string `json:"note,omitempty"`
}

// Exempt is a class of "anet…" string literals the scan does not need registered: prose, log
// lines and identifiers that are not on the wire or under a signature.
type Exempt struct {
	Class string `json:"class"`
	Match string `json:"match"` // exact, prefix, regexp
	Value string `json:"value"`
	Note  string `json:"note"`
}

// Signers lists the identity-key signing methods and every function allowed to call one.
type Signers struct {
	Methods []string  `json:"methods"`
	Calls   []*Signer `json:"calls"`
}

// Signer is one function that signs with an identity key, and what it signs.
type Signer struct {
	Repo  string `json:"repo"`
	Func  string `json:"func"`
	Signs string `json:"signs"` // a registered object, a D-class object, or a tag id (L22)
}

// ScanRules are the code conventions wire/scan relies on.
type ScanRules struct {
	Consts  []*ConstRule `json:"consts"`
	Actions *ConstRule   `json:"actions"`
	Pattern string       `json:"pattern"` // string literals the scan looks at
}

// ConstRule maps integer constants named Prefix* in package Pkg of repo Repo to the keys of Object.
type ConstRule struct {
	Repo   string `json:"repo"`
	Pkg    string `json:"pkg"`
	Prefix string `json:"prefix"`
	Object string `json:"object,omitempty"`
	// Param (actions only): a constant passed to a string parameter of this name, in any
	// repository, is a relayauth action.
	Param string `json:"param,omitempty"`
}

// NULGuard is a function that must refuse a field holding U+0000 (CORE-E9).
type NULGuard struct {
	Repo  string `json:"repo"`
	Label string `json:"label"`
	What  string `json:"what"`
}

var (
	loadOnce sync.Once
	loaded   *Registry
	loadErr  error
)

// Load returns the embedded registry, decoded and indexed. It is decoded once; callers must
// not modify it.
func Load() (*Registry, error) {
	loadOnce.Do(func() { loaded, loadErr = Parse(registryJSON) })
	return loaded, loadErr
}

// MustLoad is Load for tests and generators.
func MustLoad() *Registry {
	r, err := Load()
	if err != nil {
		panic(err)
	}
	return r
}

// RegistryJSON returns the embedded registry.json bytes.
func RegistryJSON() []byte { return bytes.Clone(registryJSON) }

// Parse decodes and indexes registry bytes. Unknown members are an error: a typo in the
// register must not silently drop a rule.
func Parse(b []byte) (*Registry, error) {
	var r Registry
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("wire: registry.json: %w", err)
	}
	if r.Format != Format {
		return nil, fmt.Errorf("wire: registry.json: format %q, want %q", r.Format, Format)
	}
	r.objects = make(map[string]*Object, len(r.Objects))
	for _, o := range r.Objects {
		if _, dup := r.objects[o.Name]; dup {
			return nil, fmt.Errorf("wire: registry.json: object %q twice", o.Name)
		}
		r.objects[o.Name] = o
		o.byNum = make(map[int]*Key)
		for _, k := range o.Keys {
			if k.N < 0 || k.Last() > 63 || k.To != 0 && k.To <= k.N {
				return nil, fmt.Errorf("wire: registry.json: %s key %d-%d: keys are listed in 0..63 (>= 64 follow the keyspace)", o.Name, k.N, k.To)
			}
			for n := k.N; n <= k.Last(); n++ {
				if _, dup := o.byNum[n]; dup {
					return nil, fmt.Errorf("wire: registry.json: %s key %d twice", o.Name, n)
				}
				o.byNum[n] = k
			}
		}
	}
	r.tags = make(map[string]*Tag)
	for _, t := range r.Tags {
		for _, v := range t.Values {
			if _, dup := r.tags[v]; dup {
				return nil, fmt.Errorf("wire: registry.json: label %q twice", v)
			}
			r.tags[v] = t
		}
	}
	r.reasonSet = map[string]map[string]*Reason{}
	for ns, list := range r.Reasons.Namespaces() {
		m := make(map[string]*Reason, len(list))
		for _, c := range list {
			if _, dup := m[c.Code]; dup {
				return nil, fmt.Errorf("wire: registry.json: reason %s/%s twice", ns, c.Code)
			}
			m[c.Code] = c
		}
		r.reasonSet[ns] = m
	}
	return &r, nil
}

// Namespaces returns the reason namespaces by name: seal, hub, note, c1, user, hub_operator,
// x402.
func (rs *Reasons) Namespaces() map[string][]*Reason {
	return map[string][]*Reason{
		"seal": rs.Seal, "hub": rs.Hub, "note": rs.Note, "c1": rs.C1,
		"user": rs.User, "hub_operator": rs.HubOperator, "x402": rs.X402,
	}
}

// Object returns the named object, or nil.
func (r *Registry) Object(name string) *Object { return r.objects[name] }

// Key returns the key entry covering number n, or nil when n is not listed. An unlisted number
// below 64 is unassigned (reserved); see KeyStatus.
func (o *Object) Key(n int) *Key { return o.byNum[n] }

// KeyStatus is the status of key number n: the listed status, or reserved for an unlisted
// number. Numbers ≥ 64 are reserved in a closed object and ignorable ("extension") in a
// critical one.
func (o *Object) KeyStatus(n int) string {
	if k := o.byNum[n]; k != nil {
		return k.Status
	}
	if n >= 64 && o.Keyspace != KeyspaceClosed {
		return "extension"
	}
	return StatusReserved
}

// ActiveKeys returns the active keys in key order.
func (o *Object) ActiveKeys() []*Key {
	var out []*Key
	for _, k := range o.Keys {
		if k.Status == StatusActive {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N < out[j].N })
	return out
}

// Tag returns the tag row holding label s, or nil.
func (r *Registry) Tag(s string) *Tag { return r.tags[s] }

// Reason returns code in namespace ns, or nil.
func (r *Registry) Reason(ns, code string) *Reason { return r.reasonSet[ns][code] }

// ReasonCodes returns the codes of namespace ns, sorted.
func (r *Registry) ReasonCodes(ns string) []string {
	var out []string
	for c := range r.reasonSet[ns] {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Action returns the relayauth action named name, or nil.
func (r *Registry) Action(name string) *Action {
	for _, a := range r.Relayauth.Actions {
		if a.Name == name {
			return a
		}
	}
	return nil
}

// MetaKey returns the metadata key named k, or nil.
func (r *Registry) MetaKey(k string) *MetaKey {
	for _, m := range r.Metadata {
		if m.Key == k {
			return m
		}
	}
	return nil
}

// Endpoint returns the hub endpoint for method and path, or nil.
func (r *Registry) Endpoint(method, path string) *Endpoint {
	for _, e := range r.HubAPI.Endpoints {
		if e.Method == method && e.Path == path {
			return e
		}
	}
	return nil
}

// ControlRoute returns the control-plane route or object named route, or nil.
func (r *Registry) ControlRoute(route string) *Route {
	for _, c := range r.Control {
		if c.Route == route {
			return c
		}
	}
	return nil
}

// StringStatus says whether s is a registered string and with what status ("" when it is not
// registered anywhere). It looks at labels, type tags, metadata keys, TaskDoc contexts, evidence
// events, ael records and the other registered strings.
func (r *Registry) StringStatus(s string) (status, where string) {
	if t := r.tags[s]; t != nil {
		return StatusActive, "label " + t.ID
	}
	for _, o := range r.Objects {
		if o.Tag == s {
			return StatusActive, "type tag of " + o.Name
		}
	}
	if m := r.MetaKey(s); m != nil {
		return m.Status, "metadata key"
	}
	for _, c := range r.Contexts {
		if c.Key == s {
			return StatusActive, "TaskDoc context"
		}
	}
	for _, e := range r.Events {
		if e.Type == s {
			return e.Status, "evidence event"
		}
	}
	for _, a := range r.AEL {
		if a.Type == s {
			return a.Status, "ael record"
		}
	}
	for _, x := range r.Strings {
		if x.Value == s {
			return x.Status, "string (" + x.Class + ")"
		}
	}
	if s == r.Relayauth.Prefix {
		return StatusActive, "relayauth prefix"
	}
	return "", ""
}

// NormName folds a field or constant name for comparison: lower case, no underscores.
// "key_state_seq", "KeyStateSeq" and "keyStateSeq" are the same name.
func NormName(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "_", "")
}

// Names returns the names a key may be spelled with in code: its name and its aliases,
// folded by NormName.
func (k *Key) Names() []string {
	var out []string
	for _, n := range append([]string{k.Name, k.Was}, k.Aliases...) {
		if n != "" {
			out = append(out, NormName(n))
		}
	}
	return out
}
