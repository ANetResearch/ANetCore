// Package agenturi implements the agent:// URI scheme: parse, canonicalize, equals.
//
// Normative source: design3/spec/agent-uri-spec.md (pairs with draft agent-uri-03).
// The canonical form is a UTF-8, NFC, lowercase-folded, minimally-percent-encoded,
// query-sorted octet string — the only form that may be signed, content-addressed,
// resolved, relayed, or compared. One algorithm (S1–S7) is applied by every party.
//
// Coverage note: the ASCII / single-percent-decode / NFC / §3.2-enumerated-deviation
// (ß→ss, ς→σ, ZWJ/ZWNJ→removed) FOLD cases and the structural/lattice REJECT cases are
// implemented to the frozen critical-path golden vectors. Generic per-code-point UTS-46
// mapping (e.g. fullwidth, marked value:conformance-kit in the spec) and the full UTS-39
// confusable-skeleton table are a follow-up keyed to Unicode 16.0.0 (§3.4); MIXED_SCRIPT
// and DISALLOWED_CODEPOINT have a baseline implementation here (§6.6 is behavioral).
package agenturi

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Form is the parsed URI form.
type Form int

const (
	Concrete Form = iota
	CapabilityQuery
)

// QPair is a decoded, NFC-normalized (never folded) query pair.
type QPair struct{ Key, Value string }

// ParseValue is the structured parse result (agent-uri-spec §2.2). All label fields
// hold decoded, folded, NFC code points; query pairs are decoded + NFC, not folded.
type ParseValue struct {
	Form       Form
	Org        string // Concrete only (position 1)
	NS         string // position 2
	Svc        string // position 3
	Inst       string // position 4
	Capability string // CapabilityQuery only
	Query      []QPair
	hasNS      bool
	hasSvc     bool
	hasInst    bool
}

// Error is a typed parse error (agent-uri-spec §2.3): SCREAMING_CASE local labels.
type Error struct {
	Reason string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Reason
	}
	return e.Reason + ": " + e.Detail
}

func errf(reason, format string, a ...any) *Error {
	return &Error{Reason: reason, Detail: fmt.Sprintf(format, a...)}
}

// ---- character classes (agent-uri-spec §4.3) ----

func isUnreserved(r rune) bool {
	if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
		return true
	}
	switch r {
	case '-', '.', '_', '~':
		return true
	}
	return false
}

// isUcschar reports RFC 3987 §2.2 ucschar membership (literal non-ASCII).
func isUcschar(r rune) bool {
	switch {
	case r >= 0x00A0 && r <= 0xD7FF,
		r >= 0xF900 && r <= 0xFDCF,
		r >= 0xFDF0 && r <= 0xFFEF,
		r >= 0x10000 && r <= 0x1FFFD,
		r >= 0x20000 && r <= 0x2FFFD,
		r >= 0x30000 && r <= 0x3FFFD,
		r >= 0x40000 && r <= 0x4FFFD,
		r >= 0x50000 && r <= 0x5FFFD,
		r >= 0x60000 && r <= 0x6FFFD,
		r >= 0x70000 && r <= 0x7FFFD,
		r >= 0x80000 && r <= 0x8FFFD,
		r >= 0x90000 && r <= 0x9FFFD,
		r >= 0xA0000 && r <= 0xAFFFD,
		r >= 0xB0000 && r <= 0xBFFFD,
		r >= 0xC0000 && r <= 0xCFFFD,
		r >= 0xD0000 && r <= 0xDFFFD,
		r >= 0xE1000 && r <= 0xEFFFD:
		return true
	}
	return false
}

// literalAllowed reports whether a literal (non-percent, non-structural) octet/rune is
// allowed in a label/capability/query position pre-decode: unreserved or ucschar.
func literalAllowed(r rune) bool { return isUnreserved(r) || isUcschar(r) }

// ---- S1 percent-decode (exactly once) ----

func hexVal(b byte) (int, bool) {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0'), true
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10, true
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10, true
	}
	return 0, false
}

// decodeComponent validates the literal alphabet (pre-decode) then percent-decodes once.
// isQuery selects the qchar alphabet (identical members; '*' still illegal in both).
func decodeComponent(s string) (string, *Error) {
	if s == "" {
		return "", errf("EMPTY_LABEL", "empty component")
	}
	var out []byte
	for i := 0; i < len(s); {
		c := s[i]
		if c == '%' {
			if i+2 >= len(s) {
				return "", errf("BAD_PCT_ENCODING", "truncated escape at %d", i)
			}
			hi, ok1 := hexVal(s[i+1])
			lo, ok2 := hexVal(s[i+2])
			if !ok1 || !ok2 {
				return "", errf("BAD_PCT_ENCODING", "non-hex escape %q", s[i:i+3])
			}
			out = append(out, byte(hi<<4|lo))
			i += 3
			continue
		}
		// literal octet: must be ASCII unreserved, or start of a UTF-8 ucschar rune.
		if c < 0x80 {
			r := rune(c)
			if r == '*' {
				return "", errf("WILDCARD_IN_LABEL", "literal * in label")
			}
			if !isUnreserved(r) {
				return "", errf("ILLEGAL_CHAR", "octet %q not name-char", string(r))
			}
			out = append(out, c)
			i++
			continue
		}
		// non-ASCII: decode one UTF-8 rune, check ucschar.
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return "", errf("BAD_UTF8", "invalid utf-8 at %d", i)
		}
		if !isUcschar(r) {
			return "", errf("ILLEGAL_CHAR", "rune %q not name-char", string(r))
		}
		out = append(out, s[i:i+size]...)
		i += size
	}
	if !utf8.Valid(out) {
		return "", errf("BAD_UTF8", "decoded bytes not valid utf-8")
	}
	return string(out), nil
}

// decodeQ decodes a query key/value: same alphabet as labels except '*' is permitted
// literally (queries are not labels) and structural '&'/'='/'/' are handled by the caller.
func decodeQ(s string) (string, *Error) {
	var out []byte
	for i := 0; i < len(s); {
		c := s[i]
		if c == '%' {
			if i+2 >= len(s) {
				return "", errf("BAD_PCT_ENCODING", "truncated escape")
			}
			hi, ok1 := hexVal(s[i+1])
			lo, ok2 := hexVal(s[i+2])
			if !ok1 || !ok2 {
				return "", errf("BAD_PCT_ENCODING", "non-hex escape")
			}
			out = append(out, byte(hi<<4|lo))
			i += 3
			continue
		}
		if c < 0x80 {
			r := rune(c)
			if !isUnreserved(r) {
				return "", errf("ILLEGAL_CHAR", "octet %q not qchar", string(r))
			}
			out = append(out, c)
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return "", errf("BAD_UTF8", "invalid utf-8 in query")
		}
		if !isUcschar(r) {
			return "", errf("ILLEGAL_CHAR", "rune %q not qchar", string(r))
		}
		out = append(out, s[i:i+size]...)
		i += size
	}
	return string(out), nil
}

// ---- S3 FOLD ----

// foldLabel applies S3 to a decoded label: UTS-46 deviation folds enumerated in §3.2 +
// ASCII lowercase, then NFC. Generic UTS-46 mapping (non-enumerated) is a follow-up.
func foldLabel(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case 0x200C, 0x200D: // ZWNJ, ZWJ — deviation folded to nothing (§3.2)
			continue
		case 0x00DF: // ß → ss (deviation)
			b.WriteString("ss")
			continue
		case 0x03C2: // ς → σ (deviation)
			b.WriteRune(0x03C3)
			continue
		}
		if r >= 'A' && r <= 'Z' { // ASCII case fold (subsumed by UTS-46 map)
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return norm.NFC.String(b.String()) // (b) Unicode NFC after mapping
}

// ---- S6 REJECT (baseline; §6.6 behavioral) ----

// rejectCheck applies the parse-computable REJECT classes (agent-uri-spec §3.3).
// Baseline: DISALLOWED_CODEPOINT (control/separator/format) and MIXED_SCRIPT
// (Latin mixed with Cyrillic or Greek). CONFUSABLE_SKELETON (corpus + whole-script
// table) is a follow-up keyed to UTS-39 confusables.txt.
func rejectCheck(label string) *Error {
	for _, r := range label {
		if r == 0x200C || r == 0x200D {
			continue // folded away at S3; never reaches here
		}
		// UTS-46 disallowed baseline: control (Cc), format (Cf), line/paragraph
		// separators (Zl/Zp). NOT Zs — an ASCII space etc. decoded as data is legal
		// and re-encoded (AU-C-11). Full UTS-46 disallowed table is a follow-up (§3.4).
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) ||
			unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return errf("DISALLOWED_CODEPOINT", "U+%04X", r)
		}
	}
	var latin, cyrillic, greek bool
	for _, r := range label {
		switch {
		case unicode.Is(unicode.Latin, r):
			latin = true
		case unicode.Is(unicode.Cyrillic, r):
			cyrillic = true
		case unicode.Is(unicode.Greek, r):
			greek = true
		}
	}
	if latin && (cyrillic || greek) {
		return errf("MIXED_SCRIPT", "Latin mixed with Cyrillic/Greek")
	}
	return nil
}

// ---- marker handling (S2) ----

type marker struct {
	prefix string
	pos    int // 2,3,4
}

var markers = []marker{{"ns=", 2}, {"svc=", 3}, {"inst=", 4}}

// matchMarker matches a literal ASCII-case-insensitive marker prefix, returns (pos, rest).
func matchMarker(seg string) (int, string, bool) {
	for _, m := range markers {
		if len(seg) >= len(m.prefix) && strings.EqualFold(seg[:len(m.prefix)], m.prefix) {
			return m.pos, seg[len(m.prefix):], true
		}
	}
	return 0, "", false
}

// Parse runs S1–S6 (agent-uri-spec §5.1), returning a ParseValue or a typed *Error.
func Parse(s string) (*ParseValue, error) {
	if !utf8.ValidString(s) {
		return nil, errf("BAD_UTF8", "input not valid utf-8")
	}
	// scheme match (ASCII-case-insensitive) on "<scheme>://"
	idx := strings.Index(s, "://")
	if idx < 0 {
		return nil, errf("SCHEME_MISMATCH", "no scheme separator")
	}
	if !strings.EqualFold(s[:idx], "agent") {
		return nil, errf("SCHEME_MISMATCH", "scheme %q", s[:idx])
	}
	rest := s[idx+3:]
	if strings.Contains(rest, "#") {
		return nil, errf("FRAGMENT_PRESENT", "# present")
	}
	path := rest
	var qs string
	hasQ := false
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		path = rest[:i]
		qs = rest[i+1:]
		hasQ = true
	}
	segs := strings.Split(path, "/")

	v := &ParseValue{}
	if segs[0] == "*" {
		// capability-query form
		if len(segs) != 2 {
			return nil, errf("WILDCARD_FORM", "wildcard requires exactly one capability segment")
		}
		cap, e := decodeComponent(segs[1])
		if e != nil {
			return nil, e
		}
		v.Form = CapabilityQuery
		v.Capability = foldLabel(cap)
		if e := rejectCheck(v.Capability); e != nil {
			return nil, e
		}
	} else {
		if segs[0] == "" {
			return nil, errf("EMPTY_AUTHORITY", "nothing after agent://")
		}
		if strings.Contains(segs[0], "*") {
			return nil, errf("WILDCARD_IN_LABEL", "* in authority label")
		}
		org, e := decodeComponent(segs[0])
		if e != nil {
			return nil, e
		}
		v.Form = Concrete
		v.Org = foldLabel(org)
		if e := rejectCheck(v.Org); e != nil {
			return nil, e
		}
		// An empty non-authority segment ("" from a trailing or double slash) is an empty
		// label, never an unmarked segment (agent-uri-spec §6.2 AU-L-07). Scanned before the
		// marker loop so the empty label is reported regardless of its position.
		for _, seg := range segs[1:] {
			if seg == "" {
				return nil, errf("EMPTY_LABEL", "empty path segment")
			}
		}
		pos := 1
		for _, seg := range segs[1:] {
			mpos, restseg, ok := matchMarker(seg)
			if !ok {
				if strings.Contains(seg, "*") {
					return nil, errf("WILDCARD_IN_LABEL", "* outside capability-query authority")
				}
				return nil, errf("UNMARKED_SEGMENT", "segment %q has no marker", seg)
			}
			if mpos <= pos {
				if assigned(v, mpos) {
					return nil, errf("DUPLICATE_MARKER", "position %d twice", mpos)
				}
				return nil, errf("POSITION_ORDER", "marker position %d after %d", mpos, pos)
			}
			if assigned(v, mpos) {
				return nil, errf("DUPLICATE_MARKER", "position %d twice", mpos)
			}
			lbl, e := decodeComponent(restseg)
			if e != nil {
				return nil, e
			}
			folded := foldLabel(lbl)
			if e := rejectCheck(folded); e != nil {
				return nil, e
			}
			setPos(v, mpos, folded)
			pos = mpos
		}
	}

	if hasQ {
		pairs, e := parseQuery(qs)
		if e != nil {
			return nil, e
		}
		v.Query = pairs
	}
	return v, nil
}

func assigned(v *ParseValue, pos int) bool {
	switch pos {
	case 2:
		return v.hasNS
	case 3:
		return v.hasSvc
	case 4:
		return v.hasInst
	}
	return false
}

func setPos(v *ParseValue, pos int, val string) {
	switch pos {
	case 2:
		v.NS, v.hasNS = val, true
	case 3:
		v.Svc, v.hasSvc = val, true
	case 4:
		v.Inst, v.hasInst = val, true
	}
}

// parseQuery splits on '&', keys on first '=', decodes + NFC (no fold) per SD-4.
func parseQuery(qs string) ([]QPair, *Error) {
	if qs == "" {
		return nil, errf("QUERY_SYNTAX", "empty query")
	}
	var out []QPair
	for _, pair := range strings.Split(qs, "&") {
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			return nil, errf("QUERY_SYNTAX", "pair %q has no =", pair)
		}
		k, val := pair[:eq], pair[eq+1:]
		if k == "" {
			return nil, errf("QUERY_SYNTAX", "empty key")
		}
		dk, e := decodeQ(k)
		if e != nil {
			return nil, e
		}
		dv, e := decodeQ(val)
		if e != nil {
			return nil, e
		}
		out = append(out, QPair{Key: norm.NFC.String(dk), Value: norm.NFC.String(dv)})
	}
	return out, nil
}

// ---- S4 / S5 / S7 serialize ----

func encLabel(s string) string {
	var b strings.Builder
	for _, r := range s {
		if isUnreserved(r) || isUcschar(r) {
			b.WriteRune(r)
			continue
		}
		for _, by := range []byte(string(r)) {
			fmt.Fprintf(&b, "%%%02X", by)
		}
	}
	return b.String()
}

// Serialize emits the canonical octet string (S4/S5/S7) from a ParseValue.
func Serialize(v *ParseValue) string {
	var b strings.Builder
	b.WriteString("agent://")
	if v.Form == CapabilityQuery {
		b.WriteString("*/")
		b.WriteString(encLabel(v.Capability))
	} else {
		b.WriteString(encLabel(v.Org))
		if v.hasNS {
			b.WriteString("/ns=")
			b.WriteString(encLabel(v.NS))
		}
		if v.hasSvc {
			b.WriteString("/svc=")
			b.WriteString(encLabel(v.Svc))
		}
		if v.hasInst {
			b.WriteString("/inst=")
			b.WriteString(encLabel(v.Inst))
		}
	}
	if len(v.Query) > 0 {
		enc := make([]string, len(v.Query))
		for i, p := range v.Query {
			enc[i] = encLabel(p.Key) + "=" + encLabel(p.Value)
		}
		sort.Strings(enc) // bytewise on encoded (key=value); duplicates preserved
		b.WriteString("?")
		b.WriteString(strings.Join(enc, "&"))
	}
	return b.String()
}

// Canonical returns canonical(s) = serialize(parse(s)) (agent-uri-spec §5.2).
func Canonical(s string) (string, error) {
	v, err := Parse(s)
	if err != nil {
		return "", err
	}
	return Serialize(v), nil
}

// Equals reports byte-identical canonical equality (agent-uri-spec §5.3, SD-12).
func Equals(a, b string) (bool, error) {
	ca, err := Canonical(a)
	if err != nil {
		return false, err
	}
	cb, err := Canonical(b)
	if err != nil {
		return false, err
	}
	return ca == cb, nil
}

// ValidateCapabilityQuery returns the canonical query identity, or WRONG_FORM (§5.4).
func ValidateCapabilityQuery(s string) (string, error) {
	v, err := Parse(s)
	if err != nil {
		return "", err
	}
	if v.Form != CapabilityQuery {
		return "", errf("WRONG_FORM", "not a capability query")
	}
	return Serialize(v), nil
}

// RequireConcreteLocator returns the canonical concrete locator, or WRONG_FORM (§5.4) —
// a wildcard form MUST NOT enter datagram Source/Dest.
func RequireConcreteLocator(s string) (string, error) {
	v, err := Parse(s)
	if err != nil {
		return "", err
	}
	if v.Form != Concrete {
		return "", errf("WRONG_FORM", "not a concrete locator")
	}
	return Serialize(v), nil
}
