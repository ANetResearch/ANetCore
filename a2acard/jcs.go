package a2acard

import (
	"bytes"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonicalize returns the RFC 8785 (JCS) canonical form of one JSON value.
//
// The input must be I-JSON (RFC 7493), which RFC 8785 §3.1 requires: valid UTF-8, no
// duplicate member names, no lone surrogates or noncharacters, and numbers within binary64
// range. Anything else is rejected rather than repaired. encoding/json repairs silently (it
// substitutes U+FFFD and keeps the last duplicate), so two different byte strings would
// canonicalize to the same payload and a signature over one would appear to cover the other.
//
// Output rules (RFC 8785 §3.2): no whitespace; object members sorted by the UTF-16 code units
// of their names; array order preserved; strings escaped with the JSON.stringify rules (only
// '"', '\\' and U+0000..U+001F are escaped, U+2028/U+2029 and '/' are literal); numbers parsed
// to IEEE 754 binary64 and printed with ECMAScript Number::toString.
//
// Nesting deeper than 128 arrays/objects is rejected as an implementation limit; it bounds
// recursion on hostile input and is far above what an AgentCard uses.
func Canonicalize(jsonBytes []byte) ([]byte, error) {
	v, err := parseJSON(jsonBytes)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v, ""); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// maxDepth is the nesting limit described on Canonicalize.
const maxDepth = 128

type kind uint8

const (
	kindNull kind = iota
	kindBool
	kindNumber
	kindString
	kindArray
	kindObject
)

// value is a parsed JSON value. Numbers are held as binary64 because RFC 8785 serializes the
// binary64 value, not the input token: 9007199254740993 and 9007199254740992 are the same
// number after parsing and have the same canonical form.
type value struct {
	kind kind
	b    bool
	num  float64
	str  string
	arr  []*value
	obj  map[string]*value
}

func (v *value) member(name string) (*value, bool) {
	if v == nil || v.kind != kindObject {
		return nil, false
	}
	m, ok := v.obj[name]
	return m, ok
}

type parser struct {
	data  []byte
	pos   int
	depth int
}

func parseJSON(data []byte) (*value, error) {
	p := &parser{data: data}
	p.skipWS()
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.data) {
		return nil, p.fail("data after the JSON value")
	}
	return v, nil
}

func (p *parser) fail(msg string) *Error {
	return newErr(CodeMalformedJSON, fmt.Sprintf("%s at byte %d", msg, p.pos))
}

func (p *parser) skipWS() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) value() (*value, error) {
	if p.pos >= len(p.data) {
		return nil, p.fail("unexpected end of input")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"':
		s, err := p.string()
		if err != nil {
			return nil, err
		}
		return &value{kind: kindString, str: s}, nil
	case c == 't':
		return p.literal("true", &value{kind: kindBool, b: true})
	case c == 'f':
		return p.literal("false", &value{kind: kindBool})
	case c == 'n':
		return p.literal("null", &value{kind: kindNull})
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, p.fail("invalid character")
	}
}

func (p *parser) literal(word string, v *value) (*value, error) {
	if !bytes.HasPrefix(p.data[p.pos:], []byte(word)) {
		return nil, p.fail("invalid literal")
	}
	p.pos += len(word)
	return v, nil
}

func (p *parser) enter() error {
	p.depth++
	if p.depth > maxDepth {
		return p.fail("nesting deeper than 128")
	}
	return nil
}

func (p *parser) object() (*value, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	p.pos++ // '{'
	v := &value{kind: kindObject, obj: map[string]*value{}}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		p.depth--
		return v, nil
	}
	for {
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, p.fail("expected member name")
		}
		keyPos := p.pos
		k, err := p.string()
		if err != nil {
			return nil, err
		}
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, p.fail("expected ':'")
		}
		p.pos++
		p.skipWS()
		m, err := p.value()
		if err != nil {
			return nil, err
		}
		if _, dup := v.obj[k]; dup {
			// I-JSON §2.3: names MUST be unique. Parsers disagree on which duplicate wins, so a
			// verifier and a consumer could read different values under one signature.
			return nil, newErr(CodeMalformedJSON, fmt.Sprintf("duplicate member name %q at byte %d", k, keyPos))
		}
		v.obj[k] = m
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, p.fail("unterminated object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
			p.skipWS()
		case '}':
			p.pos++
			p.depth--
			return v, nil
		default:
			return nil, p.fail("expected ',' or '}'")
		}
	}
}

func (p *parser) array() (*value, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	p.pos++ // '['
	v := &value{kind: kindArray, arr: []*value{}}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		p.depth--
		return v, nil
	}
	for {
		e, err := p.value()
		if err != nil {
			return nil, err
		}
		v.arr = append(v.arr, e)
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, p.fail("unterminated array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
			p.skipWS()
		case ']':
			p.pos++
			p.depth--
			return v, nil
		default:
			return nil, p.fail("expected ',' or ']'")
		}
	}
}

// number validates the RFC 8259 number grammar and converts the token to binary64.
func (p *parser) number() (*value, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	switch {
	case p.pos < len(p.data) && p.data[p.pos] == '0':
		p.pos++
	case p.pos < len(p.data) && p.data[p.pos] >= '1' && p.data[p.pos] <= '9':
		p.digits()
	default:
		return nil, p.fail("invalid number")
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if p.digits() == 0 {
			return nil, p.fail("invalid number fraction")
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if p.digits() == 0 {
			return nil, p.fail("invalid number exponent")
		}
	}
	f, err := strconv.ParseFloat(string(p.data[start:p.pos]), 64)
	if err != nil {
		// Only overflow reaches here (the grammar is already checked). ParseFloat returns ±Inf,
		// which has no JSON form; RFC 8785 §3.2.2.3 requires an error.
		return nil, newErr(CodeMalformedJSON, fmt.Sprintf("number outside binary64 range at byte %d", start))
	}
	return &value{kind: kindNumber, num: f}, nil
}

func (p *parser) digits() int {
	n := 0
	for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
		p.pos++
		n++
	}
	return n
}

// string decodes a JSON string starting at the opening quote.
func (p *parser) string() (string, error) {
	p.pos++ // '"'
	var sb strings.Builder
	for {
		if p.pos >= len(p.data) {
			return "", p.fail("unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return sb.String(), nil
		case c == '\\':
			r, err := p.escape()
			if err != nil {
				return "", err
			}
			sb.WriteRune(r)
		case c < 0x20:
			return "", p.fail("unescaped control character in string")
		case c < utf8.RuneSelf:
			sb.WriteByte(c)
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size == 1 {
				// Also covers UTF-8-encoded surrogates (ED A0..BF xx), which DecodeRune rejects.
				return "", p.fail("invalid UTF-8")
			}
			if isNoncharacter(r) {
				return "", p.fail("noncharacter in string")
			}
			sb.Write(p.data[p.pos : p.pos+size])
			p.pos += size
		}
	}
}

// escape decodes one backslash escape; p.pos is at the backslash.
func (p *parser) escape() (rune, error) {
	p.pos++
	if p.pos >= len(p.data) {
		return 0, p.fail("unterminated escape")
	}
	c := p.data[p.pos]
	p.pos++
	switch c {
	case '"', '\\', '/':
		return rune(c), nil
	case 'b':
		return '\b', nil
	case 'f':
		return '\f', nil
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case 'u':
	default:
		p.pos--
		return 0, p.fail("invalid escape")
	}
	r1, ok := p.hex4()
	if !ok {
		return 0, p.fail("invalid \\u escape")
	}
	var r rune
	switch {
	case utf16.IsSurrogate(r1) && r1 < 0xDC00:
		// A high surrogate must be followed by an escaped low surrogate.
		if p.pos+1 >= len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
			return 0, p.fail("lone high surrogate")
		}
		p.pos += 2
		r2, ok := p.hex4()
		if !ok || r2 < 0xDC00 || r2 > 0xDFFF {
			return 0, p.fail("lone high surrogate")
		}
		r = utf16.DecodeRune(r1, r2)
	case utf16.IsSurrogate(r1):
		return 0, p.fail("lone low surrogate")
	default:
		r = r1
	}
	if isNoncharacter(r) {
		return 0, p.fail("noncharacter in string")
	}
	return r, nil
}

func (p *parser) hex4() (rune, bool) {
	if p.pos+4 > len(p.data) {
		return 0, false
	}
	var r rune
	for _, c := range p.data[p.pos : p.pos+4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	p.pos += 4
	return r, true
}

// isNoncharacter reports the 66 Unicode noncharacters, which I-JSON (RFC 7493 §2.1) excludes.
func isNoncharacter(r rune) bool {
	return (r >= 0xFDD0 && r <= 0xFDEF) || r&0xFFFE == 0xFFFE
}

// writeCanonical writes v in RFC 8785 form. When skipTop is non-empty and v is an object, the
// member of that name is omitted at this level only; Sign and Verify use it to drop the
// top-level "signatures" member (A2A §8.4.1 rule 3) without copying the tree.
func writeCanonical(buf *bytes.Buffer, v *value, skipTop string) error {
	switch v.kind {
	case kindNull:
		buf.WriteString("null")
	case kindBool:
		if v.b {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case kindNumber:
		s, err := formatNumber(v.num)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case kindString:
		writeString(buf, v.str)
	case kindArray:
		buf.WriteByte('[')
		for i, e := range v.arr {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e, ""); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case kindObject:
		buf.WriteByte('{')
		first := true
		for _, k := range sortedNames(v.obj) {
			if skipTop != "" && k == skipTop {
				continue
			}
			if !first {
				buf.WriteByte(',')
			}
			first = false
			writeString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, v.obj[k], ""); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return newErr(CodeMalformedJSON, "unknown value kind")
	}
	return nil
}

// sortedNames orders member names by their UTF-16 code units (RFC 8785 §3.2.3). This differs
// from byte (code point) order only when a name contains a character above U+FFFF: such a
// character is a surrogate pair D800..DBFF, which sorts below U+E000..U+FFFF.
func sortedNames(obj map[string]*value) []string {
	type named struct {
		name  string
		units []uint16
	}
	ns := make([]named, 0, len(obj))
	for k := range obj {
		ns = append(ns, named{k, utf16.Encode([]rune(k))})
	}
	slices.SortFunc(ns, func(a, b named) int { return slices.Compare(a.units, b.units) })
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = n.name
	}
	return out
}

// writeString escapes per RFC 8785 §3.2.2.2 (ECMAScript JSON.stringify): the two-character
// escapes for \b \t \n \f \r " \, \u00xx with lowercase hex for the other C0 controls, and
// every other character as literal UTF-8. The input is valid UTF-8 (it came from parseJSON or
// from this package), so it is copied byte for byte.
func writeString(buf *bytes.Buffer, s string) {
	const hexDigits = "0123456789abcdef"
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if c < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigits[c>>4])
				buf.WriteByte(hexDigits[c&0xF])
			} else {
				buf.WriteByte(c)
			}
		}
	}
	buf.WriteByte('"')
}

// formatNumber implements ECMAScript Number::toString for a finite binary64 (RFC 8785
// §3.2.2.3, ECMA-262 Number::toString steps 1-10).
//
// strconv's shortest formatting supplies the digits: FormatFloat(f, 'e', -1, 64) yields the
// fewest decimal digits that parse back to f, choosing the closest candidate when several have
// that length, which is the digit selection ECMA-262 specifies. Only the layout differs from
// Go's 'g' format: decimal notation for 1e-6 <= |f| < 1e21, exponent notation otherwise, an
// explicit '+' and no leading zeros in the exponent, and -0 printed as 0.
func formatNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", newErr(CodeMalformedJSON, "NaN or Infinity has no JSON form")
	}
	if f == 0 {
		return "0", nil
	}
	neg := f < 0
	if neg {
		f = -f
	}
	mant, exp, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	digits := strings.Replace(mant, ".", "", 1)
	// For a finite f the 'e' format always ends in a signed decimal exponent, so Atoi cannot
	// fail here; NaN and Inf, which have no exponent, are excluded above.
	e, _ := strconv.Atoi(exp)
	// ECMA-262 names: the value is 0.d1d2...dk × 10^n, i.e. digits × 10^(n-k).
	k, n := len(digits), e+1
	var s string
	switch {
	case k <= n && n <= 21:
		s = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		s = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		s = "0." + strings.Repeat("0", -n) + digits
	default:
		sign := "+"
		if n-1 < 0 {
			sign = "-"
		}
		abs := n - 1
		if abs < 0 {
			abs = -abs
		}
		if k == 1 {
			s = digits + "e" + sign + strconv.Itoa(abs)
		} else {
			s = digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(abs)
		}
	}
	if neg {
		s = "-" + s
	}
	return s, nil
}
