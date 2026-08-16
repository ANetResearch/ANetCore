package adp

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
)

// jcsMarshal serializes a JSON value as RFC 8785 JSON Canonicalization Scheme (JCS) bytes,
// the adp-card canonical pre-image (adp-spec §3.1). Hand-rolled minimal JCS:
//
//   - objects: keys sorted by their UTF-16 code-unit sequence (for the ASCII keys of the
//     card schema this is identical to byte-wise sort), recursively; no whitespace;
//   - arrays: element order preserved, no whitespace;
//   - strings: minimal JSON escaping, UTF-8 (no \uXXXX for representable code points);
//   - numbers: card numbers are integers, emitted as plain decimal with no exponent
//     (RFC 8785 §3.2.2.3 integer case); fractional JSON numbers are formatted with Go's
//     shortest round-trip 'g' but the card schema never produces them.
//
// The input is the generic-decoded card pre-image object (map[string]any) produced by
// preimageObject; json.Number is used so integer card fields (seq, issued_at, …) keep their
// exact integer text rather than going through float64.
func jcsMarshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := jcsWrite(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func jcsWrite(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(jcsNumber(val.String()))
	case float64:
		// json.Unmarshal into any yields float64 for numbers unless UseNumber is set.
		// Card integers (seq, issued_at, not_before, card_schema.major) MUST emit as plain
		// decimal with no exponent (RFC 8785; the spec notes card numbers are integers).
		if val == float64(int64(val)) {
			buf.WriteString(strconv.FormatInt(int64(val), 10))
		} else {
			buf.WriteString(strconv.FormatFloat(val, 'g', -1, 64))
		}
	case int64:
		buf.WriteString(strconv.FormatInt(val, 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(val, 10))
	case string:
		jcsWriteString(buf, val)
	case []any:
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := jcsWrite(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		// RFC 8785 sorts by UTF-16 code units; for the ASCII keys here a byte sort matches.
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			jcsWriteString(buf, k)
			buf.WriteByte(':')
			if err := jcsWrite(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case json.RawMessage:
		// Re-canonicalize embedded raw JSON (e.g. delegation_proof) through the generic path.
		var inner any
		dec := json.NewDecoder(bytes.NewReader(val))
		dec.UseNumber()
		if err := dec.Decode(&inner); err != nil {
			return &Error{Code: MALFORMED_CARD, Detail: "embedded JSON not decodable: " + err.Error()}
		}
		return jcsWrite(buf, inner)
	default:
		return &Error{Code: MALFORMED_CARD, Detail: "JCS: unsupported value type"}
	}
	return nil
}

// jcsNumber renders an already-textual JSON number in JCS integer form when it is integral.
// Card numbers are integers (adp-spec §3.1 note), so the integer branch is the live path.
func jcsNumber(s string) string {
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return strconv.FormatInt(i, 10)
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		if f == float64(int64(f)) {
			return strconv.FormatInt(int64(f), 10)
		}
		return strconv.FormatFloat(f, 'g', -1, 64)
	}
	return s
}

// The 6-ASCII-char JSON escapes Go's encoding/json emits for U+2028 / U+2029 even with
// SetEscapeHTML(false): backslash 'u' '2' '0' '2' '8' (and ...'9'). They are built as
// explicit byte slices so the literal ESCAPE (not the code point) is matched; RFC 8785
// (§3.2.2.2) instead emits these two code points as raw UTF-8 (only the C0 control set
// plus " and \ are escaped). The raw forms are the canonical 3-byte UTF-8 encodings.
var (
	escLineSep = []byte{0x5C, 'u', '2', '0', '2', '8'} //
	escParaSep = []byte{0x5C, 'u', '2', '0', '2', '9'} //
	escPrefix  = []byte{0x5C, 'u', '2', '0', '2'}      // \u202 cheap pre-filter
	rawLineSep = []byte{0xE2, 0x80, 0xA8}              // U+2028 LINE SEPARATOR, raw UTF-8
	rawParaSep = []byte{0xE2, 0x80, 0xA9}              // U+2029 PARAGRAPH SEPARATOR, raw UTF-8
)

// jcsWriteString writes a JSON string with RFC 8785 minimal escaping. Go's json.Marshal
// produces RFC 8785-compatible escaping for strings (it escapes only the mandatory control
// chars, ", and \, and emits UTF-8 for the rest) EXCEPT (a) it escapes <, >, & by default
// for HTML safety, and (b) it escapes the JS line terminators U+2028/U+2029 even with
// SetEscapeHTML(false). RFC 8785 escapes ONLY the C0 control set plus " and \; every other
// code point — including U+2028/U+2029 — is emitted as raw UTF-8. So we disable HTML
// escaping AND post-process the two JS-line-terminator escapes back to their raw 3-byte
// UTF-8 forms, matching RFC 8785's mandatory-escape set exactly.
func jcsWriteString(buf *bytes.Buffer, s string) {
	var sb bytes.Buffer
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	// Encode writes the quoted string plus a trailing newline; trim the newline.
	_ = enc.Encode(s)
	b := sb.Bytes()
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	// Unescape the two JS line terminators back to raw UTF-8 (RFC 8785 emits them raw).
	if bytes.Contains(b, escPrefix) {
		b = bytes.ReplaceAll(b, escLineSep, rawLineSep)
		b = bytes.ReplaceAll(b, escParaSep, rawParaSep)
	}
	buf.Write(b)
}
