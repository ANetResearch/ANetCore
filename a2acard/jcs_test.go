package a2acard

import (
	"math"
	"strings"
	"testing"
)

// RFC 8785 Appendix B: IEEE 754 bit patterns and their required serialization. The two NaN and
// Infinity rows of the appendix have no JSON form and are covered by TestFormatNumberRejectsNaNInf.
// The digit strings were also checked against Python's float repr, an independent
// shortest-round-trip implementation.
var rfc8785AppendixB = []struct {
	bits uint64
	want string
}{
	{0x0000000000000000, "0"},
	{0x8000000000000000, "0"}, // minus zero
	{0x0000000000000001, "5e-324"},
	{0x8000000000000001, "-5e-324"},
	{0x7fefffffffffffff, "1.7976931348623157e+308"},
	{0xffefffffffffffff, "-1.7976931348623157e+308"},
	{0x4340000000000000, "9007199254740992"},
	{0xc340000000000000, "-9007199254740992"},
	{0x4430000000000000, "295147905179352830000"},
	{0x44b52d02c7e14af5, "9.999999999999997e+22"},
	{0x44b52d02c7e14af6, "1e+23"},
	{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
	{0x444b1ae4d6e2ef4e, "999999999999999700000"},
	{0x444b1ae4d6e2ef4f, "999999999999999900000"},
	{0x444b1ae4d6e2ef50, "1e+21"},
	{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
	{0x3eb0c6f7a0b5ed8d, "0.000001"},
	{0x41b3de4355555553, "333333333.3333332"},
	{0x41b3de4355555554, "333333333.33333325"},
	{0x41b3de4355555555, "333333333.3333333"},
	{0x41b3de4355555556, "333333333.3333334"},
	{0x41b3de4355555557, "333333333.33333343"},
	{0xbecbf647612f3696, "-0.0000033333333333333333"},
	{0x43143ff3c1cb0959, "1424953923781206.2"}, // round to even
}

func TestNumberSerializationRFC8785AppendixB(t *testing.T) {
	for _, tc := range rfc8785AppendixB {
		got, err := formatNumber(math.Float64frombits(tc.bits))
		if err != nil {
			t.Errorf("%016x: %v", tc.bits, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%016x: got %s, want %s", tc.bits, got, tc.want)
		}
	}
}

func TestFormatNumberRejectsNaNInf(t *testing.T) {
	for _, f := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if s, err := formatNumber(f); err == nil {
			t.Errorf("formatNumber(%v) = %q, want an error", f, s)
		}
	}
}

// Numbers given as JSON text. The first group are the boundary cases of ECMAScript
// Number::toString; the second are integer vectors from a2a-go's a2acrypto tests
// (Apache-2.0, github.com/a2aproject/a2a-go/v2 a2acrypto/sign_test.go), which check that
// an integer token is serialized from its binary64 value rather than copied.
func TestNumberTokens(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1e21", "1e+21"},
		{"1E21", "1e+21"},
		{"999999999999999900000", "999999999999999900000"},
		{"1e-7", "1e-7"},
		{"0.000001", "0.000001"},
		{"0.0000010", "0.000001"},
		{"123456789012345680000", "123456789012345680000"},
		{"4.35", "4.35"},
		{"4.50", "4.5"},
		{"-0", "0"},
		{"-0.0e5", "0"},
		{"1E30", "1e+30"},
		{"2e-3", "0.002"},
		{"0.000000000000000000000000001", "1e-27"},
		{"333333333.33333329", "333333333.3333333"},
		{"1e-400", "0"}, // underflows to zero, as in ECMAScript
		{"100", "100"},
		{"1.5e+2", "150"},
		{"-1.5e-7", "-1.5e-7"},
		{"1e-5", "0.00001"},
		{"0.1", "0.1"},
		// a2a-go vectors
		{"12345", "12345"},
		{"-42", "-42"},
		{"9007199254740992", "9007199254740992"},
		{"9007199254740993", "9007199254740992"},
		{"9007199254740994", "9007199254740994"},
		{"1152921504606846976", "1152921504606847000"},
		{"295147905179352825856", "295147905179352830000"},
	}
	for _, tc := range cases {
		got, err := Canonicalize([]byte(tc.in))
		if err != nil {
			t.Errorf("Canonicalize(%s): %v", tc.in, err)
			continue
		}
		if string(got) != tc.want {
			t.Errorf("Canonicalize(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// j converts test JSON written with ~ for the JSON backslash into real JSON. Writing JSON
// escapes as ~u20ac keeps them distinct from Go escapes when reading the source: every
// escape sequence in these inputs is decoded by the parser under test, not by the Go compiler.
func j(s string) []byte { return []byte(strings.ReplaceAll(s, "~", "\x5c")) }

// RFC 8785 §3.2.2 example: whitespace removal, number and string serialization, member order.
// The expected output is the RFC's, byte for byte.
func TestRFC8785Example(t *testing.T) {
	in := j(`{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "~u20ac$~u000F~u000aA'~u0042~u0022~u005c~~~"~/",
  "literals": [null, true, false]
}`)
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],` +
		"\"string\":\"\U000020AC$" + string(j(`~u000f~nA'B~"~~~~~"/"}`))
	got, err := Canonicalize(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// RFC 8785 §3.2.3 example. Member names are ordered by UTF-16 code units: U+1F600 is the
// surrogate pair D83D DE00 and sorts before U+FB33, the reverse of code point (and UTF-8
// byte) order.
func TestRFC8785SortingNonBMP(t *testing.T) {
	in := j(`{
  "~u20ac": "Euro Sign",
  "~r": "Carriage Return",
  "~ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "~ud83d~ude00": "Emoji: Grinning Face",
  "~u0080": "Control",
  "~u00f6": "Latin Small Letter O With Diaeresis"
}`)
	want := string(j(`{"~r":"Carriage Return","1":"One",`)) +
		"\"\U00000080\":\"Control\"," +
		"\"\U000000F6\":\"Latin Small Letter O With Diaeresis\"," +
		"\"\U000020AC\":\"Euro Sign\"," +
		"\"\U0001F600\":\"Emoji: Grinning Face\"," +
		"\"\U0000FB33\":\"Hebrew Letter Dalet With Dagesh\"}"
	got, err := Canonicalize(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestSortingNestedAndPrefix(t *testing.T) {
	got, err := Canonicalize([]byte(`{"b":{"z":1,"a":[3,1,2]},"a":0,"ab":1,"":2}`))
	if err != nil {
		t.Fatal(err)
	}
	// Array order is preserved; a prefix sorts before its extensions; the empty name first.
	if want := `{"":2,"a":0,"ab":1,"b":{"a":[3,1,2],"z":1}}`; string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestStringEscaping(t *testing.T) {
	cases := []struct{ in, want string }{
		{`"~u0000~u0001~u001f~u001F"`, `"~u0000~u0001~u001f~u001f"`},
		{`"~b~t~n~f~r"`, `"~b~t~n~f~r"`},
		{`"~u0008~u0009~u000a~u000c~u000d"`, `"~b~t~n~f~r"`},
		{`"~u007f"`, "\"\x7f\""}, // DEL is not escaped
		// encoding/json escapes U+2028 and U+2029; RFC 8785 writes them literally.
		{`"~u2028~u2029"`, "\"\U00002028\U00002029\""},
		{`"<>&"`, `"<>&"`}, // no HTML escaping
		{`"~/"`, `"/"`},
		{`"~u00e9"`, "\"\U000000E9\""},
		{"\"\U000000E9\"", "\"\U000000E9\""},
		{`"~ud83d~ude00"`, "\"\U0001F600\""},
		{`"~uD83D~uDE00"`, "\"\U0001F600\""},
		{`"~"~~"`, `"~"~~"`},
	}
	for _, tc := range cases {
		want := string(j(tc.want))
		got, err := Canonicalize(j(tc.in))
		if err != nil {
			t.Errorf("Canonicalize(%s): %v", j(tc.in), err)
			continue
		}
		if string(got) != want {
			t.Errorf("Canonicalize(%s) = %q, want %q", j(tc.in), got, want)
		}
	}
}

func TestLiteralsAndWhitespace(t *testing.T) {
	got, err := Canonicalize([]byte(" \t\r\n[ true , false,null ,{ } ,[ ] ] \n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := `[true,false,null,{},[]]`; string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

// Input that is not I-JSON must be rejected, not repaired.
func TestRejectsNonIJSON(t *testing.T) {
	cases := map[string]string{
		"duplicate name":             `{"a":1,"a":1}`,
		"duplicate name via escape":  `{"a":1,"~u0061":2}`,
		"nested duplicate":           `{"x":{"k":1,"k":2}}`,
		"lone high surrogate":        `"~ud83d"`,
		"high then non-low":          `"~ud83d~u0041"`,
		"high then text":             `"~ud83dx"`,
		"high then high":             `"~ud83d~ud83d"`,
		"lone low surrogate":         `"~ude00"`,
		"escaped noncharacter FFFF":  `"~uffff"`,
		"escaped noncharacter FDD0":  `"~ufdd0"`,
		"escaped noncharacter 1FFFE": `"~ud83f~udffe"`,
		"raw noncharacter FFFE":      "\"\xef\xbf\xbe\"",
		"raw noncharacter 10FFFF":    "\"\xf4\x8f\xbf\xbf\"",
		"invalid UTF-8":              "\"\xff\"",
		"truncated UTF-8":            "\"\xe2\x82\"",
		"UTF-8 encoded surrogate":    "\"\xed\xa0\x80\"",
		"overlong UTF-8":             "\"\xc0\xaf\"",
		"control character":          "\"a\x01b\"",
		"NaN":                        `NaN`,
		"Infinity":                   `[Infinity]`,
		"overflow":                   `1e400`,
		"negative overflow":          `-1e400`,
		"leading zero":               `01`,
		"leading zero in array":      `[01]`,
		"bare fraction":              `.5`,
		"empty fraction":             `1.`,
		"empty exponent":             `1e`,
		"plus sign":                  `+1`,
		"lone minus":                 `-`,
		"hex escape too short":       `"~u12"`,
		"hex escape not hex":         `"~u12g4"`,
		"bad escape":                 `"~x"`,
		"trailing comma in array":    `[1,]`,
		"trailing comma in object":   `{"a":1,}`,
		"missing colon":              `{"a" 1}`,
		"unquoted name":              `{a:1}`,
		"single quotes":              `'a'`,
		"trailing data":              `{} {}`,
		"unterminated string":        `"abc`,
		"unterminated object":        `{"a":1`,
		"unterminated array":         `[1`,
		"empty input":                ``,
		"whitespace only":            "  ",
		"byte order mark":            "\xef\xbb\xbf{}",
		"bad literal":                `tru`,
		"comment":                    `{/*x*/}`,
		"non-JSON whitespace (0x0b)": "[1,\x0b2]",
	}
	for name, in := range cases {
		out, err := Canonicalize(j(in))
		if err == nil {
			t.Errorf("%s: Canonicalize(%q) = %q, want an error", name, j(in), out)
			continue
		}
		if !IsCode(err, CodeMalformedJSON) {
			t.Errorf("%s: error %v, want code %s", name, err, CodeMalformedJSON)
		}
	}
}

func TestNestingLimit(t *testing.T) {
	ok := strings.Repeat("[", maxDepth) + strings.Repeat("]", maxDepth)
	if _, err := Canonicalize([]byte(ok)); err != nil {
		t.Fatalf("depth %d rejected: %v", maxDepth, err)
	}
	deep := strings.Repeat("[", maxDepth+1) + strings.Repeat("]", maxDepth+1)
	if _, err := Canonicalize([]byte(deep)); !IsCode(err, CodeMalformedJSON) {
		t.Fatalf("depth %d: err %v, want %s", maxDepth+1, err, CodeMalformedJSON)
	}
	deepObj := strings.Repeat(`{"a":`, maxDepth+1) + "1" + strings.Repeat("}", maxDepth+1)
	if _, err := Canonicalize([]byte(deepObj)); !IsCode(err, CodeMalformedJSON) {
		t.Fatalf("object depth %d: err %v, want %s", maxDepth+1, err, CodeMalformedJSON)
	}
	// Siblings do not accumulate depth.
	wide := "[" + strings.Repeat(strings.Repeat("[", maxDepth-1)+strings.Repeat("]", maxDepth-1)+",", 3) + "1]"
	if _, err := Canonicalize([]byte(wide)); err != nil {
		t.Fatalf("sibling arrays rejected: %v", err)
	}
}

// Canonicalization is idempotent and independent of input member order and whitespace.
func TestCanonicalIsFixedPoint(t *testing.T) {
	a := j(`{"z":[1,{"y":"~u00e9","x":1.0}],"a":"~u2028"}`)
	b := []byte("{ \"a\" : \"\U00002028\", \"z\" : [ 1e0 , { \"x\" : 1 , \"y\" : \"\U000000E9\" } ] }")
	ca, err := Canonicalize(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := Canonicalize(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca) != string(cb) {
		t.Fatalf("equivalent inputs differ:\n%s\n%s", ca, cb)
	}
	again, err := Canonicalize(ca)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(ca) {
		t.Fatalf("not a fixed point:\n%s\n%s", ca, again)
	}
}

// The parser itself rejects a number that overflows binary64; formatNumber's own check is a
// second line and is tested separately.
func TestParserRejectsOverflow(t *testing.T) {
	for _, in := range []string{"1e400", "-1e400", "[1.8e308]"} {
		if _, err := parseJSON([]byte(in)); !IsCode(err, CodeMalformedJSON) {
			t.Errorf("parseJSON(%s): err %v, want %s", in, err, CodeMalformedJSON)
		}
	}
	if _, err := parseJSON([]byte("1.7976931348623157e308")); err != nil {
		t.Errorf("max binary64 rejected: %v", err)
	}
}
