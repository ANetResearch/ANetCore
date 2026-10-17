package coredet

import (
	"strings"
	"testing"
)

// C-R2 (_CONVENTIONS §2): the decoder MUST forbid CBOR tags. A tag-bearing byte
// sequence (here 0xc0 = tag 0, RFC 3339 date-time, wrapping a text string) MUST be
// rejected, not silently decoded.
func TestUnmarshalRejectsTags(t *testing.T) {
	// 0xc0 = major type 6, tag 0; 0x60 = empty text string. A well-formed tagged item.
	tagged := []byte{0xc0, 0x60}
	var v any
	if err := Unmarshal(tagged, &v); err == nil {
		t.Fatalf("Unmarshal of tag-bearing bytes must error (C-R2), got value %v", v)
	}
}

// Sanity: an untagged value still decodes.
func TestUnmarshalUntagged(t *testing.T) {
	b, err := Marshal(uint64(7))
	if err != nil {
		t.Fatal(err)
	}
	var n uint64
	if err := Unmarshal(b, &n); err != nil {
		t.Fatalf("untagged decode failed: %v", err)
	}
	if n != 7 {
		t.Fatalf("got %d want 7", n)
	}
}

// A Go string can hold any bytes; a CBOR text string cannot. The encoder did
// not check and the decoder did, so data could be written but not read back,
// and the writer was told it succeeded.
//
// Where: coredet.Marshal. Behaviour: a string that is not valid UTF-8 was
// encoded as major type 3. Effect: the data on disk fails at the next read, at
// a time and in a process unrelated to the write. Found when the anet daemon
// wrote a command echo containing 0xa2 into the evidence ledger; the ledger
// could not be read on restart and the node crashed and restarted endlessly
// under systemd.
func TestMarshalRefusesAStringItCannotDecodeBack(t *testing.T) {
	bad := map[string]any{"observed_state": string([]byte{0x68, 0x69, 0xa2, 0x6f})}
	b, err := Marshal(bad)
	if err == nil {
		t.Fatalf("非法 UTF-8 的 string 必须在编码时就被拒绝, 而不是留到解码时; 得到 %d 字节", len(b))
	}
	if !strings.Contains(err.Error(), "will not decode") {
		t.Fatalf("错误信息应说清是编不出能解的东西, 实得: %v", err)
	}

	// The same bytes in a []byte field are legal: a CBOR byte string has no UTF-8 requirement.
	ok := map[string]any{"observed_state": []byte{0x68, 0x69, 0xa2, 0x6f}}
	enc, err := Marshal(ok)
	if err != nil {
		t.Fatalf("[]byte 承载任意字节应当合法: %v", err)
	}
	var back map[string]any
	if err := Unmarshal(enc, &back); err != nil {
		t.Fatalf("字节串必须能解回来: %v", err)
	}

	// Valid UTF-8 (including Chinese text and NUL) is unaffected.
	for _, s := range []string{"", "hello", "中文与符号 ±∞", string([]byte{0x00, 0x41})} {
		if _, err := Marshal(map[string]any{"s": s}); err != nil {
			t.Fatalf("合法 UTF-8 %q 不该被拒: %v", s, err)
		}
	}
}
