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

// 一个 Go string 可以装任意字节, CBOR 文本串不行。编码器不查、解码器查, 于是
// 写得进读不出 —— 写入方还拿到了成功返回。
//
// 位置 coredet.Marshal; 行为 非法 UTF-8 的 string 被编成 major type 3;
// 影响 落盘的数据下次读取时失败, 且失败发生在与写入无关的时间和进程里;
// 发现方式 anet daemon 把含 0xa2 的命令回显写进证据账本, 重启时账本读不动,
// 节点在 systemd 下无限崩溃重启。
func TestMarshalRefusesAStringItCannotDecodeBack(t *testing.T) {
	bad := map[string]any{"observed_state": string([]byte{0x68, 0x69, 0xa2, 0x6f})}
	b, err := Marshal(bad)
	if err == nil {
		t.Fatalf("非法 UTF-8 的 string 必须在编码时就被拒绝, 而不是留到解码时; 得到 %d 字节", len(b))
	}
	if !strings.Contains(err.Error(), "will not decode") {
		t.Fatalf("错误信息应说清是编不出能解的东西, 实得: %v", err)
	}

	// 同样的字节放进 []byte 字段是合法的 —— CBOR 字节串没有 UTF-8 要求。
	ok := map[string]any{"observed_state": []byte{0x68, 0x69, 0xa2, 0x6f}}
	enc, err := Marshal(ok)
	if err != nil {
		t.Fatalf("[]byte 承载任意字节应当合法: %v", err)
	}
	var back map[string]any
	if err := Unmarshal(enc, &back); err != nil {
		t.Fatalf("字节串必须能解回来: %v", err)
	}

	// 合法 UTF-8 (含中文与 NUL) 不受影响。
	for _, s := range []string{"", "hello", "中文与符号 ±∞", string([]byte{0x00, 0x41})} {
		if _, err := Marshal(map[string]any{"s": s}); err != nil {
			t.Fatalf("合法 UTF-8 %q 不该被拒: %v", s, err)
		}
	}
}
