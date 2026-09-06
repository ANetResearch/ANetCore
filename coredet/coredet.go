// Package coredet implements CoreDet-CBOR, the Agent Network suite's deterministic
// CBOR profile. It is the single encoder for every CID preimage and signature
// preimage in the stack.
//
// Normative source: design3/spec/_CONVENTIONS §2 = RFC 8949 §4.2 Core Deterministic
// Encoding (shortest-form integers/lengths, definite-length items, map keys sorted by
// bytewise-lexicographic order of their encoded bytes, preferred float serialization)
// plus the suite restrictions C-R1 (no NaN/±Infinity in any value) and C-R2 (no CBOR
// tags). RFC 7049 "canonical CBOR" (length-first key sort) MUST NOT be substituted.
package coredet

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	opts := cbor.CoreDetEncOptions()        // RFC 8949 §4.2
	opts.NaNConvert = cbor.NaNConvertReject // C-R1
	opts.InfConvert = cbor.InfConvertReject // C-R1
	m, err := opts.EncMode()
	if err != nil {
		panic(fmt.Sprintf("coredet: invalid CoreDet enc options: %v", err))
	}
	encMode = m
	// C-R2: no CBOR tags. DupMapKeyEnforcedAPF: reject duplicate map keys — a canonical CoreDet
	// encoding (RFC 8949 §4.2) never has them, so a decoder that verifies the profile MUST reject
	// them rather than silently keep last-wins (which would let two implementations disagree).
	dm, err := cbor.DecOptions{TagsMd: cbor.TagsForbidden, DupMapKey: cbor.DupMapKeyEnforcedAPF}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("coredet: invalid dec options: %v", err))
	}
	decMode = dm
}

// Marshal encodes v as CoreDet-CBOR. It returns an error if v contains NaN or
// ±Infinity (C-R1), or if the result would not decode under Unmarshal.
//
// That last check closes an asymmetry between the two modes. A Go string may
// hold arbitrary bytes and the encoder writes it as a CBOR text string without
// looking; the decoder refuses one that is not valid UTF-8, as RFC 8949
// requires. Without the check this package can emit a preimage it cannot read
// back, and the writer is told it succeeded.
//
// 位置 coredet.Marshal; 行为 编码器接受非法 UTF-8 的 Go string, 解码器拒绝;
// 影响 写入成功、数据落盘, 失败推迟到下一次读取 —— 往往是另一个进程、另一天;
// 发现方式 anet daemon 把一条含 0xa2 字节的命令回显写进证据账本, 两天后重启时
// 账本读不动, 节点在 systemd 下每 5 秒崩溃重启, 只能手工编辑账本才能恢复。
//
// 修在这里而不是各调用点: 本包是全栈唯一的 preimage 编码器, 在这里立住
// "能编码即能解码", 这类缺陷对所有调用方一次消失。代价是每次 Marshal 多一次
// 解码; 若将来证明它在热路径上要紧, 那时再拿基准数据来换写法。
func Marshal(v any) ([]byte, error) {
	b, err := encMode.Marshal(v)
	if err != nil {
		return nil, err
	}
	// Ask the decoder rather than reimplement its rules. Valid() only checks
	// structure — the UTF-8 rule lives in the value-building path — and a
	// hand-written scan would be a second copy of the decoder that is free to
	// drift from the first.
	var back any
	if err := decMode.Unmarshal(b, &back); err != nil {
		return nil, fmt.Errorf("coredet: encoded value will not decode (%w) — "+
			"a string almost certainly carries bytes that are not valid UTF-8; "+
			"arbitrary bytes belong in a []byte field", err)
	}
	return b, nil
}

// Unmarshal decodes CoreDet-CBOR bytes into v. Decoding determinism is not required
// (it is an encode property); re-encoding the result with Marshal reproduces canonical bytes.
func Unmarshal(b []byte, v any) error {
	return decMode.Unmarshal(b, v)
}
