package liabtree

import (
	"fmt"
)

// WireStep is a path step as the hub's liability-proof response carries it (hub API wire 3):
// h is 64 lowercase hex digits, side is "L" or "R".
type WireStep struct {
	H    string `json:"h"`
	Sum  uint64 `json:"sum"`
	Side string `json:"side"`
}

// WireProof is the proof part of GET /agents/{aid}/liability-proof: the response is these members
// plus from_day, ledger_hw and record, so a hub's response type embeds it. Hashes and salts are
// lowercase hex (CORE-E5: public hashes meant for checking by hand).
type WireProof struct {
	ToDay   uint64     `json:"to_day"`
	AID     string     `json:"aid"`
	Balance uint64     `json:"balance"`
	Salt    string     `json:"salt"`
	Path    []WireStep `json:"path"`
}

const hexDigits = "0123456789abcdef"

// Hex is the one spelling of a hash or salt on the wire: 64 lowercase hex digits.
func Hex(b [32]byte) string {
	var s [64]byte
	for i, c := range b {
		s[2*i] = hexDigits[c>>4]
		s[2*i+1] = hexDigits[c&0x0f]
	}
	return string(s[:])
}

// ParseHex reads 64 lowercase hex digits; any other spelling (upper case, short, long) is refused,
// so one value has one spelling.
func ParseHex(s string) ([32]byte, error) {
	var out [32]byte
	if len(s) != 64 {
		return out, fmt.Errorf("%w: %d characters where 64 lowercase hex digits belong", ErrMalformed, len(s))
	}
	for i := 0; i < 64; i++ {
		var v byte
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		default:
			return out, fmt.Errorf("%w: character %d is not a lowercase hex digit", ErrMalformed, i)
		}
		out[i/2] = out[i/2]<<4 | v
	}
	return out, nil
}

// Wire is the response form of p.
func (p Proof) Wire() WireProof {
	w := WireProof{ToDay: p.ToDay, AID: p.AID, Balance: p.Balance, Salt: Hex(p.Salt), Path: make([]WireStep, len(p.Path))}
	for i, s := range p.Path {
		w.Path[i] = WireStep{H: Hex(s.Hash), Sum: s.Sum, Side: string(rune(s.Side))}
	}
	return w
}

// Parse reads a proof from its response form. It checks the spelling only (hex, side, at most
// MaxDepth steps); Verify checks the rest. Errors wrap ErrMalformed.
func (w WireProof) Parse() (Proof, error) {
	if len(w.Path) > MaxDepth {
		return Proof{}, fmt.Errorf("%w: the path has %d steps; a tree has at most %d levels", ErrMalformed, len(w.Path), MaxDepth)
	}
	salt, err := ParseHex(w.Salt)
	if err != nil {
		return Proof{}, fmt.Errorf("salt: %w", err)
	}
	p := Proof{AID: w.AID, ToDay: w.ToDay, Balance: w.Balance, Salt: salt, Path: make([]Step, len(w.Path))}
	for i, s := range w.Path {
		h, err := ParseHex(s.H)
		if err != nil {
			return Proof{}, fmt.Errorf("path step %d: %w", i, err)
		}
		var side Side
		switch s.Side {
		case "L":
			side = Left
		case "R":
			side = Right
		default:
			return Proof{}, fmt.Errorf("%w: path step %d has side %q; it is \"L\" or \"R\"", ErrMalformed, i, s.Side)
		}
		p.Path[i] = Step{Hash: h, Sum: s.Sum, Side: side}
	}
	return p, nil
}
