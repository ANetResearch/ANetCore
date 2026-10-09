package seal

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// Core §2.3: Grant key 3 (home) is an AID (identity.ValidAID) and key 5 (p2p) is host:port of at
// most 262 bytes with a port from 1 to 65535. Both are checked when the grant is decoded: CheckGrant
// and UnmarshalGrant refuse at step decode, Marshal refuses to write such a grant. The positives
// of GRANT-1 still pass (TestGRANT_1) with the vector unchanged.
func TestGrantHomeAndP2PBounds(t *testing.T) {
	long := func(n int) string { // host:port of n bytes, port 4710
		return strings.Repeat("h", n-len(":4710")) + ":4710"
	}
	for _, c := range []struct {
		name, home string
		p2p        *string
		ok         bool
	}{
		{"an AID home and no p2p", testHomeAID, nil, true},
		{"a host name", testHomeAID, strp("node.example:4710"), true},
		{"an IPv4 address", testHomeAID, strp("192.0.2.10:4710"), true},
		{"an IPv6 address", testHomeAID, strp("[2001:db8::1]:4710"), true},
		{"port 1", testHomeAID, strp("192.0.2.10:1"), true},
		{"port 65535", testHomeAID, strp("192.0.2.10:65535"), true},
		{"262 bytes", testHomeAID, strp(long(262)), true},

		{"home empty", "", nil, false},
		{"home a host name", "hub.example", nil, false},
		{"home a URL", "https://hub.example", nil, false},
		{"home an AID in upper case", strings.ToUpper(testHomeAID), nil, false},
		{"home an AID cut short", testHomeAID[:len(testHomeAID)-1], nil, false},
		{"home an AID with U+0000", testHomeAID + "\x00", nil, false},
		{"p2p of 263 bytes", testHomeAID, strp(long(263)), false},
		{"p2p empty", testHomeAID, strp(""), false},
		{"p2p without a port", testHomeAID, strp("192.0.2.10"), false},
		{"p2p with an empty port", testHomeAID, strp("192.0.2.10:"), false},
		{"p2p without a host", testHomeAID, strp(":4710"), false},
		{"port 0", testHomeAID, strp("192.0.2.10:0"), false},
		{"port 65536", testHomeAID, strp("192.0.2.10:65536"), false},
		{"port 99999999999999999999", testHomeAID, strp("192.0.2.10:99999999999999999999"), false},
		// 2^64 + 80 and 2^64 + 1: read into a 64-bit counter without a bound, they wrap to 80 and 1.
		{"port 2^64 + 80", testHomeAID, strp("192.0.2.10:18446744073709551696"), false},
		{"port 2^64 + 1", testHomeAID, strp("192.0.2.10:18446744073709551617"), false},
		{"port with a sign", testHomeAID, strp("192.0.2.10:+80"), false},
		{"port negative", testHomeAID, strp("192.0.2.10:-1"), false},
		{"port a name", testHomeAID, strp("192.0.2.10:http"), false},
		{"an IPv6 address without brackets", testHomeAID, strp("2001:db8::1:4710"), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newGrantScene()
			s.home, s.p2p = c.home, c.p2p
			raw := s.grantBytes(t)
			_, _, cerr := CheckGrant(&SealedInner{From: s.from, IX: s.inIX, Grant: raw}, &s.keys, s.now)
			_, uerr := UnmarshalGrant(raw)
			b, err := s.body.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			g := &Grant{Cap: Cap{Body: b, Sig: ed25519.Sign(s.signer, b)}, HolderSeed: s.seed, Home: c.home, P2P: c.p2p}
			_, merr := g.Marshal()
			if c.p2p != nil && c.home == testHomeAID && ValidP2PAddr(*c.p2p) != c.ok {
				t.Fatalf("ValidP2PAddr(%q) = %v", *c.p2p, !c.ok)
			}
			if c.ok {
				wantStep(t, cerr, "")
				if uerr != nil || merr != nil {
					t.Fatalf("UnmarshalGrant %v, Marshal %v", uerr, merr)
				}
				return
			}
			wantStep(t, cerr, "decode")
			wantStep(t, uerr, "decode")
			if ReasonOf(merr) != ReasonInvalidInput {
				t.Fatalf("Marshal: %v, want %s", merr, ReasonInvalidInput)
			}
		})
	}
}
