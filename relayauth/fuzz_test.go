package relayauth

// Fuzz targets for the relay v2 authentication header and preimage.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

// FuzzDecodeSig: a header value that decodes is exactly one 64-byte signature with exactly one
// accepted spelling, the one EncodeSig produces (the hub keys its replay cache on the header).
func FuzzDecodeSig(f *testing.F) {
	f.Add(EncodeSig(make([]byte, 64)))
	f.Add(EncodeSig(bytes.Repeat([]byte{0xff}, 64)))
	f.Add(EncodeSig(bytes.Repeat([]byte{0xff}, 64)) + "=")
	f.Add(strings.Repeat("A", 85) + "B")
	f.Add(strings.Repeat("A", 43) + "\n" + strings.Repeat("A", 43))
	f.Fuzz(func(t *testing.T, s string) {
		b, err := DecodeSig(s)
		if err != nil {
			if err != ErrBadSig {
				t.Fatalf("DecodeSig error %v is not ErrBadSig", err)
			}
			return
		}
		if len(b) != ed25519.SignatureSize {
			t.Fatalf("decoded %d bytes", len(b))
		}
		if EncodeSig(b) != s {
			t.Fatalf("%q decodes to a signature whose spelling is %q", s, EncodeSig(b))
		}
	})
}

// FuzzPreimageV2: under the documented preconditions (no "/" in action, aid and hub AID), the
// preimage determines every field it binds: the prefix fields split back out, and the digest
// part is the one the method, target and body give.
func FuzzPreimageV2(f *testing.F) {
	f.Add(ActionSession, "bafyreiaid", "bafyreihub", uint64(1767225600000), "POST", "/relay/session", []byte("body"))
	f.Add(ActionKeys, "a", "b", uint64(0), "GET", "/agents/a/keys?x=1", []byte{})
	f.Fuzz(func(t *testing.T, action, aid, hub string, ts uint64, method, target string, body []byte) {
		if strings.Contains(action, "/") || strings.Contains(aid, "/") || strings.Contains(hub, "/") {
			return
		}
		p := PreimageV2(action, aid, hub, ts, method, target, body)
		rest, ok := bytes.CutPrefix(p, []byte("anet-relay/v2/"))
		if !ok {
			t.Fatalf("preimage %q lacks the v2 prefix", p)
		}
		parts := strings.Split(string(rest), "/")
		if len(parts) != 5 {
			t.Fatalf("preimage %q splits into %d fields", p, len(parts))
		}
		if parts[0] != action || parts[1] != aid || parts[2] != hub {
			t.Fatalf("preimage %q does not split back to %q/%q/%q", p, action, aid, hub)
		}
		// The digest is the only part method, target and body reach: a different request gives a
		// different digest (unless SHA-256 collides).
		other := PreimageV2(action, aid, hub, ts, method+"X", target, body)
		if bytes.Equal(other, p) {
			t.Fatal("the method is not bound")
		}
		other = PreimageV2(action, aid, hub, ts, method, target, append(append([]byte(nil), body...), 0))
		if bytes.Equal(other, p) {
			t.Fatal("the body is not bound")
		}
		// Moving bytes between target and body changes the digest (the NUL separator). An HTTP
		// method or origin-form target never holds a NUL, which is what the separator relies on.
		if len(target) > 0 && !strings.Contains(method+target, "\x00") {
			moved := PreimageV2(action, aid, hub, ts, method, target[:len(target)-1],
				append([]byte{target[len(target)-1]}, body...))
			if bytes.Equal(moved, p) {
				t.Fatal("a byte moved from the target to the body gives the same preimage")
			}
		}
	})
}

// FuzzSessionHeaders: a X-ANet-Session or X-ANet-MAC value that decodes holds exactly the right
// number of bytes and has exactly one accepted spelling, the one the encoder produces.
func FuzzSessionHeaders(f *testing.F) {
	f.Add(EncodeSessionID(make([]byte, SessionIDLen)))
	f.Add(EncodeMAC(bytes.Repeat([]byte{0xff}, SessionMACLen)))
	f.Add(EncodeMAC(bytes.Repeat([]byte{0xff}, SessionMACLen)) + "=")
	f.Add(strings.Repeat("A", 21) + "B")
	f.Add(strings.Repeat("A", 11) + "\n" + strings.Repeat("A", 10))
	f.Add(EncodeSessionID(make([]byte, SessionIDLen)) + "\n")
	f.Add(strings.Repeat("A", 20) + "\r\n" + strings.Repeat("A", 23))
	f.Fuzz(func(t *testing.T, s string) {
		if b, err := DecodeSessionID(s); err == nil {
			if len(b) != SessionIDLen || EncodeSessionID(b) != s {
				t.Fatalf("%q decodes to %d bytes spelled %q", s, len(b), EncodeSessionID(b))
			}
		} else if err != ErrBadSessionHeader {
			t.Fatalf("DecodeSessionID error %v", err)
		}
		if b, err := DecodeMAC(s); err == nil {
			if len(b) != SessionMACLen || EncodeMAC(b) != s {
				t.Fatalf("%q decodes to %d bytes spelled %q", s, len(b), EncodeMAC(b))
			}
		} else if err != ErrBadSessionHeader {
			t.Fatalf("DecodeMAC error %v", err)
		}
	})
}

// FuzzOpenSessionKey: whatever a hub answers, opening it never panics, and only a sealed key
// opens. Random enc and ct are refused as ErrSessionKey or ErrSessionInput; a key sealed for the
// fuzzed hub AID and session id opens to itself.
func FuzzOpenSessionKey(f *testing.F) {
	esk, epk, err := NewSessionKey()
	if err != nil {
		f.Fatal(err)
	}
	f.Add("bafyreihub", make([]byte, SessionIDLen), make([]byte, 32), make([]byte, 48), make([]byte, SessionKeyLen))
	f.Add("h\x00", make([]byte, 15), []byte{1}, []byte{2}, []byte{3})
	f.Fuzz(func(t *testing.T, hub string, sid, enc, ct, k []byte) {
		if _, err := OpenSessionKey(esk, hub, sid, enc, ct); err == nil {
			t.Fatalf("random enc %x and ct %x opened", enc, ct)
		} else if !errors.Is(err, ErrSessionKey) && !errors.Is(err, ErrSessionInput) && !errors.Is(err, ErrNUL) {
			t.Fatalf("unexpected error %v", err)
		}
		enc2, ct2, err := SealSessionKey(epk, hub, sid, k)
		if err != nil {
			return
		}
		got, err := OpenSessionKey(esk, hub, sid, enc2, ct2)
		if err != nil || !bytes.Equal(got, k) {
			t.Fatalf("sealed %x for %q, opened %x, %v", k, hub, got, err)
		}
	})
}

// FuzzSessionMACInput: under the documented precondition (no U+0000 in method, target and home),
// the MAC input determines every field: two requests that differ in any field have different
// inputs. A field holding U+0000 is refused instead.
func FuzzSessionMACInput(f *testing.F) {
	f.Add(uint64(1767225600000), "POST", "/relay/send", "bafyreihub", []byte("body"), uint64(1), "POST", "/relay/send", "", []byte("body"))
	f.Add(uint64(7), "POST/", "relay", "", []byte{}, uint64(7), "POST", "/relay", "", []byte{})
	f.Fuzz(func(t *testing.T, ts1 uint64, m1, p1, h1 string, b1 []byte, ts2 uint64, m2, p2, h2 string, b2 []byte) {
		sid := make([]byte, SessionIDLen)
		in1, err1 := sessionMACInput(sid, ts1, m1, p1, h1, b1)
		in2, err2 := sessionMACInput(sid, ts2, m2, p2, h2, b2)
		if strings.Contains(m1+p1+h1, "\x00") != (err1 != nil) || strings.Contains(m2+p2+h2, "\x00") != (err2 != nil) {
			t.Fatalf("U+0000 refusal wrong: %v, %v", err1, err2)
		}
		if err1 != nil || err2 != nil {
			return
		}
		same := ts1 == ts2 && m1 == m2 && p1 == p2 && h1 == h2 && bytes.Equal(b1, b2)
		if bytes.Equal(in1, in2) != same {
			t.Fatalf("inputs equal = %v for requests equal = %v", bytes.Equal(in1, in2), same)
		}
	})
}
