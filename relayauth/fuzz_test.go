package relayauth

// Fuzz targets for the relay v2 authentication header and preimage (ANet docs/notes/0033).

import (
	"bytes"
	"crypto/ed25519"
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
// part is the one the method, target and body give. No v2 preimage equals a v1 preimage.
func FuzzPreimageV2(f *testing.F) {
	f.Add(ActionSend, "bafyreiaid", "bafyreihub", uint64(1767225600000), "POST", "/relay/send", []byte("body"), "poll")
	f.Add(ActionKeys, "a", "b", uint64(0), "GET", "/agents/a/keys?x=1", []byte{}, "v2")
	f.Fuzz(func(t *testing.T, action, aid, hub string, ts uint64, method, target string, body []byte, v1action string) {
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
		if !strings.Contains(v1action, "/") && !strings.Contains(aid, "/") {
			if bytes.Equal(Preimage(v1action, aid, ts), p) {
				t.Fatalf("v1 preimage equals v2 preimage %q", p)
			}
		}
	})
}
