package relayauth

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strconv"
	"strings"
	"testing"
)

// The preimage is a shared constant between two repos.
//
// The daemon builds these bytes and signs them; the hub builds them again and verifies. They are
// not exchanged, only recomputed — so a change on either side that looks harmless (a separator, a
// field order, an action name) locks every node out of its own mailbox, and the symptom at the
// hub is an invalid signature from a key that is perfectly valid. Pinning the exact bytes is the
// point (TestPreimageV2BytesArePinned, and golden/relayauth_v3_test.go for every action).

// The separator only separates because no field contains it.
//
// "anet-relay/v2/" + action + "/" + aid + "/" + hubAID + "/" + ts + "/" + digest is unambiguous
// exactly while action, aid and hubAID are slash-free: an AID "a/1" signed for "poll" and an AID
// "1" signed for "poll/a" are the same bytes. Actions are the constants below and AIDs are CIDs,
// so neither can carry a slash today — the ambiguity is a property of the inputs, not of the
// format.
//
// Written down because that is the kind of precondition a later change walks into. The day this
// function is asked to sign for a human-chosen name instead of a CID, this test is the one that
// has to be read.
func TestTheFormatIsUnambiguousOnlyForSlashFreeFields(t *testing.T) {
	for _, a := range allActions {
		if strings.Contains(a, "/") {
			t.Errorf("action %q contains the separator: it can pose as a different action+aid pair", a)
		}
	}
	// The collision the constraint rules out, stated so it is visible.
	if string(PreimageV2("poll", "a/1", "h", 2, "POST", "/", nil)) != string(PreimageV2("poll/a", "1", "h", 2, "POST", "/", nil)) {
		t.Fatal("expected the documented ambiguity; the format changed, so re-derive the precondition")
	}
}

// allActions lists every action constant. A new constant that is not added here escapes the
// distinctness and separator checks below, so the list is the place to extend first.
var allActions = []string{
	ActionPoll, ActionAck, ActionRegister, ActionProfile,
	ActionVisibility, ActionDeregister,
	ActionBalance, ActionLedger, ActionRedemptions, ActionKeys,
	ActionSession, ActionRevoke,
	ActionFedForward, ActionFedBucket, ActionFedCards,
}

// The v2 action strings are wire constants: the hub rebuilds the preimage from its own copy of the
// action name, so a renamed constant fails every signature for that endpoint.
func TestV2ActionNamesArePinned(t *testing.T) {
	want := []string{
		"poll", "ack", "register", "profile",
		"visibility", "deregister",
		"balance", "ledger", "redemptions", "keys",
		"session", "revoke",
		"fed_forward", "fed_bucket", "fed_cards",
	}
	if len(allActions) != len(want) {
		t.Fatalf("%d actions, want %d", len(allActions), len(want))
	}
	for i, a := range allActions {
		if a != want[i] {
			t.Errorf("action %d = %q, want %q", i, a, want[i])
		}
	}
}

// The v2 preimage bytes, pinned. The digests were computed independently of this package
// (Python hashlib + base64.urlsafe_b64encode with the padding stripped), so a change to the digest
// input, the separators, the alphabet or the padding fails here.
func TestPreimageV2BytesArePinned(t *testing.T) {
	const aid = "bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay"
	const hub = "bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y"
	cases := []struct {
		name                 string
		action, method, path string
		body                 []byte
		want                 string
	}{
		{
			name: "POST with a body", action: ActionSession, method: "POST", path: "/relay/session",
			body: []byte(`{"epk":"AA"}`),
			want: "anet-relay/v2/session/" + aid + "/" + hub + "/1767225600000/BCb8Ngf3B7fnOm4sYvp76V6r8NYlJs75bmoBS45lxLE",
		},
		{
			// The digest contains "-", which is where the URL-safe alphabet differs from the standard one.
			name: "GET with a query and no body", action: ActionLedger, method: "GET",
			path: "/agents/" + aid + "/ledger?limit=10",
			want: "anet-relay/v2/ledger/" + aid + "/" + hub + "/1767225600000/qDfr8hVW8UzedKzgDmakEJVsfo-b72PuLHdoV2TvdZw",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(PreimageV2(tc.action, aid, hub, 1767225600000, tc.method, tc.path, tc.body))
			if got != tc.want {
				t.Fatalf("the v2 signed bytes moved:\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}

// Every input is inside the signature. Each variant below changes one input; if any produced the
// base bytes, a signature for the base request would authorize the variant.
func TestPreimageV2BindsEveryInput(t *testing.T) {
	type in struct {
		action, aid, hub string
		ts               uint64
		method, path     string
		body             string
	}
	p := func(x in) string {
		return string(PreimageV2(x.action, x.aid, x.hub, x.ts, x.method, x.path, []byte(x.body)))
	}
	base := in{ActionRevoke, "did:anet:alice", "did:anet:hub-a", 1000, "POST", "/mailbox/revoke", `{"cap_ids":["bob"]}`}
	variants := map[string]in{
		"another action":             {ActionPoll, base.aid, base.hub, base.ts, base.method, base.path, base.body},
		"another sender":             {base.action, "did:anet:mallory", base.hub, base.ts, base.method, base.path, base.body},
		"another hub":                {base.action, base.aid, "did:anet:hub-b", base.ts, base.method, base.path, base.body},
		"another time":               {base.action, base.aid, base.hub, 1001, base.method, base.path, base.body},
		"another method":             {base.action, base.aid, base.hub, base.ts, "PUT", base.path, base.body},
		"another target":             {base.action, base.aid, base.hub, base.ts, base.method, "/mailbox/revoke?x=1", base.body},
		"another body":               {base.action, base.aid, base.hub, base.ts, base.method, base.path, `{"cap_ids":["eve"]}`},
		"body bytes moved to target": {base.action, base.aid, base.hub, base.ts, base.method, base.path + base.body[:1], base.body[1:]},
		"target bytes moved to method": {base.action, base.aid, base.hub, base.ts, base.method + base.path[:1],
			base.path[1:], base.body},
	}
	want := p(base)
	for name, v := range variants {
		if p(v) == want {
			t.Errorf("%s produces the same preimage as the base request", name)
		}
	}
}

func TestV2ActionsAreDistinctAndSlashFree(t *testing.T) {
	seen := map[string]string{}
	for _, a := range allActions {
		if strings.Contains(a, "/") {
			t.Errorf("action %q contains the separator", a)
		}
		pv := string(PreimageV2(a, "did:anet:x", "did:anet:h", 1, "POST", "/", nil))
		if prev, dup := seen[pv]; dup {
			t.Errorf("actions %q and %q produce the same v2 challenge", prev, a)
		}
		seen[pv] = a
	}
}

// The replay window has to be short enough to matter and long enough to survive ordinary clock
// drift. Five minutes is the number the hub enforces on a signed request's X-ANet-TS (and on a
// session send's); pinning it here means changing it fails a test rather than silently widening
// the window for every hub that reads the constant.
func TestReplayWindowIsFiveMinutes(t *testing.T) {
	if MaxSkewMillis != 5*60*1000 {
		t.Fatalf("replay window = %dms, want 300000ms — the hub enforces this number too", MaxSkewMillis)
	}
}

// The header names are part of the wire: the hub looks up these exact names.
func TestHeaderNamesArePinned(t *testing.T) {
	for _, h := range []struct{ got, want string }{
		{HeaderAID, "X-ANet-AID"}, {HeaderTS, "X-ANet-TS"}, {HeaderSeq, "X-ANet-Seq"}, {HeaderSig, "X-ANet-Sig"},
	} {
		if h.got != h.want {
			t.Errorf("header %q, want %q", h.got, h.want)
		}
	}
}

// One signature has exactly one accepted header spelling: unpadded base64url of 64 bytes.
func TestSigHeaderEncoding(t *testing.T) {
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(0xf8 + i) // high bytes so the encoding contains "-" and "_"
	}
	enc := EncodeSig(sig)
	if len(enc) != 86 || strings.ContainsAny(enc, "=+/") {
		t.Fatalf("EncodeSig = %q: want 86 unpadded URL-safe characters", enc)
	}
	back, err := DecodeSig(enc)
	if err != nil || string(back) != string(sig) {
		t.Fatalf("round trip failed: %v", err)
	}
	for name, bad := range map[string]string{
		"padded":            enc + "==",
		"standard alphabet": strings.NewReplacer("-", "+", "_", "/").Replace(enc),
		"63 bytes":          EncodeSig(sig[:63]),
		"65 bytes":          EncodeSig(append(append([]byte(nil), sig...), 0)),
		"empty":             "",
		// encoding/base64 skips CR and LF even in strict mode, so without a length check these
		// decode to the same 64 bytes as enc and a second spelling of one signature exists.
		"embedded LF":   enc[:40] + "\n" + enc[40:],
		"embedded CRLF": enc[:40] + "\r\n" + enc[40:],
		"trailing LF":   enc + "\n",
	} {
		if _, err := DecodeSig(bad); !errors.Is(err, ErrBadSig) {
			t.Errorf("%s: want ErrBadSig, got %v", name, err)
		}
	}
	// Non-zero trailing bits: the last character of an 86-character encoding carries 4 padding
	// bits. A lenient decoder would map two spellings to one signature.
	last := enc[len(enc)-1]
	alt := enc[:len(enc)-1] + string(last+1)
	if _, err := DecodeSig(alt); !errors.Is(err, ErrBadSig) {
		t.Errorf("a spelling with non-zero trailing bits must be rejected, got %v", err)
	}
}

// A retired action is not an action: "send" and "p2p" (relay v2's sender-authenticated send and
// the hub rendezvous) and "fedkeys" (the federated key lookup) are gone in 0.3.0 and their names
// are never assigned again. Nothing may sign for them and no hub accepts them.
func TestRetiredActionsAreNotValid(t *testing.T) {
	for _, a := range []string{"send", "p2p", "fedkeys", "", "Poll", "poll ", "task.create", "anet-relay"} {
		if ValidAction(a) {
			t.Errorf("ValidAction(%q) = true", a)
		}
	}
	for _, a := range allActions {
		if !ValidAction(a) {
			t.Errorf("ValidAction(%q) = false for a defined action", a)
		}
	}
	if len(validActions) != len(allActions) {
		t.Errorf("validActions has %d entries, allActions %d", len(validActions), len(allActions))
	}
}

// Every Action* constant of this package is in validActions, read from the source so that a
// constant added without its entry fails here rather than being refused by every hub.
func TestEveryActionConstantIsValid(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, sp := range gd.Specs {
					vs := sp.(*ast.ValueSpec)
					for i, id := range vs.Names {
						if !strings.HasPrefix(id.Name, "Action") || i >= len(vs.Values) {
							continue
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							t.Errorf("%s is not a string literal", id.Name)
							continue
						}
						v, _ := strconv.Unquote(lit.Value)
						n++
						if !ValidAction(v) {
							t.Errorf("%s = %q is not in validActions", id.Name, v)
						}
					}
				}
			}
		}
	}
	if n != len(validActions) {
		t.Errorf("%d Action* constants, %d valid actions", n, len(validActions))
	}
}
