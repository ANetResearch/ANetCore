package relayauth

import (
	"errors"
	"strings"
	"testing"
)

// The preimage is a shared constant between two repos.
//
// The daemon builds these bytes and signs them; the hub builds them again
// and verifies. They are not exchanged, only recomputed — so a change on
// either side that looks harmless (a separator, a field order, an action
// name) locks every node out of its own mailbox, and the symptom at the
// hub is an invalid signature from a key that is perfectly valid.
//
// Pinning the exact bytes is the point. A test that only compared
// Preimage to itself would pass through any such change.
func TestPreimageBytesArePinned(t *testing.T) {
	const aid = "bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay"
	got := string(Preimage(ActionPoll, aid, 1767225600000))
	want := "anet-relay/poll/" + aid + "/1767225600000"
	if got != want {
		t.Fatalf("the signed bytes moved:\n got %s\nwant %s\n"+
			"Every node signing the old form is now locked out of its mailbox.", got, want)
	}
}

// A signature authorises one action, for one AID, at one time. Anything
// less and a captured signature becomes a capability someone else holds.
func TestASignatureAuthorisesOnlyWhatItSays(t *testing.T) {
	const alice = "did:anet:alice"
	const bob = "did:anet:bob"
	base := string(Preimage(ActionPoll, alice, 1000))

	// Reading someone's mailbox and rewriting their public profile are not
	// the same permission. If the action were outside the preimage, a
	// captured poll signature would be a profile-overwrite signature.
	for _, action := range []string{ActionAck, ActionRegister, ActionProfile} {
		if other := string(Preimage(action, alice, 1000)); other == base {
			t.Errorf("%q and %q produce the same challenge — one signature would authorise both",
				ActionPoll, action)
		}
	}
	if other := string(Preimage(ActionPoll, bob, 1000)); other == base {
		t.Error("two AIDs share a challenge — Alice's signature would open Bob's mailbox")
	}
	if other := string(Preimage(ActionPoll, alice, 1001)); other == base {
		t.Error("the timestamp is not in the challenge — a captured signature would never expire")
	}
}

// Every action constant must be distinct, and distinct after being placed
// in the preimage. Adding a new action is the moment this can break, and
// adding one is a two-line change nobody reviews closely.
func TestEveryActionIsDistinct(t *testing.T) {
	actions := []string{ActionPoll, ActionAck, ActionRegister, ActionProfile}
	seen := map[string]string{}
	for _, a := range actions {
		p := string(Preimage(a, "did:anet:x", 1))
		if prev, dup := seen[p]; dup {
			t.Errorf("actions %q and %q produce the same challenge", prev, a)
		}
		seen[p] = a
	}
	if len(seen) != len(actions) {
		t.Errorf("%d actions collapsed to %d challenges", len(actions), len(seen))
	}
}

// The replay window has to be short enough to matter and long enough to
// survive ordinary clock drift. Five minutes is the number both repos
// enforce; pinning it here means changing one side alone fails a test
// rather than silently widening the window on the other.
func TestReplayWindowIsFiveMinutes(t *testing.T) {
	if MaxSkewMillis != 5*60*1000 {
		t.Fatalf("replay window = %dms, want 300000ms — the hub enforces this number too",
			MaxSkewMillis)
	}
}

// The separator only separates because no field contains it.
//
// "anet-relay/" + action + "/" + aid + "/" + ts is unambiguous exactly
// while action and aid are slash-free: Preimage("poll", "a/1", 2) and
// Preimage("poll/a", "1", 2) are the same bytes. Actions are the four
// constants above and AIDs are CIDs, so neither can carry a slash today —
// the ambiguity is a property of the inputs, not of the format.
//
// Written down because that is the kind of precondition a later change
// walks into. The day this function is asked to sign for a human-chosen
// name instead of a CID, this test is the one that has to be read.
func TestTheFormatIsUnambiguousOnlyForSlashFreeFields(t *testing.T) {
	for _, a := range []string{ActionPoll, ActionAck, ActionRegister, ActionProfile} {
		if strings.Contains(a, "/") {
			t.Errorf("action %q contains the separator: it can pose as a different action+aid pair", a)
		}
	}
	// The collision the constraint rules out, stated so it is visible.
	if string(Preimage("poll", "a/1", 2)) != string(Preimage("poll/a", "1", 2)) {
		t.Fatal("expected the documented ambiguity; the format changed, so re-derive the precondition")
	}
}

// allActions lists every action constant. A new constant that is not added here escapes the
// distinctness and separator checks below, so the list is the place to extend first.
var allActions = []string{
	ActionPoll, ActionAck, ActionRegister, ActionProfile,
	ActionSend, ActionVisibility, ActionDeregister, ActionP2P,
	ActionBalance, ActionLedger, ActionRedemptions, ActionKeys,
}

// The v2 action strings are wire constants: the hub rebuilds the preimage from its own copy of the
// action name, so a renamed constant fails every signature for that endpoint.
func TestV2ActionNamesArePinned(t *testing.T) {
	want := []string{
		"poll", "ack", "register", "profile",
		"send", "visibility", "deregister", "p2p",
		"balance", "ledger", "redemptions", "keys",
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
			name: "POST with a body", action: ActionSend, method: "POST", path: "/relay/send",
			body: []byte(`{"to_aid":"x","envelope":"AA"}`),
			want: "anet-relay/v2/send/" + aid + "/" + hub + "/1767225600000/bzvqHocrRgGjbbYhXuGbxxXVfd3nQnvjuhvgduVcy6w",
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
	base := in{ActionSend, "did:anet:alice", "did:anet:hub-a", 1000, "POST", "/relay/send", `{"to_aid":"bob"}`}
	variants := map[string]in{
		"another action":             {ActionPoll, base.aid, base.hub, base.ts, base.method, base.path, base.body},
		"another sender":             {base.action, "did:anet:mallory", base.hub, base.ts, base.method, base.path, base.body},
		"another hub":                {base.action, base.aid, "did:anet:hub-b", base.ts, base.method, base.path, base.body},
		"another time":               {base.action, base.aid, base.hub, 1001, base.method, base.path, base.body},
		"another method":             {base.action, base.aid, base.hub, base.ts, "PUT", base.path, base.body},
		"another target":             {base.action, base.aid, base.hub, base.ts, base.method, "/relay/send?x=1", base.body},
		"another body":               {base.action, base.aid, base.hub, base.ts, base.method, base.path, `{"to_aid":"eve"}`},
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
