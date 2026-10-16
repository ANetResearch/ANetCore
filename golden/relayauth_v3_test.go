package golden

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/wire"
)

// RELAYAUTH-3 (label L22): for every relayauth action of the wire registry, the exact PreimageV2
// bytes of one request and the Ed25519 signature over them; and the retired actions are refused.
//
// The pinned preimages and signatures were computed independently of Go: relayauth3_pins in
// golden/py/gen_v016.py (Python on the cryptography package's SHA-256 and Ed25519), which
// golden/py/test_gen_v016.py compares with the literals of ra3Rows in the CI job golden-xcheck. A
// change to the prefix, a separator, the digest input, the digest's alphabet or padding, or an
// action's name fails here — and a hub and a daemon that disagree on any of those bytes lock
// every node out of its own mailbox.
//
// Signer keys: Ed25519 seeds SHA-256("anet-golden/v016/RELAYAUTH-3/agent") for the agent rows and
// SHA-256("anet-golden/v016/RELAYAUTH-3/peer-hub") for the /fed/v3 rows (a peer hub signs those).

const (
	ra3AgentAID = "bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay"
	ra3PeerAID  = "bafyreianotherhub"
	ra3HubAID   = "bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y"
	ra3TS       = 1767225600000
)

type ra3Row struct {
	action, signer, method, path, body string // body hex
	preimage, sig                      string // sig hex
}

// ra3Rows: one per action this package defines. Each action is named by its Go constant, so a
// renamed constant fails to compile here and a changed value fails the preimage.
var ra3Rows = []ra3Row{
	{relayauth.ActionPoll, "agent", "POST", "/relay/poll", "7b226c696d6974223a31307d",
		"anet-relay/v2/poll/bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/hCAMXAkVelLFbcB075tmRaNOpqET4lTzNIZwhZmLTpg",
		"6614ea6ca87b6c7aec869a198af80bf31830ee2a7f4e0eb6414891abfb8c37d153fc1fe38abf35115fc59e761bac67c45b1817c60f16ec5000b306a8d86e8a03"},
	{relayauth.ActionAck, "agent", "POST", "/relay/ack", "7b226974656d73223a5b7b226964223a317d5d7d",
		"anet-relay/v2/ack/bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/QoYTAkjSzNkpFrJimtv02SgUesqpqQbSqcG8Kgm5PhM",
		"d97a1d99fbbff16a06f5a95b494eb6293a8d3f1baa7ea6ff22f2a59b43c1cab2483d61c8beadc8d5c1ebc71b2fbc55105c6aff97010ee4bf6202267bb926510a"},
	{relayauth.ActionRegister, "agent", "POST", "/register", "7b22616964223a2262616679726569686e6e6f6f656f6d7369357769646177356f63327869697369766d7569707a616c79787862376d796271777534756a3769706179227d",
		"anet-relay/v2/register/bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/8ILGoBc13zQWURgen2XzYQMo7rKJCASSSCiWdvMTqYg",
		"ffb43a1c0783dd83cc610293c30b5fdcf62b78c544e14a06d267935867dbbb93af9df7abb3fd8d853ab581ee7fcceb0f33cd22537a2b537926c73f5c4ae0c900"},
	{relayauth.ActionProfile, "agent", "POST", "/profile", "7b2273756d6d617279223a22676f6c64656e227d",
		"anet-relay/v2/profile/bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/Gzxnffrhy_uA7f-LMHteQ-9mzsyiUjYVDRaTU2s0w_Y",
		"bd333337a427a67ce2cecc34087f3958547ad8109605953b11ffb2ba4e0734c371f53000a36689fc92e45a911b7640e27199543a8ed034da9a9b4267b0ed6903"},
	{relayauth.ActionVisibility, "agent", "POST", "/visibility", "7b2276697369626c65223a747275657d",
		"anet-relay/v2/visibility/bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/IpoCxdCc2AidoqPYVuG6mnA-liaku2VxWX-yQOkEwIA",
		"88c64e978e921143ae71e78d7210e7da229e08690bb998b0b8718ca6e712cfe38197e188a133280a9ed461b155512e162c75481d210aa4abc05fd83468b5a80d"},
	{relayauth.ActionDeregister, "agent", "POST", "/deregister", "7b7d",
		"anet-relay/v2/deregister/bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/FoqPFP7Piz5MmcU-o1fu3gHV7MZT-ioh6Q_1yq8wmuA",
		"712d616cc69c829578850148d459eb918adb6fea3132883e5c8a667ddc6c94ba025ff4a8a85831d49b23974e77a32cd15324ca5de392881a824b7701d803eb0d"},
	{relayauth.ActionBalance, "agent", "GET", "/agents/" + ra3AgentAID + "/balance", "",
		"anet-relay/v2/balance/bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/2UezxbeCQYvpmuQL_oInPJGyKFHbGJKPT2KI9QO2l9Y",
		"c3949fa11989de399638883d48d244b5d7ae681c676cf37bbeb6fb945f86f1cf2b460a822f7f7ec4d017dc9e8c58a817ea59907910413b1161affc3e2cae360a"},
	{relayauth.ActionLedger, "agent", "GET", "/agents/" + ra3AgentAID + "/ledger?limit=10", "",
		"anet-relay/v2/ledger/bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/qDfr8hVW8UzedKzgDmakEJVsfo-b72PuLHdoV2TvdZw",
		"2d422a3faef948615b36781766751e25be645e37989ba340fceffb2fc36a9acb4be67fb799d323950a8a6cf3797ff461826953cc47a2a033095661acd76d070d"},
	{relayauth.ActionRedemptions, "agent", "GET", "/agents/" + ra3AgentAID + "/redemptions?limit=500", "",
		"anet-relay/v2/redemptions/bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/Qjg1JfnE8G5d_vifB71xEkCCfx0kUjaciGF59hV5DAQ",
		"162e1044ca4b8c10d9592c5caf5b30a9fb503bad5d7288266939fc88ce453cb0458b90fbe3433a821cfaa50a62fd621fcb6a8e6d435043bd028610978fba4d01"},
	{relayauth.ActionKeys, "agent", "POST", "/agents/" + ra3AgentAID + "/keys", "7b22707265765f736571223a307d",
		"anet-relay/v2/keys/bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/76aYtUq_U_wP3OH2z0K5hoG4gAZzEYDROIF4a3PFls8",
		"ea734cba9ff2711c10db0b33b0d340c3b6a47566df4979ca45805d203820603dffb4b1b4ceb9bd9af8de592c803df146b968ed88225f7d10453479d15dc75003"},
	// Sealed sender: the first-contact session and capability revocation (agent), and the three
	// federation routes this area serves (peer hub).
	{relayauth.ActionSession, "agent", "POST", "/relay/session", "7b2265706b223a2241414141414141414141414141414141414141414141414141414141414141414141414141414141414141227d",
		"anet-relay/v2/session/bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/9jnT_UmqoguV2QxMVvVBXqB_opumBv0Ov9fzovbQng8",
		"036acf8fb99f0c7e9a0ee7ddc0fe1bda49c2def1fe5995adb2bdf843dc478d5376504e0554a71eb6c740ce40d4b332e3c004c897418fef42b5780c29f54c890b"},
	{relayauth.ActionRevoke, "agent", "POST", "/mailbox/revoke", "7b226361705f696473223a5b2241414141414141414141414141414141414141414141225d7d",
		"anet-relay/v2/revoke/bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/8iCwniFQMcKqCkCtuYw1dHb4BQ2WdZjZ26TIIbGUibM",
		"e03dda4f5a4d65f963065945c12b91bd41baac6b15961aff0e8b043182229481be6420346f65428229e78a9485a03442410048c1ffe2e357e6203d7e6d9c0107"},
	// Hub and payment privacy: the review upload and the liability proof (agent).
	{relayauth.ActionReview, "agent", "POST", "/reviews", "7b2272656365697074223a226f5145222c22726576696577223a226f5145222c227273616c74223a2241414141414141414141414141414141414141414141414141414141414141414141414141414141414141227d",
		"anet-relay/v2/review/bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/1ZMPOqrWnPG0oFXHqRFzUA4aZqjv525fWyCabYOT5WA",
		"1c3fcc895d54bb39b5c1808da7fc9b9972f17f7c15cb47518588813539ffc5e6eadea652c676fe550556f3871ec614e190264ae04942439d71f40afebee57209"},
	{relayauth.ActionLiabProof, "agent", "GET", "/agents/" + ra3AgentAID + "/liability-proof?to_day=20454", "",
		"anet-relay/v2/liab_proof/bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/dirWmXPn75gkAYw7eUB4GUhGLDDQU4EWyvPspwjNWEM",
		"179a4de2b055134f4d918d2789ed5b3536c6ad0a1116c7e6fa3e08ca7934fb1590d7a9566028b01c5179f25e92e133e51130bf7777467b04c200e6edf3576107"},
	{relayauth.ActionFedForward, "peer-hub", "POST", "/fed/v3/forward", "a60102",
		"anet-relay/v2/fed_forward/bafyreianotherhub/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/6Tqoo1hDOID93zWOkH3AMDNCzyRh4rymndO1zfO86yc",
		"306b34c8a8e1397da1ec40742eebad7c05ad318a6ef93a1c2959faede22bb1bdb73b27bdbef061a790a76fec0bdff98766bf8098d079fe4a0699f5d072df5504"},
	{relayauth.ActionFedBucket, "peer-hub", "POST", "/fed/v3/directory:bucket", "7b22707265666978223a224141222c2262697473223a387d",
		"anet-relay/v2/fed_bucket/bafyreianotherhub/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/i6Z0g0s0_N5JXBIfzMA2wPBKzanZzl1P4prPzmNrEtY",
		"145e45679729fc133929eb8015083b486e5679c39f6da734ebe5d8e48311b26ffd0d046f2c5413879c9d068111d3e88eaf6d6dfecd540e234916ce21a84e5b08"},
	{relayauth.ActionFedCards, "peer-hub", "GET", "/fed/v3/cards?cursor=0", "",
		"anet-relay/v2/fed_cards/bafyreianotherhub/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/raCoqeEz9zLlBlFAnQMJvYISRTsONrLfA9xRdoAPtVI",
		"07c29358e3cab28c0eb10bd13388652a9923226b3d726144a5f29966d940206eb3a17beaf92a87a76118326faccaa4f95c4eb41be4697b331ea25bab0d632c06"},
	// The federation routes of hub and payment privacy (peer hub).
	{relayauth.ActionFedSettle, "peer-hub", "POST", "/fed/v3/settle", "7b227834303256657273696f6e223a327d",
		"anet-relay/v2/fed_settle/bafyreianotherhub/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/QPEtLOVRuhUpXT66s0-hr0xyt5tDIra6y-Gz0BH28jk",
		"7e5120b5451f01af9c64baa7d6b01787bcd45dd389222eec470139cdfcc98d020e68ded9c8bd3c4fcee358f27232168d52f943be73e1d2bcbe2af7d830e6190a"},
	{relayauth.ActionFedReviews, "peer-hub", "GET", "/fed/v3/reviews?cursor=0", "",
		"anet-relay/v2/fed_reviews/bafyreianotherhub/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/7wVGLDMcEPsU2iotGL5X_2YF0xX20DMpNw3yTkQFfko",
		"5454a3764d2082153d7fb16d3c46ad589d52d528662c236c3a031be62023e71d8ccf25d067d7a23a2d98ae81c5a3bebc8f47dca04c8e6d4796a98ad114f64e04"},
	{relayauth.ActionFedClear, "peer-hub", "POST", "/fed/v3/clear", "7b227265636569707473223a5b5d7d",
		"anet-relay/v2/fed_clear/bafyreianotherhub/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/Emm6QsmD7tlipy4gFT6EjHBEEFOBtM0-NEsYzGSw7bE",
		"e2cfb983af964c8f6b88a3ad8d348b4c46b28f7e57210a49c3fd662946d40909229ee0de1b2156210652f81f17f89e06d97496fb2dc9476a5528bbe10f743004"},
	// Delivery tokens: the anonymous status check a hub passes on to the peer hub that queued
	// the envelopes (peer hub).
	{relayauth.ActionFedStatus, "peer-hub", "POST", "/fed/v3/relay-status", "7b226974656d73223a5b7b22726964223a2241414141414141414141414141414141414141414141222c2268616e646c65223a2241414141414141414141414141414141414141414141227d5d7d",
		"anet-relay/v2/fed_status/bafyreianotherhub/bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y/1767225600000/dWTaQ9qfoonxKm1RgHd89YQKGvE-Oy4c4pH_uf1fciM",
		"69e2399e0c40e16f858ac2cce9544f5f2d4d4aa01c6a86f18af77fdcd468ba11c4c1b4bae9807cb8322b4889023b38be34ae038d14d9397c60d466f869c20e0b"},
}

// ra3Pending: registered actions whose constant another work item adds, with that item's marker.
// The item that adds the constant moves the action into ra3Rows with its pinned bytes. Every
// registered action has its constant now, so it is empty; TestRELAYAUTH3CoversTheRegistry keeps
// the mechanism for an action registered ahead of its code.
var ra3Pending = map[string]string{}

func ra3Key(role string) (string, ed25519.PrivateKey) {
	s := sha256.Sum256([]byte("anet-golden/v016/RELAYAUTH-3/" + role))
	aid := ra3AgentAID
	if role == "peer-hub" {
		aid = ra3PeerAID
	}
	return aid, ed25519.NewKeyFromSeed(s[:])
}

func TestRELAYAUTH_3(t *testing.T) {
	for _, r := range ra3Rows {
		t.Run(r.action, func(t *testing.T) {
			if !relayauth.ValidAction(r.action) {
				t.Fatalf("%q is not a valid action", r.action)
			}
			aid, key := ra3Key(r.signer)
			body, err := hex.DecodeString(r.body)
			if err != nil {
				t.Fatal(err)
			}
			pre := relayauth.PreimageV2(r.action, aid, ra3HubAID, ra3TS, r.method, r.path, body)
			if string(pre) != r.preimage {
				t.Fatalf("the signed bytes moved:\n got  %s\n want %s", pre, r.preimage)
			}
			sig := ed25519.Sign(key, pre)
			if hex.EncodeToString(sig) != r.sig {
				t.Fatalf("signature\n got  %x\n want %s", sig, r.sig)
			}
			if !ed25519.Verify(key.Public().(ed25519.PublicKey), pre, sig) {
				t.Fatal("the pinned signature does not verify")
			}
		})
	}
}

// Every action the registry lists as active has a pinned row here, or is pending with the marker
// of the work item that adds it; every row is a registered, active action; and the retired
// actions are refused.
func TestRELAYAUTH3CoversTheRegistry(t *testing.T) {
	reg := wire.MustLoad()
	pinned := map[string]bool{}
	for _, r := range ra3Rows {
		if pinned[r.action] {
			t.Errorf("%q is pinned twice", r.action)
		}
		pinned[r.action] = true
		a := reg.Action(r.action)
		if a == nil || a.Status != wire.StatusActive {
			t.Errorf("%q is pinned but is not an active registered action", r.action)
		}
	}
	retired := 0
	for _, a := range reg.Relayauth.Actions {
		switch {
		case a.Status != wire.StatusActive:
			retired++
			if relayauth.ValidAction(a.Name) {
				t.Errorf("retired action %q is valid", a.Name)
			}
		case pinned[a.Name]:
		case ra3Pending[a.Name] != "":
			t.Run(a.Name, func(t *testing.T) {
				if relayauth.ValidAction(a.Name) {
					t.Fatalf("%q is valid now: pin its row in ra3Rows and remove it from ra3Pending", a.Name)
				}
				t.Skip(ra3Pending[a.Name])
			})
		default:
			t.Errorf("registered action %q has no RELAYAUTH-3 row", a.Name)
		}
	}
	if retired < 3 {
		t.Errorf("the registry lists %d retired actions, want send, p2p and fedkeys at least", retired)
	}
	for name := range ra3Pending {
		if a := reg.Action(name); a == nil || a.Status != wire.StatusActive {
			t.Errorf("pending %q is not an active registered action", name)
		}
	}
}

// A retired action is refused (send, p2p, fedkeys), and a signature made over a request with a
// retired action authorises no request of any action that is still valid: the action is inside
// the signed bytes.
func TestRELAYAUTH3RetiredActionsAreRefused(t *testing.T) {
	aid, key := ra3Key("agent")
	for _, retired := range []string{"send", "p2p", "fedkeys"} {
		if relayauth.ValidAction(retired) {
			t.Errorf("%q is still a valid action", retired)
		}
		for _, r := range ra3Rows {
			body, _ := hex.DecodeString(r.body)
			sig := ed25519.Sign(key, relayauth.PreimageV2(retired, aid, ra3HubAID, ra3TS, r.method, r.path, body))
			if ed25519.Verify(key.Public().(ed25519.PublicKey),
				relayauth.PreimageV2(r.action, aid, ra3HubAID, ra3TS, r.method, r.path, body), sig) {
				t.Errorf("a %q signature verifies as %q", retired, r.action)
			}
		}
	}
}
