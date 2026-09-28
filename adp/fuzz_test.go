package adp

// Fuzz targets for the ADP gossip decoder, the card pre-image and AdmitCard (ANet docs/notes/0033).
//
// FuzzParseGossip feeds gossip payloads. FuzzAdmitSigned decodes a card, signs it with the suite
// key and admits it, so AdmitCard's checks run on arbitrary field values under a good signature;
// an admitted card must bind every signed field, and its pre-image must be the RFC 8785 form the
// adp-card profile names (checked against a2acard.Canonicalize, the module's full JCS).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/a2acard"
	"github.com/ANetResearch/ANetCore/identity"
)

var fuzzMajors = SupportedMajors(SchemaMajor)

// suiteIdentityKey is the current key of identity.SuiteController() (not aobj's suite test key,
// which suiteKey returns), so a card signed with it verifies against the suite KEL.
func suiteIdentityKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(sha256Of("anet-suite-identity-v1/cur"))
}

func fuzzSeedCards(tb testing.TB) [][]byte {
	tb.Helper()
	suite := identity.SuiteController()
	base := func() *AgentCard {
		return &AgentCard{SubjectDID: suite.AID(), CardSchema: CardSchema{Major: 1}, Seq: 1767225600,
			IssuedAt: 1767225600, NotBefore: 1767225540, Capabilities: []string{"nlp/translation"},
			CriticalExtensions: []string{}, Name: "fuzz"}
	}
	var out [][]byte
	add := func(c *AgentCard) {
		if err := c.SignWithKey(suiteIdentityKey(), suite.AID(), 0); err != nil {
			tb.Fatal(err)
		}
		b, err := json.Marshal(c)
		if err != nil {
			tb.Fatal(err)
		}
		out = append(out, b)
	}
	add(base())
	c := base()
	c.Domains = []string{"bridge"}
	c.Extensions = map[string]any{"anet.pricing": map[string]any{"cap": 5}, "ratio": 0.25}
	c.Endpoints = []EndpointDesc{{Protocol: "redeem", URI: "https://x", Methods: []string{"POST"}}}
	c.Tools = []ToolDesc{{Name: "t", InputSchema: json.RawMessage(`{"type":"object"}`)}}
	add(c)
	c = base()
	c.Genome = &Genome{SpeciesCID: "bafyspecies"}
	c.DelegationProof = json.RawMessage(`{"zcap":"x"}`)
	add(c)
	c = base()
	c.Seq = 1<<53 + 1 // TestAdmitRefusesIntegersThePreimageCannotBind
	add(c)
	return out
}

func FuzzParseGossip(f *testing.F) {
	for _, c := range fuzzSeedCards(f) {
		f.Add(c)
		f.Add(append([]byte{byte(SchemaMajor)}, c...))
		env, _ := json.Marshal(map[string]any{"action": "publish", "card": json.RawMessage(c)})
		f.Add(append([]byte{0}, env...))
	}
	tb, _ := json.Marshal(GossipCardMessage{Action: "revoke", Tombstone: &CardTombstone{SubjectDID: "did:x", Seq: 2}})
	f.Add(tb)
	kel := identity.SuiteController().KEL()
	now := time.Unix(1767225600, 0)
	f.Fuzz(func(t *testing.T, payload []byte) {
		card, err := ParseGossip(payload, fuzzMajors)
		if err != nil {
			if _, ok := err.(*Error); !ok {
				t.Fatalf("ParseGossip returned a non-*Error: %v", err)
			}
			return
		}
		var env GossipCardMessage
		if json.Unmarshal(payload, &env) == nil && env.Tombstone != nil {
			_ = AdmitTombstone(env.Tombstone, 0, kel)
			_, _ = env.Tombstone.Preimage()
		}
		if card == nil {
			return
		}
		pre, perr := card.Preimage()
		_, _ = card.CardCID()
		_, _ = AdmitCard(card, now, 0, kel, fuzzMajors, nil)
		if perr != nil {
			return
		}
		// The pre-image survives the card's own JSON round trip: a hub stores and serves the
		// card as JSON, and the next reader must compute the same card_cid.
		b, err := json.Marshal(card)
		if err != nil {
			t.Fatalf("a parsed card does not encode: %v", err)
		}
		back, err := ParseGossip(b, fuzzMajors)
		if err != nil || back == nil {
			t.Fatalf("a re-encoded card does not parse: %v", err)
		}
		pre2, err := back.Preimage()
		if err != nil || !bytes.Equal(pre, pre2) {
			t.Fatalf("pre-image changed across a JSON round trip (%v):\n%s\n%s", err, pre, pre2)
		}
	})
}

func FuzzAdmitSigned(f *testing.F) {
	for _, c := range fuzzSeedCards(f) {
		f.Add(c, uint64(0), int64(60))
	}
	suite := identity.SuiteController()
	kel := suite.KEL()
	f.Fuzz(func(t *testing.T, cardJSON []byte, highWater uint64, nowOffset int64) {
		var card AgentCard
		if json.Unmarshal(cardJSON, &card) != nil {
			return
		}
		if err := card.SignWithKey(suiteIdentityKey(), suite.AID(), 0); err != nil {
			return
		}
		now := time.Unix(card.IssuedAt, 0).Add(time.Duration(nowOffset%(1<<40)) * time.Second)
		disp, err := AdmitCard(&card, now, highWater, kel, fuzzMajors, nil)
		if err != nil {
			if _, ok := err.(*Error); !ok {
				t.Fatalf("AdmitCard returned a non-*Error: %v", err)
			}
			return
		}
		if disp != DispPublished && disp != DispExpired {
			t.Fatalf("admitted with disposition %q", disp)
		}
		if card.Seq <= highWater {
			t.Fatalf("admitted seq %d at high water %d", card.Seq, highWater)
		}
		if card.Envelope.SignerAID != card.SubjectDID && len(card.DelegationProof) == 0 {
			t.Fatal("admitted a card for another subject without a delegation proof")
		}
		pre, err := card.Preimage()
		if err != nil {
			t.Fatal(err)
		}
		// The signature binds the signed fields: changing one changes the pre-image.
		for name, mutate := range map[string]func(c *AgentCard){
			"seq":        func(c *AgentCard) { c.Seq ^= 1 },
			"issued_at":  func(c *AgentCard) { c.IssuedAt ^= 1 },
			"not_before": func(c *AgentCard) { c.NotBefore ^= 1 },
			"name":       func(c *AgentCard) { c.Name += "x" },
		} {
			c2 := card
			mutate(&c2)
			if p2, err := c2.Preimage(); err == nil && bytes.Equal(p2, pre) {
				t.Fatalf("changing %s leaves the pre-image, and so the signature, unchanged (seq %d, issued_at %d, not_before %d)",
					name, card.Seq, card.IssuedAt, card.NotBefore)
			}
		}
		// The adp-card profile names RFC 8785 for the pre-image. Checked only for cards without
		// free-form JSON (extensions, tools, delegation_proof) or unbounded numbers (constraints,
		// metadata, endpoint priority): there the pre-image prints non-integers with Go's 'g'
		// format and sorts non-ASCII keys by bytes, which RFC 8785 does not (ANet
		// docs/notes/0033 §5, left for a decision).
		if card.Extensions == nil && len(card.Tools) == 0 && len(card.DelegationProof) == 0 &&
			card.Constraints == nil && card.Metadata == nil && len(card.Endpoints) == 0 {
			canon, err := a2acard.Canonicalize(pre)
			if err != nil || !bytes.Equal(canon, pre) {
				t.Fatalf("pre-image is not RFC 8785 canonical (%v):\n%s\n%s", err, pre, canon)
			}
		}
	})
}
