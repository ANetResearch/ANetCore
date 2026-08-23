package ael

import (
	"errors"
	"fmt"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// A head attestation is one party's signed record of what another party's
// chain looked like at a moment.
//
// An AEL is fork-evident: a reader who holds record N can later show that
// record N has changed. It is not fork-preventing, and it offers a fresh
// reader nothing about the past — a chain that has never been observed
// can be presented in any form its owner likes.
//
// An attestation closes that gap for anyone who trusts the witness. The
// witness signs "at time T, this chain's head was record N with id X".
// If the chain later shows a different record at N, the two signed
// statements together prove the chain owner rewrote its history: one
// signed by the owner, one by the witness.
//
// The trust requirement changes shape rather than disappearing. Instead
// of trusting the chain's owner, a reader trusts that the owner and every
// witness did not collude. That is a weaker assumption when the witnesses
// are parties with no reason to help — a peer hub with its own users, or
// an agent whose balance is at stake.
type HeadAttestation struct {
	// ChainDID is whose chain was observed.
	ChainDID string `cbor:"1,keyasint"`
	// Seq and HeadID are the head at the moment of observation. Both,
	// because either alone is insufficient: a sequence number without an
	// id says nothing about content, and an id without a sequence cannot
	// be located in the chain to compare against.
	Seq    uint64 `cbor:"2,keyasint"`
	HeadID string `cbor:"3,keyasint"`
	// ObservedAt is when the witness looked, in unix millis. It is the
	// witness's own clock and is worth exactly what the witness is worth;
	// it orders that witness's own observations and nothing more.
	ObservedAt int64 `cbor:"4,keyasint"`
	// Envelope is the witness's detached signature.
	Envelope *aobj.Envelope `cbor:"-"`
}

type attestationPreimage struct {
	ChainDID   string `cbor:"1,keyasint"`
	Seq        uint64 `cbor:"2,keyasint"`
	HeadID     string `cbor:"3,keyasint"`
	ObservedAt int64  `cbor:"4,keyasint"`
}

func (a *HeadAttestation) canonical() attestationPreimage {
	return attestationPreimage{ChainDID: a.ChainDID, Seq: a.Seq,
		HeadID: a.HeadID, ObservedAt: a.ObservedAt}
}

// CanonicalPreimage returns the CoreDet-CBOR signing preimage.
func (a *HeadAttestation) CanonicalPreimage() ([]byte, error) {
	return coredet.Marshal(a.canonical())
}

// ID is the content identifier over the preimage.
func (a *HeadAttestation) ID() (string, error) {
	pre, err := a.CanonicalPreimage()
	if err != nil {
		return "", err
	}
	return anetcid.Sum(pre)
}

// WitnessAID is who signed this attestation, or empty if unsigned.
func (a *HeadAttestation) WitnessAID() string {
	if a.Envelope == nil {
		return ""
	}
	return a.Envelope.SignerAID
}

// Sign attaches the witness's signature.
//
// A witness must not sign an observation of its own chain. Such an
// attestation carries no information — the chain's owner asserting its
// own head is what the chain already does — and publishing one alongside
// genuine attestations would pad a witness list with self-reference.
func (a *HeadAttestation) Sign(c *identity.Controller) error {
	if a.ChainDID == c.AID() {
		return errors.New("ael: a chain cannot witness itself")
	}
	if a.HeadID == "" || a.Seq == 0 {
		return errors.New("ael: an attestation must name a head")
	}
	pre, err := a.CanonicalPreimage()
	if err != nil {
		return err
	}
	sig, seq := c.Sign(pre)
	a.Envelope = &aobj.Envelope{SignerAID: c.AID(), KeyStateSeq: seq,
		Alg: aobj.AlgEdDSA, Sig: sig}
	return nil
}

// Verify checks the witness signature against the witness's key history.
//
// expectWitness pins who is supposed to have signed. Without it, a
// verifier would accept an attestation from anyone and a chain owner
// could supply attestations signed by keys it controls. Passing the
// witness one already trusts is what makes this a check rather than a
// signature test.
func (a *HeadAttestation) Verify(kel []identity.SignedEvent, expectWitness string, now int64) error {
	if a.Envelope == nil {
		return errors.New("ael: unsigned attestation")
	}
	if err := a.Envelope.Validate(); err != nil {
		return err
	}
	if expectWitness != "" && a.Envelope.SignerAID != expectWitness {
		return fmt.Errorf("ael: attestation signed by %s, not the expected witness %s",
			a.Envelope.SignerAID, expectWitness)
	}
	if a.Envelope.SignerAID == a.ChainDID {
		return errors.New("ael: a chain cannot witness itself")
	}
	pre, err := a.CanonicalPreimage()
	if err != nil {
		return err
	}
	return identity.VerifyObject(kel, a.Envelope.SignerAID, a.Envelope.KeyStateSeq,
		uint64(now), pre, a.Envelope.Sig)
}

type wireAttestation struct {
	Body     attestationPreimage `cbor:"1,keyasint"`
	Envelope *aobj.Envelope      `cbor:"2,keyasint"`
}

// Marshal encodes the attestation with its detached signature.
func (a *HeadAttestation) Marshal() ([]byte, error) {
	return coredet.Marshal(wireAttestation{Body: a.canonical(), Envelope: a.Envelope})
}

// UnmarshalHeadAttestation decodes a wire attestation.
func UnmarshalHeadAttestation(b []byte) (*HeadAttestation, error) {
	var w wireAttestation
	if err := coredet.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	return &HeadAttestation{
		ChainDID: w.Body.ChainDID, Seq: w.Body.Seq, HeadID: w.Body.HeadID,
		ObservedAt: w.Body.ObservedAt, Envelope: w.Envelope,
	}, nil
}

// ContradictedBy reports whether a chain record contradicts this
// attestation: same chain, same sequence, different id.
//
// This is the whole point of holding attestations. The two objects
// together are a proof that does not depend on either party agreeing:
// the record is signed by the chain owner, the attestation by the
// witness, and both name the same position in the same chain with
// different contents.
func (a *HeadAttestation) ContradictedBy(r *EventRecord) bool {
	if r == nil || r.ChainDID != a.ChainDID || r.Seq != a.Seq {
		return false
	}
	return r.ID != a.HeadID
}
