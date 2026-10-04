package seal

// Receive step 6½ (CheckNotice, KEL C-55) and its interplay with step 7 (VerifyInnerSig, C-54)
// across a rotation of the sender. identity/ksnvec_test.go (KSN-1) covers each step of the notice
// check itself; here the cases go through Seal and Open as a receiver sees them.

import (
	"crypto/ed25519"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
)

// DefaultRotationGrace is declared here so that the package does not compile, tests included, if
// seal declares it again: the rotation grace is identity.RotationGrace, a constant, and no longer
// a parameter of VerifyInnerSig (KEL C-57).
const DefaultRotationGrace = "removed: see identity.RotationGrace"

// VerifyInnerSig takes the arrival time and no grace (KEL C-54).
var _ func(*SealedInner, []byte, []identity.SignedEvent, uint64) error = VerifyInnerSig

// fixedSigner is an identity.Signer at one key state: the last event of kel, signed with key.
type fixedSigner struct {
	aid string
	kel []identity.SignedEvent
	key ed25519.PrivateKey
}

func (s *fixedSigner) AID() string                 { return s.aid }
func (s *fixedSigner) KEL() []identity.SignedEvent { return s.kel }
func (s *fixedSigner) Sign(pre []byte) ([]byte, uint64) {
	return ed25519.Sign(s.key, pre), s.kel[len(s.kel)-1].Event.Seq
}

func pubOfKey(k ed25519.PrivateKey) []byte { return k.Public().(ed25519.PublicKey) }

// noticeScene is a witness hub W, an agent A whose witness is W, and a recipient B.
type noticeScene struct {
	w    *identity.Controller
	a, b *party
}

func newNoticeScene(t *testing.T) *noticeScene {
	t.Helper()
	w, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	ac, err := identitytest.Agent()
	if err != nil {
		t.Fatal(err)
	}
	if err := identitytest.SwitchWitness(ac, w.AID(), t0-dayMS); err != nil {
		t.Fatal(err)
	}
	return &noticeScene{w: w, a: partyFor(t, ac), b: newParty(t)}
}

// hubs is what B holds of the hub KELs: W's.
func (s *noticeScene) hubs(aid string) ([]identity.SignedEvent, bool) {
	if aid == s.w.AID() {
		return s.w.KEL(), true
	}
	return nil, false
}

// notice is W's notice for the tip of A's KEL as it is now, observed at observedAt.
func (s *noticeScene) notice(t *testing.T, observedAt uint64) []byte {
	t.Helper()
	kel := s.a.c.KEL()
	tip := kel[len(kel)-1]
	n, err := identity.SignNotice(s.w, identity.NoticeBody{AID: s.a.aid(), Seq: tip.Event.Seq, Head: tip.EventID, ObservedAt: observedAt})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// send seals a message from A to B at ts carrying A's KEL and notice n, and opens it as B.
func (s *noticeScene) send(t *testing.T, ts uint64, n []byte) *Opened {
	t.Helper()
	in := innerFrom(t, s.a, s.b, ts)
	in.Notices = [][]byte{n}
	return mustOpen(t, mustSeal(t, in, &s.b.kp.Public, s.a.c.Sign), s.b)
}

func TestCheckNotice(t *testing.T) {
	s := newNoticeScene(t)
	observed := t0 - minuteMS
	o := s.send(t, t0, s.notice(t, observed))
	if err := CheckNotice(&o.Inner, o.KEL, s.hubs, t0); err != nil {
		t.Fatalf("a fresh notice of the witness for the tip: %v", err)
	}
	t.Run("witness-unknown is not permanent", func(t *testing.T) {
		none := func(string) ([]identity.SignedEvent, bool) { return nil, false }
		err := CheckNotice(&o.Inner, o.KEL, none, t0)
		wantReason(t, err, ReasonWitnessUnknown)
		if IsPermanent(err) {
			t.Fatal("witness-unknown must not be permanent: a refresh of the hub KEL set can change it")
		}
		wantReason(t, CheckNotice(&o.Inner, o.KEL, nil, t0), ReasonWitnessUnknown)
	})
	t.Run("witness-stale", func(t *testing.T) {
		if err := CheckNotice(&o.Inner, o.KEL, s.hubs, observed+identity.NoticeMaxAge); err != nil {
			t.Fatalf("6 h old: %v", err)
		}
		err := CheckNotice(&o.Inner, o.KEL, s.hubs, observed+identity.NoticeMaxAge+1)
		wantReason(t, err, ReasonWitnessStale)
		if !IsPermanent(err) {
			t.Fatal("witness-stale is permanent")
		}
		wantReason(t, CheckNotice(&o.Inner, o.KEL, s.hubs, observed-identity.EventClockWindow-1), ReasonWitnessStale)
	})
	t.Run("witness-mismatch", func(t *testing.T) {
		// The notice of a tip the KEL has moved past.
		old := s.notice(t, observed)
		if err := identitytest.Rotate(s.a.c, t0-dayMS/2); err != nil {
			t.Fatal(err)
		}
		s.a.resign(t, t0)
		o := s.send(t, t0, old)
		wantReason(t, CheckNotice(&o.Inner, o.KEL, s.hubs, t0), ReasonWitnessMismatch)
		o = s.send(t, t0, s.notice(t, observed))
		if err := CheckNotice(&o.Inner, o.KEL, s.hubs, t0); err != nil {
			t.Fatalf("the notice of the new tip: %v", err)
		}
	})
	t.Run("witness-invalid", func(t *testing.T) {
		// Another hub signs a notice for A's tip: A's KEL does not name it.
		other, err := identitytest.Hub()
		if err != nil {
			t.Fatal(err)
		}
		kel := s.a.c.KEL()
		tip := kel[len(kel)-1]
		n, err := identity.SignNotice(other, identity.NoticeBody{AID: s.a.aid(), Seq: tip.Event.Seq, Head: tip.EventID, ObservedAt: observed})
		if err != nil {
			t.Fatal(err)
		}
		both := func(aid string) ([]identity.SignedEvent, bool) {
			if aid == other.AID() {
				return other.KEL(), true
			}
			return s.hubs(aid)
		}
		o := s.send(t, t0, n)
		wantReason(t, CheckNotice(&o.Inner, o.KEL, both, t0), ReasonWitnessInvalid)
		// Not a notice at all.
		o = s.send(t, t0, []byte("notice"))
		wantReason(t, CheckNotice(&o.Inner, o.KEL, s.hubs, t0), ReasonWitnessInvalid)
	})
	t.Run("witness-missing", func(t *testing.T) {
		// A hub (toad 0) sends: its KEL names no witness.
		hub := newParty(t)
		in := innerFrom(t, hub, s.b, t0)
		in.Notices = [][]byte{s.notice(t, observed)}
		o := mustOpen(t, mustSeal(t, in, &s.b.kp.Public, hub.c.Sign), s.b)
		wantReason(t, CheckNotice(&o.Inner, o.KEL, s.hubs, t0), ReasonWitnessMissing)
		// An agent whose witness is pending (its icp alone) sends.
		ac, err := identitytest.Agent()
		if err != nil {
			t.Fatal(err)
		}
		pending := partyFor(t, ac)
		in = innerFrom(t, pending, s.b, t0)
		in.Notices = [][]byte{s.notice(t, observed)}
		o = mustOpen(t, mustSeal(t, in, &s.b.kp.Public, pending.c.Sign), s.b)
		wantReason(t, CheckNotice(&o.Inner, o.KEL, s.hubs, t0), ReasonWitnessMissing)
		// A message with neither KEL nor notice (only a preview frame may be one).
		in = innerFrom(t, s.a, s.b, t0)
		in.KEL, in.Notices = nil, nil
		wantReason(t, CheckNotice(in, nil, s.hubs, t0), ReasonWitnessMissing)
	})
	t.Run("inputs", func(t *testing.T) {
		wantReason(t, CheckNotice(nil, o.KEL, s.hubs, t0), ReasonInvalidInput)
		// The KEL given must be the one the message carries (KEL D-21).
		wantReason(t, CheckNotice(&o.Inner, s.a.c.KEL(), s.hubs, t0), ReasonInvalidInput)
		wantReason(t, CheckNotice(&o.Inner, nil, s.hubs, t0), ReasonInvalidInput)
		// A KEL as long as the carried one is not it either: another agent's, event for event.
		other := newNoticeScene(t).a.c.KEL()
		if len(other) != len(o.KEL) {
			t.Fatalf("setup: %d events, the carried KEL has %d", len(other), len(o.KEL))
		}
		wantReason(t, CheckNotice(&o.Inner, other, s.hubs, t0), ReasonInvalidInput)
		// Two notices: Open never gives this, CheckNotice refuses it anyway.
		two := o.Inner
		two.Notices = [][]byte{o.Notices[0], o.Notices[0]}
		wantReason(t, CheckNotice(&two, o.KEL, s.hubs, t0), ReasonWitnessInvalid)
		// A carried KEL that does not replay.
		bad := append([]identity.SignedEvent(nil), o.KEL...)
		bad[0].Sig = make([]byte, SigLen)
		b, err := identity.MarshalKEL(bad)
		if err != nil {
			t.Fatal(err)
		}
		broken := o.Inner
		broken.KEL = b
		wantReason(t, CheckNotice(&broken, bad, s.hubs, t0), ReasonBadKEL)
	})
}

// Every refusal of identity.VerifyNotice has its seal reason (KEL C-56).
func TestNoticeReasonsCoverVerifyNotice(t *testing.T) {
	want := map[error]string{
		identity.ErrNoticeMissing:        ReasonWitnessMissing,
		identity.ErrNoticeInvalid:        ReasonWitnessInvalid,
		identity.ErrNoticeMismatch:       ReasonWitnessMismatch,
		identity.ErrNoticeUnknownWitness: ReasonWitnessUnknown,
		identity.ErrNoticeStale:          ReasonWitnessStale,
	}
	if len(noticeReasons) != len(want) {
		t.Fatalf("%d mapped refusals, want %d", len(noticeReasons), len(want))
	}
	for _, m := range noticeReasons {
		if want[m.err] != m.reason {
			t.Errorf("%v maps to %q, want %q", m.err, m.reason, want[m.err])
		}
	}
	for _, r := range []string{ReasonWitnessMissing, ReasonWitnessStale, ReasonWitnessMismatch, ReasonWitnessInvalid,
		ReasonKELFromFuture} {
		if !(&Error{Reason: r}).Permanent() {
			t.Errorf("%s is not permanent", r)
		}
	}
	if (&Error{Reason: ReasonWitnessUnknown}).Permanent() {
		t.Error("witness-unknown is permanent")
	}
}

// A message A sealed before rotating, carrying the KEL and the notice of its time, reaches B after
// B merged the rotation (KEL D-21, D-22; §7.3 M10, M13, M40).
func TestNoticeAndSignatureAcrossARotation(t *testing.T) {
	const rot = t0 + 10*minuteMS
	for _, emergency := range []bool{false, true} {
		name := "planned"
		if emergency {
			name = "emergency"
		}
		t.Run(name, func(t *testing.T) {
			s := newNoticeScene(t)
			o := s.send(t, t0, s.notice(t, t0-minuteMS))
			rotate := identitytest.Rotate
			if emergency {
				rotate = identitytest.RotateEmergency
			}
			if err := rotate(s.a.c, rot); err != nil {
				t.Fatal(err)
			}
			merged := s.a.c.KEL()
			if identity.MergedEmergency(o.KEL, merged) != emergency {
				t.Fatalf("MergedEmergency = %v", !emergency)
			}
			arrival := rot + 30*minuteMS
			// Step 6½ judges the notice against the carried KEL, so it still confirms it.
			if err := CheckNotice(&o.Inner, o.KEL, s.hubs, arrival); err != nil {
				t.Fatalf("the notice of the message's time: %v", err)
			}
			// It does not take the merged KEL for the carried one.
			wantReason(t, CheckNotice(&o.Inner, merged, s.hubs, arrival), ReasonInvalidInput)
			// Step 7 judges the signature under the merged KEL: inside the planned grace it is
			// accepted, after an emergency rotation never, whatever the hub says the arrival was.
			err := VerifyInnerSig(&o.Inner, o.Preimage, merged, arrival)
			if !emergency {
				if err != nil {
					t.Fatalf("inside the grace: %v", err)
				}
				wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, merged, rot+identity.RotationGrace+1), ReasonGraceExpired)
				return
			}
			wantReason(t, err, ReasonRevokedKey)
			wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, merged, rot-1), ReasonRevokedKey)
			if !IsPermanent(err) {
				t.Fatal("revoked-key is permanent")
			}
		})
	}
}
