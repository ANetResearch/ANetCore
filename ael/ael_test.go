package ael

import (
	"encoding/hex"
	"testing"

	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/identity"
)

// VEC-AEL-GENESIS-1 (evidence-spec §6.1): GENESIS_PREV literal is frozen.
func TestGenesisPrev(t *testing.T) {
	const want = "bafyreifi23d3grw75bm2ox7ssj3fq3mrtwxyb646ojzabakucfpf527clm"
	if GenesisPrev() != want {
		t.Fatalf("GENESIS_PREV\n got  %s\n want %s", GenesisPrev(), want)
	}
}

// EV-1 / VEC-AEL-CID-1 / VEC-AEL-CHAIN-1 (evidence-spec §6.1): the seq=0 genesis id.
func TestVEC_AEL_CID_1(t *testing.T) {
	r := &EventRecord{
		ChainDID: "did:key:zChain1", Seq: 0, PrevID: GenesisPrev(),
		EventType: EvGenesis, VersionMajor: VersionMajor2,
		Payload:   map[uint64]any{1: "did:key:zChain1", 2: uint64(1), 3: int64(1700000000000)},
		Timestamp: 1700000000000,
		SignerAID: "did:key:zChain1", KeyStateSeq: 0,
	}
	const want = "bafyreihl55yezde3kqf2tudcvavg5oasqadedkadyeqal5ha2oqrpiageu"
	got, err := r.ComputeID()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("EV-1 id\n got  %s\n want %s", got, want)
	}
}

// EV-2 / VEC-AEL-CHAIN-2 (evidence-spec §6.1): the seq=1..3 id chain + final head.
func TestVEC_AEL_CHAIN_2(t *testing.T) {
	genesis := &EventRecord{
		ChainDID: "did:key:zChain1", Seq: 0, PrevID: GenesisPrev(), EventType: EvGenesis,
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "did:key:zChain1", 2: uint64(1), 3: int64(1700000000000)},
		Timestamp: 1700000000000, SignerAID: "did:key:zChain1", KeyStateSeq: 0,
	}
	prev, _ := genesis.ComputeID()
	steps := []struct {
		etype, status, want string
	}{
		{"commitment.update", "started", "bafyreibib5dgpluc4jfh3mz3rrqunqlrgvjrd65pmxtvcdsbcaqc5owycq"},
		{"commitment.update", "progress", "bafyreifjsxrg4qp4pv6w7p2p2algjryip2i7tmf7tcohylu6lp2wfually"},
		{"commitment.done", "done", "bafyreifd5mrqxp35mrqntlp25ockey6qcivx33zglzrkbdwf6u5lyp7rci"},
	}
	for i, s := range steps {
		seq := uint64(i + 1)
		r := &EventRecord{
			ChainDID: "did:key:zChain1", Seq: seq, PrevID: prev, EventType: s.etype,
			VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "task:t1", 2: s.status},
			Timestamp: int64(1700000000000 + seq), SignerAID: "did:key:zChain1", KeyStateSeq: 0,
		}
		got, err := r.ComputeID()
		if err != nil {
			t.Fatal(err)
		}
		if got != s.want {
			t.Fatalf("seq=%d id\n got  %s\n want %s", seq, got, s.want)
		}
		prev = got
	}
	if prev != "bafyreifd5mrqxp35mrqntlp25ockey6qcivx33zglzrkbdwf6u5lyp7rci" {
		t.Fatalf("final head id = %s", prev)
	}
}

// Ledger append + verify-before-store + chain linkage, with a real did:anet signer.
func TestLedgerAppendChain(t *testing.T) {
	c, _ := identity.Incept()
	l := NewLedger()
	gen := &EventRecord{
		ChainDID: c.AID(), Seq: 0, PrevID: GenesisPrev(), EventType: EvGenesis,
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "init"}, Timestamp: 1700000000000,
	}
	if err := gen.Sign(c); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(gen, c.KEL()); err != nil {
		t.Fatalf("append genesis: %v", err)
	}
	if l.State(c.AID()) != ChainActive {
		t.Fatalf("state = %s", l.State(c.AID()))
	}
	headID, headSeq, _ := l.Head(c.AID())
	if headSeq != 0 {
		t.Fatalf("head seq after genesis = %d, want 0", headSeq)
	}
	next := &EventRecord{
		// chain from the reported head rather than a hard-coded 1, so a
		// wrong head advance fails here instead of passing silently
		ChainDID: c.AID(), Seq: headSeq + 1, PrevID: headID, EventType: "commitment.update",
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "step"}, Timestamp: 1700000000001,
	}
	if err := next.Sign(c); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(next, c.KEL()); err != nil {
		t.Fatalf("append seq1: %v", err)
	}
	_, headSeq, _ = l.Head(c.AID())
	if headSeq != 1 {
		t.Fatalf("head seq = %d", headSeq)
	}
	// tampering after sign breaks verify-before-store.
	bad := &EventRecord{ChainDID: c.AID(), Seq: 2, PrevID: next.ID, EventType: "x",
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "y"}, Timestamp: 1700000000002}
	_ = bad.Sign(c)
	bad.Payload = map[uint64]any{1: "TAMPERED"} // mutate after sign → id no longer re-derives
	if err := l.Append(bad, c.KEL()); err == nil {
		t.Fatal("tampered record must fail verify-before-store")
	}
}

// Fork-trap: two distinct records at one (chain_did, seq) ⇒ EquivocationProof + sticky quarantine.
func TestLedgerEquivocationQuarantine(t *testing.T) {
	c, _ := identity.Incept()
	l := NewLedger()
	gen := &EventRecord{ChainDID: c.AID(), Seq: 0, PrevID: GenesisPrev(), EventType: EvGenesis,
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "init"}, Timestamp: 1700000000000}
	_ = gen.Sign(c)
	if err := l.Append(gen, c.KEL()); err != nil {
		t.Fatal(err)
	}
	gid, _, _ := l.Head(c.AID())
	a := &EventRecord{ChainDID: c.AID(), Seq: 1, PrevID: gid, EventType: "commitment.update",
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "A"}, Timestamp: 1700000000001}
	b := &EventRecord{ChainDID: c.AID(), Seq: 1, PrevID: gid, EventType: "commitment.update",
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "B"}, Timestamp: 1700000000001}
	_ = a.Sign(c)
	_ = b.Sign(c)
	if err := l.Append(a, c.KEL()); err != nil {
		t.Fatalf("append A: %v", err)
	}
	err := l.Append(b, c.KEL()) // competing seq=1
	ep, ok := err.(*EquivocationProof)
	if !ok {
		t.Fatalf("want EquivocationProof, got %v", err)
	}
	if ep.Seq != 1 || ep.NodeA.ID == ep.NodeB.ID {
		t.Fatalf("bad proof: %+v", ep)
	}
	if l.State(c.AID()) != ChainQuarantined {
		t.Fatal("chain must be sticky QUARANTINED after equivocation")
	}
	// further appends rejected on a quarantined chain.
	if err := l.Append(a, c.KEL()); err == nil {
		t.Fatal("append to quarantined chain must fail")
	}
}

// EV-1 suite-key SIGNATURE vector (evidence-spec §6.1): SuiteSign over the EV-1 preimage MUST
// reproduce the pinned sig_hex byte-for-byte (Ed25519 is deterministic, RFC 8032), and the
// signature MUST verify against the suite public key.
func TestVEC_AEL_EV1_Signature(t *testing.T) {
	r := &EventRecord{
		ChainDID: "did:key:zChain1", Seq: 0, PrevID: GenesisPrev(),
		EventType: EvGenesis, VersionMajor: VersionMajor2,
		Payload:   map[uint64]any{1: "did:key:zChain1", 2: uint64(1), 3: int64(1700000000000)},
		Timestamp: 1700000000000,
		SignerAID: "did:key:zChain1", KeyStateSeq: 0,
	}
	pre, err := r.Preimage()
	if err != nil {
		t.Fatal(err)
	}
	const wantSig = "2a5aea579409a746aaa271c67230f48fcd1660b59c3b85c1b9ce14aed2fccbeaab00f6836f6d0fd1a164e7c5f193c840fa4c2d3e1dc61fe0a4c1cbc8b3049d05"
	sig := aobj.SuiteSign(pre)
	if got := hex.EncodeToString(sig); got != wantSig {
		t.Fatalf("EV-1 sig_hex\n got  %s\n want %s", got, wantSig)
	}
	if err := aobj.Verify(aobj.SuitePub, pre, sig); err != nil {
		t.Fatalf("EV-1 signature must verify under the suite key: %v", err)
	}
}

// F1: the sticky-quarantine guard runs FIRST in Append — before verify. A broken-signature
// append to an already-quarantined chain returns CHAIN_QUARANTINED, NOT INVALID_SIGNATURE.
func TestQuarantineGuardFirst(t *testing.T) {
	c, _ := identity.Incept()
	l := NewLedger()
	gen := &EventRecord{ChainDID: c.AID(), Seq: 0, PrevID: GenesisPrev(), EventType: EvGenesis,
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "init"}, Timestamp: 1700000000000}
	_ = gen.Sign(c)
	if err := l.Append(gen, c.KEL()); err != nil {
		t.Fatal(err)
	}
	gid, _, _ := l.Head(c.AID())
	a := &EventRecord{ChainDID: c.AID(), Seq: 1, PrevID: gid, EventType: "commitment.update",
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "A"}, Timestamp: 1700000000001}
	b := &EventRecord{ChainDID: c.AID(), Seq: 1, PrevID: gid, EventType: "commitment.update",
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "B"}, Timestamp: 1700000000001}
	_ = a.Sign(c)
	_ = b.Sign(c)
	_ = l.Append(a, c.KEL())
	if _, ok := l.Append(b, c.KEL()).(*EquivocationProof); !ok {
		t.Fatal("expected equivocation to quarantine the chain")
	}
	// Now craft a record with a BROKEN signature for a later seq. The sticky guard must win.
	broken := &EventRecord{ChainDID: c.AID(), Seq: 2, PrevID: a.ID, EventType: "x",
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "y"}, Timestamp: 1700000000002}
	_ = broken.Sign(c)
	broken.Payload = map[uint64]any{1: "TAMPERED"} // would normally fail verify (ID_MISMATCH)
	err := l.Append(broken, c.KEL())
	if !IsCode(err, CHAIN_QUARANTINED) {
		t.Fatalf("F1: want CHAIN_QUARANTINED (guard before verify), got %v", err)
	}
}

// F2: a non-MAJOR-2 record is rejected by the version gate (VERSION_UNSUPPORTED) before it is
// ever hashed/verified as MAJOR-2.
func TestWrongMajorRejected(t *testing.T) {
	c, _ := identity.Incept()
	l := NewLedger()
	r := &EventRecord{ChainDID: c.AID(), Seq: 0, PrevID: GenesisPrev(), EventType: EvGenesis,
		VersionMajor: 1, Payload: map[uint64]any{1: "init"}, Timestamp: 1700000000000}
	_ = r.Sign(c)
	err := l.Append(r, c.KEL())
	if !IsCode(err, VERSION_UNSUPPORTED) {
		t.Fatalf("F2: want VERSION_UNSUPPORTED, got %v", err)
	}
	if l.State(c.AID()) != "" {
		t.Fatal("F2: a wrong-MAJOR record must not create a chain")
	}
}

// F3: the revocation gate is as-of the record's timestamp. A record signed under the retiring
// seq0 key but time-stamped AFTER the rotation → REVOKED_KEY (msgTime=0 used to disable this).
func TestRevokedKeyImport(t *testing.T) {
	c, _ := identity.Incept()
	l := NewLedger()
	// genesis under seq0, time-stamped before any rotation.
	gen := &EventRecord{ChainDID: c.AID(), Seq: 0, PrevID: GenesisPrev(), EventType: EvGenesis,
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "init"}, Timestamp: 1000}
	_ = gen.Sign(c) // signs under key_state_seq 0
	if err := l.Append(gen, c.KEL()); err != nil {
		t.Fatalf("genesis append: %v", err)
	}
	// craft a seq1 record signed under the seq0 key, time-stamped AFTER the rotation at T=5000.
	gid, _, _ := l.Head(c.AID())
	bad := &EventRecord{ChainDID: c.AID(), Seq: 1, PrevID: gid, EventType: "commitment.update",
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "x"}, Timestamp: 6000}
	_ = bad.Sign(c) // still key_state_seq 0
	// rotate the controller at T=5000 — seq0 is now retired as-of 5000 < bad.Timestamp(6000).
	if err := c.Rotate(5000); err != nil {
		t.Fatal(err)
	}
	err := l.Append(bad, c.KEL())
	if !IsCode(err, REVOKED_KEY) {
		t.Fatalf("F3: want REVOKED_KEY (seq0 retired before the record ts), got %v", err)
	}
}

// F5: an out-of-order future-seq record STAGES (no SEQ_GAP); when the gap fills it drains
// contiguously and the head advances.
func TestOutOfOrderStaging(t *testing.T) {
	c, _ := identity.Incept()
	l := NewLedger()
	gen := &EventRecord{ChainDID: c.AID(), Seq: 0, PrevID: GenesisPrev(), EventType: EvGenesis,
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "init"}, Timestamp: 1000}
	_ = gen.Sign(c)
	if err := l.Append(gen, c.KEL()); err != nil {
		t.Fatal(err)
	}
	gid, _, _ := l.Head(c.AID())
	seq1 := &EventRecord{ChainDID: c.AID(), Seq: 1, PrevID: gid, EventType: "commitment.update",
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "1"}, Timestamp: 1001}
	_ = seq1.Sign(c)
	seq2 := &EventRecord{ChainDID: c.AID(), Seq: 2, PrevID: seq1.ID, EventType: "commitment.update",
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "2"}, Timestamp: 1002}
	_ = seq2.Sign(c)
	// Deliver seq2 FIRST (future-seq): must STAGE, not fail, and not advance the head.
	if err := l.Append(seq2, c.KEL()); err != nil {
		t.Fatalf("F5: out-of-order seq2 must stage, got %v", err)
	}
	if _, hs, _ := l.Head(c.AID()); hs != 0 {
		t.Fatalf("F5: head must stay at 0 while seq2 is staged, got %d", hs)
	}
	// Now deliver seq1: the gap fills → seq1 applies AND seq2 drains contiguously → head = 2.
	if err := l.Append(seq1, c.KEL()); err != nil {
		t.Fatalf("F5: seq1 append: %v", err)
	}
	if _, hs, _ := l.Head(c.AID()); hs != 2 {
		t.Fatalf("F5: head must drain to 2 after the gap fills, got %d", hs)
	}
}

// F6: equivocation persists BOTH records and appends a converge.fork_detected anchor, sets
// sticky QUARANTINED, and still returns the *EquivocationProof.
func TestEquivocationPersistsBothAndForkEvent(t *testing.T) {
	c, _ := identity.Incept()
	l := NewLedger()
	gen := &EventRecord{ChainDID: c.AID(), Seq: 0, PrevID: GenesisPrev(), EventType: EvGenesis,
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "init"}, Timestamp: 1000}
	_ = gen.Sign(c)
	if err := l.Append(gen, c.KEL()); err != nil {
		t.Fatal(err)
	}
	gid, _, _ := l.Head(c.AID())
	a := &EventRecord{ChainDID: c.AID(), Seq: 1, PrevID: gid, EventType: "commitment.update",
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "A"}, Timestamp: 1001}
	b := &EventRecord{ChainDID: c.AID(), Seq: 1, PrevID: gid, EventType: "commitment.update",
		VersionMajor: VersionMajor2, Payload: map[uint64]any{1: "B"}, Timestamp: 1001}
	_ = a.Sign(c)
	_ = b.Sign(c)
	_ = l.Append(a, c.KEL())
	ep, ok := l.Append(b, c.KEL()).(*EquivocationProof)
	if !ok {
		t.Fatal("F6: expected *EquivocationProof")
	}
	if ep.NodeA.ID != a.ID || ep.NodeB.ID != b.ID {
		t.Fatal("F6: proof must carry both records")
	}
	if l.State(c.AID()) != ChainQuarantined {
		t.Fatal("F6: chain must be sticky QUARANTINED")
	}
	// both equivocating records persisted + a fork_detected anchor.
	evs := l.Events(c.AID())
	var haveA, haveB, haveFork bool
	for _, e := range evs {
		switch {
		case e.EventType == EvForkDetected:
			haveFork = true
		case e.ID == a.ID:
			haveA = true
		case e.ID == b.ID:
			haveB = true
		}
	}
	if !haveA || !haveB {
		t.Fatalf("F6: both records must be persisted (A=%v B=%v)", haveA, haveB)
	}
	if !haveFork {
		t.Fatal("F6: a converge.fork_detected anchor must be appended")
	}
}
