package seal

// Delivery tokens (DLV §2.1, §2.2, §2.6.1, §4.1; core §2.7, §2.15.2, §3.2 L12-L14,
// CORE-K11, K19, K21, K22).
//
// "Delivered" is said only by the recipient. Seal and Open give both ends the same ack_key, the
// layer-1 HPKE export (envelope.go). When the recipient has decided an envelope for good, it
// answers with a dack, 80 bytes:
//
//	tok(o)  16  HMAC-SHA256(ack_key, "anet-dack-tok/v1" ‖ u8(o))[0:16], o = 1 processed, 2 refused
//	note    64  nonce (12) ‖ ChaCha20-Poly1305(note_key, nonce, pt, aad = tok(o)) (52)
//
// with note_key = HMAC-SHA256(ack_key, "anet-dack-note/v1") and a 36-byte note plaintext: the
// format 0x01, retry_after (seconds, big-endian u32, at most MaxRetryAfterS), the reason's length
// L (0 to MaxNoteReasonLen) and the reason, zero-padded to 30 bytes. The handle the sender asks a
// hub about is HMAC-SHA256(ack_key, "anet-dack-handle/v1")[0:16].
//
// Only the two ends can compute any of these, so a hub, an anetpeer or anything on the path can
// hold a dack back but cannot make one, neither "processed" nor "refused". A dack is the same
// length whatever its outcome and reason, and the note is encrypted, so the outcome is not on
// the wire in the clear. A token is an HMAC, not a signature: either end could have made it, so
// it proves nothing to a third party, and it is not evidence.
//
// Nothing here does I/O or reads a clock (DLV-C-5, CORE-A4): the only input from outside is the
// note's nonce, drawn from crypto/rand by MakeDAck, and RetryBucket takes the time as an
// argument. The imports are kept to crypto packages, encoding/binary and errors, which a test
// checks.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Sizes of the delivery-token objects (core §2.7). DAckLen equals module.DAckLen in ANet
// (CORE-K11).
const (
	// HandleLen is the length of the handle a sender queries a hub with.
	HandleLen = 16
	// TokenLen is the length of tok(o).
	TokenLen = 16
	// NoteLen is the length of the encrypted note: nonce, ciphertext and tag.
	NoteLen = 64
	// DAckLen is the length of a dack, whatever its outcome and note.
	DAckLen = TokenLen + NoteLen

	// MaxNoteReasonLen is the longest reason code a note holds (CORE-K19).
	MaxNoteReasonLen = 30
	// MaxRetryAfterS bounds a note's retry_after: MakeDAck writes at most this, and VerifyDAck
	// reads a larger value as this (DLV-W-7).
	MaxRetryAfterS = 86_400
)

// The labels of core §3.2 L12-L14.
const (
	dackHandleLabel = "anet-dack-handle/v1"
	dackTokLabel    = "anet-dack-tok/v1"
	dackNoteLabel   = "anet-dack-note/v1"
)

// The note plaintext: format (1), retry_after (4), L (1), reason (MaxNoteReasonLen).
const (
	noteFormat   = 0x01
	notePTLen    = 1 + 4 + 1 + MaxNoteReasonLen
	noteNonceLen = chacha20poly1305.NonceSize
)

// Outcome is the recipient's final decision on an envelope, the o of tok(o).
type Outcome uint8

const (
	// OutcomeProcessed: the envelope was taken (stored and acted on, or a duplicate of one that
	// was). Its note is empty.
	OutcomeProcessed Outcome = 1
	// OutcomeRefused: the envelope was refused for good. Its note may say why and when to retry.
	OutcomeRefused Outcome = 2
)

// Note is the content of a dack's note: why a refused envelope was refused, and how long the
// sender should wait before trying again. The zero Note is the empty note, the only one a
// processed token carries; a refused token with the empty reason is shown as "refused".
type Note struct {
	// Reason is "" or a reason code: [a-z][a-z0-9_]*, at most MaxNoteReasonLen bytes
	// (CORE-K19). The codes of core §2.15.2 are the Note* constants; a verifier keeps another
	// well-formed code as it is (DLV-W-8).
	Reason string
	// RetryAfterS is the wait in seconds, 0 for none; RetryBucket rounds it.
	RetryAfterS uint32
}

// The note reason codes (core §2.15.2), one constant per code. The set is the registry's
// reasons.note, row for row (DLV-C-7; TestWireRegistry). sandbox_unavailable, budget and
// provider_policy are decided after the recipient took the message and travel in a status
// message, so they are not note codes (CORE-K21).
//
//anet:wire reasons.note complete
const (
	// The recipient's policy: no reason to retry.
	NoteNotAccepting        = "not_accepting"
	NoteDenied              = "denied"
	NoteCapabilityNotPublic = "capability_not_public"
	NotePendingFull         = "pending_full"

	// Load: with a retry_after, rounded by RetryBucket. caller_busy is always 5 seconds;
	// quota_caller_per_day waits for the next UTC day (RetryBucket's dayWindow).
	NoteBusy              = "busy"
	NoteCallerBusy        = "caller_busy"
	NoteQuotaCallerPerMin = "quota_caller_per_min"
	NoteQuotaCallerPerDay = "quota_caller_per_day"

	// The request does not fit what the capability accepts.
	NoteArgsTooLarge        = "args_too_large"
	NoteFilesCount          = "files_count"
	NoteFilesTooLarge       = "files_too_large"
	NoteFileTypeNotAccepted = "file_type_not_accepted"
	NoteBadRequest          = "bad_request"

	// The sender's key state could not be checked or is not acceptable.
	NoteKeyState = "key_state"

	// The delivery itself: the task was canceled or is unknown or over, or the message was
	// invalid.
	NoteCanceled     = "canceled"
	NoteTaskNotFound = "task_not_found"
	NoteTaskEnded    = "task_ended"
	NoteInvalid      = "invalid"
)

// errZeroAckKey refuses the zero ack_key. No export is zero; the zero value is what Seal returns
// with an error and AckKeyOf returns without a key, and a token under it is a token anyone can
// make.
var errZeroAckKey = errors.New("the zero ack_key is not an envelope's: was AckKeyOf's ok, or Seal's error, ignored?")

// isZero reports whether k is the zero AckKey.
func (k *AckKey) isZero() bool {
	var zero AckKey
	return subtle.ConstantTimeCompare(k[:], zero[:]) == 1
}

// mac is HMAC-SHA256(ack_key, label ‖ extra).
func (k *AckKey) mac(label string, extra ...byte) []byte {
	m := hmac.New(sha256.New, k[:])
	m.Write([]byte(label))
	m.Write(extra)
	return m.Sum(nil)
}

// Handle returns the handle of the envelope k belongs to (L12): the name a recipient files the
// dack under at a hub, and a sender queries the hub with. It is not a token.
func (k AckKey) Handle() [HandleLen]byte {
	var h [HandleLen]byte
	copy(h[:], k.mac(dackHandleLabel))
	return h
}

// token is tok(o) (L13). The outcome byte is part of the MAC, so tok(1) and tok(2) are unrelated.
func (k *AckKey) token(o Outcome) [TokenLen]byte {
	var t [TokenLen]byte
	copy(t[:], k.mac(dackTokLabel, byte(o)))
	return t
}

// noteKey is note_key (L14).
func (k *AckKey) noteKey() []byte { return k.mac(dackNoteLabel) }

// MakeDAck returns the dack of outcome o with note n (DLV-C-3): tok(o) and the note, sealed under
// a fresh random nonce. It refuses, with a *Error of reason invalid-input, an outcome other than
// OutcomeProcessed and OutcomeRefused, a reason that is not "" or a reason code (CORE-K19: it is
// never cut or rewritten), a processed token with a non-empty note (DLV-W-5), and the zero
// ack_key. A RetryAfterS above MaxRetryAfterS is written as MaxRetryAfterS.
func (k AckKey) MakeDAck(o Outcome, n Note) ([DAckLen]byte, error) {
	var nonce [noteNonceLen]byte
	// crypto/rand.Read does not return an error since Go 1.24; on failure of the system
	// source it terminates the program.
	_, _ = rand.Read(nonce[:])
	return k.makeDAck(o, n, nonce)
}

// makeDAck is MakeDAck with the note's nonce given, so that a golden vector can fix it.
func (k *AckKey) makeDAck(o Outcome, n Note, nonce [noteNonceLen]byte) ([DAckLen]byte, error) {
	var d [DAckLen]byte
	switch {
	case o != OutcomeProcessed && o != OutcomeRefused:
		return d, fail(ReasonInvalidInput, "outcome %d is neither processed (1) nor refused (2)", o)
	case n.Reason != "" && !ValidNoteReason(n.Reason):
		return d, fail(ReasonInvalidInput, "note reason %q is not a reason code: [a-z][a-z0-9_]*, at most %d bytes (CORE-K19)", n.Reason, MaxNoteReasonLen)
	case o == OutcomeProcessed && n != (Note{}):
		return d, fail(ReasonInvalidInput, "a processed token carries the empty note, not %+v (DLV-W-5)", n)
	case k.isZero():
		return d, failWrap(ReasonInvalidInput, errZeroAckKey, "")
	}
	pt := encodeNotePT(n)
	aead, err := chacha20poly1305.New(k.noteKey())
	if err != nil {
		return d, failWrap(ReasonInternalError, err, "note key")
	}
	tok := k.token(o)
	ct := aead.Seal(nil, nonce[:], pt[:], tok[:])
	if len(ct) != NoteLen-noteNonceLen {
		return d, fail(ReasonInternalError, "note ciphertext of %d bytes", len(ct))
	}
	copy(d[:TokenLen], tok[:])
	copy(d[TokenLen:], nonce[:])
	copy(d[TokenLen+noteNonceLen:], ct)
	return d, nil
}

// encodeNotePT is the note plaintext of n. n.Reason is "" or valid.
func encodeNotePT(n Note) [notePTLen]byte {
	var pt [notePTLen]byte
	pt[0] = noteFormat
	binary.BigEndian.PutUint32(pt[1:5], min(n.RetryAfterS, MaxRetryAfterS))
	pt[5] = byte(len(n.Reason))
	copy(pt[6:], n.Reason)
	return pt
}

// decodeNotePT reads a note plaintext (DLV-W-7): the format is 0x01, L is at most
// MaxNoteReasonLen, a non-empty reason is a reason code, and every byte after the reason is
// zero; otherwise ok is false. A retry_after above MaxRetryAfterS reads as MaxRetryAfterS.
func decodeNotePT(pt []byte) (n Note, ok bool) {
	if len(pt) != notePTLen || pt[0] != noteFormat {
		return Note{}, false
	}
	l := int(pt[5])
	if l > MaxNoteReasonLen {
		return Note{}, false
	}
	reason := pt[6 : 6+l]
	if l > 0 && !validNoteReason(reason) {
		return Note{}, false
	}
	for _, b := range pt[6+l:] {
		if b != 0 {
			return Note{}, false
		}
	}
	return Note{Reason: string(reason), RetryAfterS: min(binary.BigEndian.Uint32(pt[1:5]), MaxRetryAfterS)}, true
}

// openNote opens the note of a dack whose token is tok(o) of k and reads it.
func (k *AckKey) openNote(o Outcome, note []byte) (Note, bool) {
	if len(note) != NoteLen {
		return Note{}, false
	}
	aead, err := chacha20poly1305.New(k.noteKey())
	if err != nil {
		return Note{}, false
	}
	tok := k.token(o)
	pt, err := aead.Open(nil, note[:noteNonceLen], note[noteNonceLen:], tok[:])
	if err != nil {
		return Note{}, false
	}
	return decodeNotePT(pt)
}

// VerifyDAck decides a dack against the ack_keys a sender holds for one message, one per
// version it sent (DLV-C-4). For each key in order it computes tok(1) and tok(2) and compares
// them with the dack's token in constant time; the first that matches gives idx (the key's
// index) and the outcome o, and ok is true. Then it opens the note: noteOK is true and n its
// content when the note opens and reads (decodeNotePT); otherwise noteOK is false and n is the
// empty note, and the outcome stands (DLV-W-7). A dack that is not DAckLen bytes, or whose token
// is no token of any key, gives ok false and idx -1. A zero key matches nothing.
func VerifyDAck(keys []AckKey, dack []byte) (idx int, o Outcome, n Note, noteOK, ok bool) {
	idx = -1
	if len(dack) != DAckLen {
		return idx, 0, Note{}, false, false
	}
	tok := dack[:TokenLen]
	for i := range keys {
		if keys[i].isZero() {
			continue
		}
		// Both tokens of every key are computed and compared, so the time taken does not say
		// which key or outcome matched.
		for _, out := range [...]Outcome{OutcomeProcessed, OutcomeRefused} {
			t := keys[i].token(out)
			if subtle.ConstantTimeCompare(t[:], tok) == 1 && idx < 0 {
				idx, o = i, out
			}
		}
	}
	if idx < 0 {
		return idx, 0, Note{}, false, false
	}
	n, noteOK = keys[idx].openNote(o, dack[TokenLen:])
	return idx, o, n, noteOK, true
}

// ValidNoteReason reports whether s is a reason code a note can carry: ^[a-z][a-z0-9_]{0,29}$
// (CORE-K19). The empty reason, which a note may also carry, is not a code.
func ValidNoteReason(s string) bool { return validNoteReason([]byte(s)) }

func validNoteReason(s []byte) bool {
	if len(s) == 0 || len(s) > MaxNoteReasonLen || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range s[1:] {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// retryTiers are the waits RetryBucket rounds up to (CORE-K22), in seconds.
var retryTiers = [...]uint32{1, 5, 15, 60, 300, 900, 3600}

// RetryBucket rounds a wait for a note's retry_after (CORE-K22, DLV-C-6), so that the value says
// little about the recipient's load or quotas beyond what the sender needs to know.
//
// Without dayWindow it returns the smallest of 1, 5, 15, 60, 300, 900 and 3600 seconds that is
// not below seconds: 0 for 0, and 3600 for anything above 3600. With dayWindow (a
// quota_caller_per_day refusal, which lasts until the UTC day ends) it ignores seconds and returns
// the time from nowMS (unix ms) to the next UTC midnight, in whole seconds rounded up and then up
// to a multiple of 900, at most MaxRetryAfterS. Within 3600 seconds, and in the day window, the
// result is never below the wait it rounds.
func RetryBucket(seconds uint32, dayWindow bool, nowMS uint64) uint32 {
	if dayWindow {
		left := dayMS - nowMS%dayMS // in (0, dayMS]
		s := (left + 999) / 1000    // whole seconds, rounded up: 1 to 86 400
		s = (s + 899) / 900 * 900   // a multiple of 900, at most 86 400
		return uint32(min(s, MaxRetryAfterS))
	}
	if seconds == 0 {
		return 0
	}
	for _, t := range retryTiers {
		if seconds <= t {
			return t
		}
	}
	return retryTiers[len(retryTiers)-1]
}
