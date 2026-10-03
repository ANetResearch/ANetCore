package delegation

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/tsir"
)

// The task binding (core §2.4.3, HPP §2.5): three private contexts in the first task of every
// delegated TaskDoc. They are inside the TaskDoc's signed preimage, and the provider copies them
// into its receipt; the receipt then binds the task without naming the requester to anyone the
// receipt is shown to.
const (
	// ContextNonce is the task nonce (r4 X4): random text, the input of ix_commit (L27) and PayBind
	// (L34) exactly as written.
	ContextNonce = "anet.nonce"
	// ContextRequesterCommit is evidence.RequesterCommit(requester AID, rsalt), base64url.
	ContextRequesterCommit = "anet.requester_commit"
	// ContextReviewKey is the public half of the one-time key the requester will sign its review
	// with, base64url.
	ContextReviewKey = "anet.review_key"
)

// bindingVisibility and bindingFormat are the Visibility and Format of the three contexts (core
// §2.4.3): private, text. An empty Format is read as text.
const (
	bindingVisibility = "private"
	bindingFormat     = "text"
)

// ErrTaskBinding: the TaskDoc does not carry the three binding contexts in their one form. The
// provider refuses such a delegation at step 9 of the receive pipeline (bad_request, CORE-K7).
var ErrTaskBinding = errors.New("delegation: the TaskDoc does not carry a well-formed task binding")

// TaskBinding is the content of the three binding contexts.
type TaskBinding struct {
	Nonce           string // anet.nonce exactly as written
	RequesterCommit []byte // 32 bytes
	ReviewKey       []byte // 32 bytes, an Ed25519 public key
}

// b64 is the encoding of the two 32-byte contexts: base64url without padding (CORE-E5). A 32-byte
// value has one spelling of 43 characters; Strict refuses non-zero trailing bits, and the length
// check refuses the CR and LF the decoder would otherwise skip.
var b64 = base64.RawURLEncoding.Strict()

var b64Len32 = b64.EncodedLen(32)

func decode32(key, v string) ([]byte, error) {
	if len(v) != b64Len32 {
		return nil, fmt.Errorf("%w: %s is %d characters, not the %d of 32 bytes in base64url", ErrTaskBinding, key, len(v), b64Len32)
	}
	b, err := b64.DecodeString(v)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("%w: %s is not 32 bytes in unpadded base64url", ErrTaskBinding, key)
	}
	return b, nil
}

// ReadTaskBinding returns the task binding of td, or ErrTaskBinding. The three contexts must each
// appear exactly once in the first task, private, as text with a Value (not a Src); anet.nonce must
// be non-empty and free of U+0000 (CORE-E9); the other two must be 32 bytes in unpadded base64url.
func ReadTaskBinding(td *tsir.TaskDoc) (*TaskBinding, error) {
	if td == nil || len(td.Tasks) == 0 {
		return nil, fmt.Errorf("%w: the TaskDoc has no task", ErrTaskBinding)
	}
	found := map[string]string{}
	for _, c := range td.Tasks[0].Contexts {
		switch c.Key {
		case ContextNonce, ContextRequesterCommit, ContextReviewKey:
		default:
			continue
		}
		if _, dup := found[c.Key]; dup {
			return nil, fmt.Errorf("%w: %s appears twice", ErrTaskBinding, c.Key)
		}
		if c.Visibility != bindingVisibility {
			return nil, fmt.Errorf("%w: %s is %q, not private", ErrTaskBinding, c.Key, c.Visibility)
		}
		if c.Format != "" && c.Format != bindingFormat {
			return nil, fmt.Errorf("%w: %s has format %q, not text", ErrTaskBinding, c.Key, c.Format)
		}
		if c.Src != "" {
			return nil, fmt.Errorf("%w: %s points elsewhere (src) instead of holding its value", ErrTaskBinding, c.Key)
		}
		found[c.Key] = c.Value
	}
	for _, k := range []string{ContextNonce, ContextRequesterCommit, ContextReviewKey} {
		if _, ok := found[k]; !ok {
			return nil, fmt.Errorf("%w: %s is missing", ErrTaskBinding, k)
		}
	}
	nonce := found[ContextNonce]
	if nonce == "" || strings.IndexByte(nonce, 0) >= 0 {
		return nil, fmt.Errorf("%w: %s is empty or holds U+0000", ErrTaskBinding, ContextNonce)
	}
	rc, err := decode32(ContextRequesterCommit, found[ContextRequesterCommit])
	if err != nil {
		return nil, err
	}
	rk, err := decode32(ContextReviewKey, found[ContextReviewKey])
	if err != nil {
		return nil, err
	}
	return &TaskBinding{Nonce: nonce, RequesterCommit: rc, ReviewKey: rk}, nil
}

// CheckTaskBinding reports whether td carries a well-formed task binding (HPP PAY-K4). The
// provider calls it at step 9 of the receive pipeline; an error is bad_request.
func CheckTaskBinding(td *tsir.TaskDoc) error {
	_, err := ReadTaskBinding(td)
	return err
}

// Contexts returns the three binding contexts in their one form, for the requester to put in the
// first task of the TaskDoc it signs.
func (b *TaskBinding) Contexts() ([]tsir.Context, error) {
	if b.Nonce == "" || strings.IndexByte(b.Nonce, 0) >= 0 {
		return nil, fmt.Errorf("%w: %s is empty or holds U+0000", ErrTaskBinding, ContextNonce)
	}
	if len(b.RequesterCommit) != evidence.CommitSize || len(b.ReviewKey) != evidence.ReviewKeySize {
		return nil, fmt.Errorf("%w: requester_commit and review_key are 32 bytes each", ErrTaskBinding)
	}
	ctx := func(k, v string) tsir.Context {
		return tsir.Context{Key: k, Value: v, Format: bindingFormat, Visibility: bindingVisibility}
	}
	return []tsir.Context{
		ctx(ContextNonce, b.Nonce),
		ctx(ContextRequesterCommit, b64.EncodeToString(b.RequesterCommit)),
		ctx(ContextReviewKey, b64.EncodeToString(b.ReviewKey)),
	}, nil
}

// IXCommit is the ix_commit a receipt for interaction ix of this task carries (L27).
func (b *TaskBinding) IXCommit(ix string) ([]byte, error) { return evidence.IXCommit(ix, b.Nonce) }

// equal32 compares two 32-byte values.
func equal32(a, b []byte) bool { return len(a) == 32 && bytes.Equal(a, b) }
