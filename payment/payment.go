// Package payment implements the x402 wire objects and the anet-credit
// scheme.
//
// x402 puts HTTP 402 to use: a server that wants paying answers with the
// price and where to pay, the client repeats the request carrying a
// signed authorization, and a facilitator verifies and settles. The
// objects here are x402 v2's — PaymentRequired, PaymentPayload,
// SettlementResponse, VerifyResponse — so an ANet hub is an ordinary
// facilitator and an ANet price is an ordinary 402 body.
//
// Two properties of that spec are why it fits rather than merely being
// adopted. `scheme` and `network` are implementation-defined identifiers
// and not closed enumerations, with non-blockchain networks explicitly
// invited to use CAIP-2 form (the spec's own examples are ach:us and
// sepa:eu) — so hub:<aid> is conformant rather than a liberty. And
// settlement is not required to be onchain, so a scheme may define it as
// a ledger entry.
//
// # What anet-credit does not pretend to be
//
// On an onchain rail a facilitator holds no funds: it broadcasts an
// authorization the payer signed, and could not divert it if it wanted
// to. That property does not survive being carried over to an internal
// ledger. A hub keeping credit balances IS the custodian of them, and
// choosing which hub to register with is choosing who to trust with
// that. It is written here, in the docs and in the hub's own code,
// because the x402 name would otherwise lend a guarantee this rail does
// not have.
//
// What the hub cannot do is rewrite history. An authorization is signed
// by the payer and a settlement is signed by the hub, both parties keep
// them, and both append the event to their own evidence chain. The hub
// keeps the balance; it does not keep the record.
package payment

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// Version is the x402 protocol version these objects speak.
const Version = 2

// SchemeCredit is a hub-internal ledger rail.
//
// Named rather than reusing "exact" because it settles differently and a
// client must be able to tell: "exact" moves a token on a chain, this
// moves a number in a hub's database. A client that cannot distinguish
// them cannot decide whether it is willing to pay that way.
const SchemeCredit = "anet-credit"

// AssetCredit is the unit of a hub's own ledger. A hub decides what a
// credit is worth, or that it is worth nothing and everything is free.
const AssetCredit = "credit"

// CreditNetwork names the hub whose ledger a payment settles on, in the
// CAIP-2 shape the spec asks non-blockchain networks to adopt. Two hubs
// are two networks: a credit on one is not a credit on the other, and a
// payer must be able to see which they are being asked for.
func CreditNetwork(hubAID string) string { return "hub:" + hubAID }

// PaymentRequired is the 402 body: what this costs and where to pay.
type PaymentRequired struct {
	X402Version int             `json:"x402Version"`
	Error       string          `json:"error,omitempty"`
	Resource    *Resource       `json:"resource,omitempty"`
	Accepts     []PaymentOption `json:"accepts"`
	Extensions  map[string]any  `json:"extensions,omitempty"`
}

// Resource identifies what is being charged for.
type Resource struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// PaymentOption is one rail the payee will accept.
//
// A list, because a provider may take several and the payer chooses:
// a hub credit, a stablecoin, an invoice. Free is not an option in this
// list — free is the absence of a 402 altogether.
type PaymentOption struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	Amount            string         `json:"amount"`
	Asset             string         `json:"asset"`
	PayTo             string         `json:"payTo"`
	MaxTimeoutSeconds int            `json:"maxTimeoutSeconds,omitempty"`
	Extra             map[string]any `json:"extra,omitempty"`
}

// PaymentPayload is what the payer sends back: which option they took
// and the scheme-defined proof.
type PaymentPayload struct {
	X402Version int            `json:"x402Version"`
	Accepted    PaymentOption  `json:"accepted"`
	Payload     map[string]any `json:"payload"`
	Extensions  map[string]any `json:"extensions,omitempty"`
}

// VerifyResponse is the facilitator's answer to "would this settle?".
type VerifyResponse struct {
	IsValid       bool   `json:"isValid"`
	InvalidReason string `json:"invalidReason,omitempty"`
	Payer         string `json:"payer,omitempty"`
}

// SettlementResponse is the facilitator's answer to "settle it".
type SettlementResponse struct {
	Success     bool           `json:"success"`
	ErrorReason string         `json:"errorReason,omitempty"`
	Payer       string         `json:"payer,omitempty"`
	Transaction string         `json:"transaction"`
	Network     string         `json:"network"`
	Amount      string         `json:"amount,omitempty"`
	Extensions  map[string]any `json:"extensions,omitempty"`
}

// Supported is what a facilitator advertises at /supported.
type Supported struct {
	Kinds []SupportedKind `json:"kinds"`
}

// SupportedKind is one scheme-network pair a facilitator will handle.
type SupportedKind struct {
	X402Version int    `json:"x402Version"`
	Scheme      string `json:"scheme"`
	Network     string `json:"network"`
}

// ---- the anet-credit scheme ----

// Authorization is what a payer signs on the anet-credit rail.
//
// It authorises one payment, once. The nonce and the window are what make
// that true: a hub replaying an authorization would settle a second time,
// and the payer's signature alone cannot say "only once" without them.
type Authorization struct {
	Payer    string `cbor:"1,keyasint"`
	PayTo    string `cbor:"2,keyasint"`
	Amount   uint64 `cbor:"3,keyasint"`
	Network  string `cbor:"4,keyasint"`
	Nonce    string `cbor:"5,keyasint"`
	IssuedAt int64  `cbor:"6,keyasint"` // unix millis
	NotAfter int64  `cbor:"7,keyasint"` // unix millis
	// InteractionID binds the payment to the work it pays for. Without it
	// an authorization is a bearer instrument: whoever holds it can spend
	// it on anything they are owed for.
	InteractionID string `cbor:"8,keyasint,omitempty"`
	// Envelope is the payer's detached signature, excluded from the
	// preimage it covers.
	Envelope *aobj.Envelope `cbor:"-"`
}

type authPreimage struct {
	Payer         string `cbor:"1,keyasint"`
	PayTo         string `cbor:"2,keyasint"`
	Amount        uint64 `cbor:"3,keyasint"`
	Network       string `cbor:"4,keyasint"`
	Nonce         string `cbor:"5,keyasint"`
	IssuedAt      int64  `cbor:"6,keyasint"`
	NotAfter      int64  `cbor:"7,keyasint"`
	InteractionID string `cbor:"8,keyasint,omitempty"`
}

// Authorization errors.
var (
	ErrUnsigned   = errors.New("payment: unsigned authorization")
	ErrExpired    = errors.New("payment: authorization outside its validity window")
	ErrBadWindow  = errors.New("payment: invalid validity window")
	ErrWrongPayer = errors.New("payment: envelope signer is not the payer")
)

func (a *Authorization) canonical() authPreimage {
	return authPreimage{
		Payer: a.Payer, PayTo: a.PayTo, Amount: a.Amount, Network: a.Network,
		Nonce: a.Nonce, IssuedAt: a.IssuedAt, NotAfter: a.NotAfter,
		InteractionID: a.InteractionID,
	}
}

// CanonicalPreimage is the CoreDet-CBOR bytes the signature covers.
func (a *Authorization) CanonicalPreimage() ([]byte, error) { return coredet.Marshal(a.canonical()) }

// ID is the content id of this authorization — the hub's idempotency key
// and the transaction id it reports back.
func (a *Authorization) ID() (string, error) {
	pre, err := a.CanonicalPreimage()
	if err != nil {
		return "", err
	}
	return anetcid.Sum(pre)
}

// Sign attaches the payer's signature. The signer becomes the payer:
// authorising a payment from somebody else's balance is not a thing a
// signature can express.
func (a *Authorization) Sign(c *identity.Controller) error {
	a.Payer = c.AID()
	pre, err := a.CanonicalPreimage()
	if err != nil {
		return err
	}
	sig, seq := c.Sign(pre)
	a.Envelope = &aobj.Envelope{SignerAID: c.AID(), KeyStateSeq: seq, Alg: aobj.AlgEdDSA, Sig: sig}
	return nil
}

// Verify checks the payer's signature and the validity window.
//
// It does not check a balance — that is the ledger's business and the
// ledger is the hub's. This says only that the payer really did authorise
// this exact payment, and said so within a window that has not closed.
func (a *Authorization) Verify(kel []identity.SignedEvent, now int64) error {
	if a.Envelope == nil {
		return ErrUnsigned
	}
	if err := a.Envelope.Validate(); err != nil {
		return err
	}
	if a.Envelope.SignerAID != a.Payer {
		return ErrWrongPayer
	}
	if a.IssuedAt <= 0 || a.NotAfter <= a.IssuedAt {
		return ErrBadWindow
	}
	if now < a.IssuedAt || now > a.NotAfter {
		return fmt.Errorf("%w: valid %d..%d, now %d", ErrExpired, a.IssuedAt, a.NotAfter, now)
	}
	pre, err := a.CanonicalPreimage()
	if err != nil {
		return err
	}
	return identity.VerifyObject(kel, a.Payer, a.Envelope.KeyStateSeq, uint64(now), pre, a.Envelope.Sig)
}

// wireAuthorization carries the detached envelope alongside the object,
// because cbor:"-" keeps it out of the signed bytes and marshalling the
// object alone would ship an unsigned authorization.
type wireAuthorization struct {
	Auth     authPreimage   `cbor:"1,keyasint"`
	Envelope *aobj.Envelope `cbor:"2,keyasint"`
}

// Marshal encodes an authorization with its signature.
func (a *Authorization) Marshal() ([]byte, error) {
	return coredet.Marshal(wireAuthorization{Auth: a.canonical(), Envelope: a.Envelope})
}

// UnmarshalAuthorization decodes one.
func UnmarshalAuthorization(b []byte) (*Authorization, error) {
	var w wireAuthorization
	if err := coredet.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	return &Authorization{
		Payer: w.Auth.Payer, PayTo: w.Auth.PayTo, Amount: w.Auth.Amount,
		Network: w.Auth.Network, Nonce: w.Auth.Nonce, IssuedAt: w.Auth.IssuedAt,
		NotAfter: w.Auth.NotAfter, InteractionID: w.Auth.InteractionID, Envelope: w.Envelope,
	}, nil
}

// Amount renders a credit amount the way x402 carries amounts: a decimal
// string, so no JSON number precision is involved in what someone owes.
func Amount(n uint64) string { return strconv.FormatUint(n, 10) }

// ParseAmount reads one back.
func ParseAmount(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("payment: amount %q is not a whole number of units: %w", s, err)
	}
	return n, nil
}
