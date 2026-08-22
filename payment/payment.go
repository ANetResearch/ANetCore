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

// ---- settlement receipts, for hubs that clear against each other ----

// Receipt is a hub's signed statement that it settled a payment.
//
// It exists because of what cross-hub payment asks of the two hubs. A
// provider on hub B, paid from a balance on hub A, means B must credit
// its own user on A's say-so — and "A said so" over plain HTTP is not
// something B can show anyone later, including A. So A signs, B keeps it,
// and the obligation between them is evidenced rather than remembered.
//
// It rides in the x402 SettlementResponse's extensions, which is the
// spec's own place for exactly this: functionality beyond the core
// payment mechanics that a facilitator advertises and a client can
// ignore.
type Receipt struct {
	AuthID   string `cbor:"1,keyasint"` // the authorization settled
	Payer    string `cbor:"2,keyasint"`
	PayTo    string `cbor:"3,keyasint"`
	Amount   uint64 `cbor:"4,keyasint"`
	Network  string `cbor:"5,keyasint"` // the ledger it moved on
	SettleAt int64  `cbor:"6,keyasint"` // unix millis
	// Envelope is the settling hub's detached signature.
	Envelope *aobj.Envelope `cbor:"-"`
}

type receiptPreimage struct {
	AuthID   string `cbor:"1,keyasint"`
	Payer    string `cbor:"2,keyasint"`
	PayTo    string `cbor:"3,keyasint"`
	Amount   uint64 `cbor:"4,keyasint"`
	Network  string `cbor:"5,keyasint"`
	SettleAt int64  `cbor:"6,keyasint"`
}

func (r *Receipt) canonical() receiptPreimage {
	return receiptPreimage{AuthID: r.AuthID, Payer: r.Payer, PayTo: r.PayTo,
		Amount: r.Amount, Network: r.Network, SettleAt: r.SettleAt}
}

// CanonicalPreimage is what the settling hub signs.
func (r *Receipt) CanonicalPreimage() ([]byte, error) { return coredet.Marshal(r.canonical()) }

// Sign attaches the settling hub's signature.
func (r *Receipt) Sign(c *identity.Controller) error {
	pre, err := r.CanonicalPreimage()
	if err != nil {
		return err
	}
	sig, seq := c.Sign(pre)
	r.Envelope = &aobj.Envelope{SignerAID: c.AID(), KeyStateSeq: seq, Alg: aobj.AlgEdDSA, Sig: sig}
	return nil
}

// Verify checks the settling hub's signature.
//
// signerAID is who the reader expected to have settled — the hub whose
// ledger the network names. Without pinning it, a hub could sign a
// receipt for a payment on somebody else's ledger and the reader would
// have no reason to notice.
func (r *Receipt) Verify(kel []identity.SignedEvent, signerAID string, now int64) error {
	if r.Envelope == nil {
		return ErrUnsigned
	}
	if err := r.Envelope.Validate(); err != nil {
		return err
	}
	if signerAID != "" && r.Envelope.SignerAID != signerAID {
		return fmt.Errorf("payment: receipt signed by %s, expected %s", r.Envelope.SignerAID, signerAID)
	}
	pre, err := r.CanonicalPreimage()
	if err != nil {
		return err
	}
	return identity.VerifyObject(kel, r.Envelope.SignerAID, r.Envelope.KeyStateSeq,
		uint64(now), pre, r.Envelope.Sig)
}

type wireReceipt struct {
	Receipt  receiptPreimage `cbor:"1,keyasint"`
	Envelope *aobj.Envelope  `cbor:"2,keyasint"`
}

// Marshal encodes a receipt with its signature.
func (r *Receipt) Marshal() ([]byte, error) {
	return coredet.Marshal(wireReceipt{Receipt: r.canonical(), Envelope: r.Envelope})
}

// UnmarshalReceipt decodes one.
func UnmarshalReceipt(b []byte) (*Receipt, error) {
	var w wireReceipt
	if err := coredet.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	return &Receipt{AuthID: w.Receipt.AuthID, Payer: w.Receipt.Payer, PayTo: w.Receipt.PayTo,
		Amount: w.Receipt.Amount, Network: w.Receipt.Network, SettleAt: w.Receipt.SettleAt,
		Envelope: w.Envelope}, nil
}

// ExtReceipt is the extensions key a settlement receipt rides under.
const ExtReceipt = "anet.settlement.receipt"

// ---- error reasons ----
//
// x402 leaves errorReason open. These are the strings this implementation
// uses, named so a caller can branch on them rather than matching prose
// that will be reworded. A reason not in this list is still valid — the
// field is a string, deliberately.
const (
	// ReasonInsufficientFunds: the payer's balance would not cover it.
	ReasonInsufficientFunds = "insufficient_funds"
	// ReasonInvalidSignature: the authorization did not verify against the
	// payer's key history. Includes a signature over different terms.
	ReasonInvalidSignature = "invalid_signature"
	// ReasonExpired: presented outside the authorization's window.
	ReasonExpired = "expired"
	// ReasonUnknownPayer: this facilitator holds no account for the payer,
	// so it has nothing to move and no key history to check against.
	ReasonUnknownPayer = "unknown_payer"
	// ReasonNetworkMismatch: signed for a different ledger. An
	// authorization naming another hub is not payable here, which is the
	// point of putting the hub's AID in the network.
	ReasonNetworkMismatch = "network_mismatch"
	// ReasonMalformed: the payload could not be read as an authorization.
	ReasonMalformed = "malformed_payment"
)

// ---- the voucher: payment here, work there ----

// Voucher is a hub's signed statement that a specific piece of work has
// been paid for, addressed to the provider that must honour it.
//
// It exists so the paying and the doing can happen in different places. A
// hub can host an x402 resource server — take the 402, settle the credit
// — without becoming a proxy for the work: it hands back a voucher, and
// the client goes to the provider itself. The hub therefore never sees
// the request or the result, which is the same property the relay has and
// worth keeping for the same reason. It cannot leak what it never held.
//
// The cost is real and should be stated: the client must be able to reach
// the provider directly. Where it cannot — the provider is behind a NAT
// with no public face — this shape does not apply, and the ordinary
// delegate-and-pay path through the relay does.
//
// One-time is enforced by the provider, not the hub. The hub cannot know
// whether a voucher was used; the provider is the only party that can,
// because it is the one performing the work. So Nonce is here for the
// provider to remember, and a provider that does not remember it has
// agreed to be paid once for work done twice.
type Voucher struct {
	AuthID     string `cbor:"1,keyasint"` // the settled authorization
	Payer      string `cbor:"2,keyasint"`
	PayTo      string `cbor:"3,keyasint"` // the provider bound to honour it
	Capability string `cbor:"4,keyasint"` // exactly what was bought
	Amount     uint64 `cbor:"5,keyasint"`
	Network    string `cbor:"6,keyasint"`
	NotAfter   int64  `cbor:"7,keyasint"` // unix millis
	Nonce      string `cbor:"8,keyasint"` // the provider's uniqueness key
	// ArgsCID pins the arguments, when the buyer named them at purchase.
	// Empty means the voucher buys the capability rather than one exact
	// call of it. Both are legitimate; which one is in force is something
	// the provider can see rather than assume.
	ArgsCID string `cbor:"9,keyasint,omitempty"`
	// Envelope is the settling hub's detached signature.
	Envelope *aobj.Envelope `cbor:"-"`
}

type voucherPreimage struct {
	AuthID     string `cbor:"1,keyasint"`
	Payer      string `cbor:"2,keyasint"`
	PayTo      string `cbor:"3,keyasint"`
	Capability string `cbor:"4,keyasint"`
	Amount     uint64 `cbor:"5,keyasint"`
	Network    string `cbor:"6,keyasint"`
	NotAfter   int64  `cbor:"7,keyasint"`
	Nonce      string `cbor:"8,keyasint"`
	ArgsCID    string `cbor:"9,keyasint,omitempty"`
}

func (v *Voucher) canonical() voucherPreimage {
	return voucherPreimage{AuthID: v.AuthID, Payer: v.Payer, PayTo: v.PayTo,
		Capability: v.Capability, Amount: v.Amount, Network: v.Network,
		NotAfter: v.NotAfter, Nonce: v.Nonce, ArgsCID: v.ArgsCID}
}

// CanonicalPreimage returns the CoreDet-CBOR signing preimage.
func (v *Voucher) CanonicalPreimage() ([]byte, error) { return coredet.Marshal(v.canonical()) }

// ID is the content identifier over the preimage — a stable name for one
// voucher, and what a provider stores when it marks the voucher spent.
func (v *Voucher) ID() (string, error) {
	pre, err := v.CanonicalPreimage()
	if err != nil {
		return "", err
	}
	return anetcid.Sum(pre)
}

// Sign attaches the settling hub's signature.
func (v *Voucher) Sign(c *identity.Controller) error {
	pre, err := v.CanonicalPreimage()
	if err != nil {
		return err
	}
	sig, seq := c.Sign(pre)
	v.Envelope = &aobj.Envelope{SignerAID: c.AID(), KeyStateSeq: seq, Alg: aobj.AlgEdDSA, Sig: sig}
	return nil
}

// Verify checks the voucher against the hub's key history and pins every
// term the provider is relying on.
//
// expectPayTo is the provider's own AID and expectCapability the work it
// is about to do: passing them is what makes this a check rather than a
// signature test. A voucher that verifies cryptographically but was
// issued for somebody else's capability is a valid signature over a
// statement that does not authorise this work.
//
// expectNetwork must be the provider's own hub. A voucher signed by some
// other hub verifies fine against that hub's KEL and means nothing here:
// the provider would be doing paid work against credit on a ledger it has
// no account on. The caller passes the network it will actually be paid
// on, and a mismatch is refused.
func (v *Voucher) Verify(kel []identity.SignedEvent, expectSigner, expectPayTo,
	expectCapability, expectNetwork string, now int64) error {
	if v.Envelope == nil {
		return errors.New("payment: unsigned voucher")
	}
	if err := v.Envelope.Validate(); err != nil {
		return err
	}
	if expectSigner != "" && v.Envelope.SignerAID != expectSigner {
		return fmt.Errorf("payment: voucher signed by %s, not the expected hub %s",
			v.Envelope.SignerAID, expectSigner)
	}
	if v.PayTo != expectPayTo {
		return fmt.Errorf("payment: voucher is payable to %s, not to this provider", v.PayTo)
	}
	if v.Capability != expectCapability {
		return fmt.Errorf("payment: voucher bought %q, not %q", v.Capability, expectCapability)
	}
	if expectNetwork != "" && v.Network != expectNetwork {
		return fmt.Errorf("payment: voucher settles on %s, not on %s", v.Network, expectNetwork)
	}
	if v.NotAfter != 0 && now > v.NotAfter {
		return errors.New("payment: voucher expired")
	}
	if v.Nonce == "" {
		return errors.New("payment: voucher has no nonce, so it cannot be spent only once")
	}
	pre, err := v.CanonicalPreimage()
	if err != nil {
		return err
	}
	return identity.VerifyObject(kel, v.Envelope.SignerAID, v.Envelope.KeyStateSeq,
		uint64(now), pre, v.Envelope.Sig)
}

type wireVoucher struct {
	Body     voucherPreimage `cbor:"1,keyasint"`
	Envelope *aobj.Envelope  `cbor:"2,keyasint"`
}

// Marshal encodes the voucher with its detached signature.
func (v *Voucher) Marshal() ([]byte, error) {
	return coredet.Marshal(wireVoucher{Body: v.canonical(), Envelope: v.Envelope})
}

// UnmarshalVoucher decodes a wire voucher.
func UnmarshalVoucher(b []byte) (*Voucher, error) {
	var w wireVoucher
	if err := coredet.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	return &Voucher{
		AuthID: w.Body.AuthID, Payer: w.Body.Payer, PayTo: w.Body.PayTo,
		Capability: w.Body.Capability, Amount: w.Body.Amount, Network: w.Body.Network,
		NotAfter: w.Body.NotAfter, Nonce: w.Body.Nonce, ArgsCID: w.Body.ArgsCID,
		Envelope: w.Envelope,
	}, nil
}

// ExtVoucher is the SettlementResponse extension key a voucher rides in.
const ExtVoucher = "anet.settlement.voucher"

// HeaderPaymentRequired, HeaderPaymentSignature and HeaderPaymentResponse
// are the x402 HTTP headers. Named here so the resource server and the
// client cannot drift apart on capitalisation or spelling.
const (
	HeaderPaymentRequired  = "PAYMENT-REQUIRED"
	HeaderPaymentSignature = "PAYMENT-SIGNATURE"
	HeaderPaymentResponse  = "PAYMENT-RESPONSE"
)
