package payment_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/payment"
)

// The facilitator request body is x402 v2's {x402Version, paymentPayload,
// paymentRequirements}. The hub requires the third field; a daemon that
// spelled it differently would be refused on every settlement.
func TestTheFacilitatorRequestKeepsTheSpecFieldNames(t *testing.T) {
	req := payment.FacilitatorRequest{
		X402Version:    payment.Version,
		PaymentPayload: &payment.PaymentPayload{X402Version: payment.Version},
		PaymentRequirements: &payment.PaymentRequirements{
			Scheme: payment.SchemeCredit, Network: payment.CreditNetwork("did:anet:hub"),
			Amount: payment.Amount(7), Asset: payment.AssetCredit, PayTo: "did:anet:provider",
		},
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"x402Version", "paymentPayload", "paymentRequirements"} {
		if _, ok := top[k]; !ok {
			t.Errorf("missing %q in %s", k, b)
		}
	}
	if len(top) != 3 {
		t.Errorf("fields = %d, want exactly 3: %s", len(top), b)
	}
	if !strings.Contains(string(top["paymentRequirements"]), `"payTo":"did:anet:provider"`) ||
		!strings.Contains(string(top["paymentRequirements"]), `"amount":"7"`) {
		t.Errorf("requirements lost their terms: %s", top["paymentRequirements"])
	}
}

// /supported carries x402 v2's extensions and signers, and anet's pointer
// to each signer's KEL.
func TestSupportedKeepsTheSpecFieldNames(t *testing.T) {
	b, err := json.Marshal(payment.Supported{
		Kinds:      []payment.SupportedKind{},
		Extensions: []string{payment.ExtReceipt},
		Signers:    map[string][]string{"hub:did:anet:hub": {"did:anet:hub"}},
		SignerKEL:  map[string]string{"did:anet:hub": "https://hub.example/hub/identity"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"kinds":[]`, `"extensions":["anet.settlement.receipt"]`,
		`"signers":{"hub:did:anet:hub":["did:anet:hub"]}`,
		`"anet.signer_kel":{"did:anet:hub":"https://hub.example/hub/identity"}`} {
		if !strings.Contains(string(b), field) {
			t.Errorf("missing %s in %s", field, b)
		}
	}
}

// The errorReason values are a contract with the daemon, which maps each
// to an a2a-x402 x402.payment.error code by exact string (A2A-DESIGN
// §8.5). A renamed value would reach the daemon's default branch.
func TestTheErrorReasonValuesArePinned(t *testing.T) {
	for _, pair := range [][2]string{
		{payment.ReasonInsufficientFunds, "insufficient_funds"},
		{payment.ReasonInvalidSignature, "invalid_signature"},
		{payment.ReasonExpiredPayment, "expired_payment"},
		{payment.ReasonNetworkMismatch, "network_mismatch"},
		{payment.ReasonUnsupportedScheme, "unsupported_scheme"},
		{payment.ReasonInvalidAmount, "invalid_amount"},
		{payment.ReasonPayeeMismatch, "payee_mismatch"},
		{payment.ReasonDuplicateNonce, "duplicate_nonce"},
		{payment.ReasonDuplicateBinding, "duplicate_binding"},
		{payment.ReasonUnknownPayer, "unknown_payer"},
		{payment.ReasonSettlementPending, "settlement_pending"},
		{payment.ReasonSettlementFailed, "settlement_failed"},
		{payment.ReasonMalformed, "malformed_payment"},
		{payment.ReasonInvalidRequirements, "invalid_payment_requirements"},
		{payment.ExtReplayed, "anet.replayed"},
		{payment.ExtOriginalTransaction, "anet.original_transaction"},
		{payment.ExtErrorDetail, "anet.error_detail"},
		{payment.ExtReceipt, "anet.settlement.receipt"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%q, want %q", pair[0], pair[1])
		}
	}
}
