package a2acard

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
)

// testdata/python-vectors.json is produced by testdata/gen_python_vectors.py with the
// a2a-python reference SDK: cards built as lf.a2a.v1.AgentCard protos, rendered with
// MessageToDict and signed by a2a.utils.signing under the anet suite identity. See the script
// for the environment and for what each vector covers.
type pythonVectors struct {
	SuiteAID string         `json:"suite_aid"`
	NowMS    uint64         `json:"now_ms"`
	Vectors  []pythonVector `json:"vectors"`
}

type pythonVector struct {
	Name           string          `json:"name"`
	Kid            string          `json:"kid"`
	Jku            string          `json:"jku"`
	Card           json.RawMessage `json:"card"`
	CardUnsigned   json.RawMessage `json:"card_unsigned"`
	PythonPayload  string          `json:"python_payload"`
	PythonVerifies bool            `json:"python_verifies"`
	Expect         struct {
		PublishForm     bool   `json:"publish_form"`
		Verify          string `json:"verify"`
		SameStatementAs string `json:"same_statement_as"`
	} `json:"expect"`
}

func loadPythonVectors(t *testing.T) pythonVectors {
	t.Helper()
	b, err := os.ReadFile("testdata/python-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var pv pythonVectors
	if err := json.Unmarshal(b, &pv); err != nil {
		t.Fatal(err)
	}
	if len(pv.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return pv
}

func suiteKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("anet-suite-identity-v1/cur"))
	return ed25519.NewKeyFromSeed(seed[:])
}

// hasCardExtension reports whether the card declares the anet-card extension, that is,
// whether the full anet Verify applies to it rather than only the JWS check.
func hasCardExtension(t *testing.T, cardJSON []byte) bool {
	t.Helper()
	var c struct {
		Capabilities struct {
			Extensions []struct {
				URI string `json:"uri"`
			} `json:"extensions"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(cardJSON, &c); err != nil {
		t.Fatal(err)
	}
	for _, e := range c.Capabilities.Extensions {
		if e.URI == ExtCardURI {
			return true
		}
	}
	return false
}

func TestPythonVectors(t *testing.T) {
	pv := loadPythonVectors(t)
	suite := identity.SuiteController()
	if pv.SuiteAID != suite.AID() {
		t.Fatalf("vectors signed for AID %s, suite identity is %s", pv.SuiteAID, suite.AID())
	}
	if pv.NowMS != t0 {
		t.Fatalf("vectors use now %d, tests use %d", pv.NowMS, t0)
	}
	key := suiteKey()
	pub := key.Public().(ed25519.PublicKey)
	hashes := map[string][32]byte{}

	for _, v := range pv.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			card := []byte(v.Card)
			sigs := signaturesOf(t, card)
			if len(sigs) != 1 {
				t.Fatalf("%d signatures, want 1", len(sigs))
			}
			anetCard := hasCardExtension(t, card)
			form := CanonicalForm(v.Expect.Verify)
			wantAccept := form == FormProtoStripped || form == FormRaw

			// a2a-python accepts every vector except the one signed over the raw form: the
			// divergent vectors are cards the reference SDK accepts and the specification's
			// rule (and so a2acard) does not.
			if v.PythonVerifies != (form != FormRaw) {
				t.Fatalf("python_verifies = %v, inconsistent with expect.verify %q", v.PythonVerifies, v.Expect.Verify)
			}

			// The JWS check under the suite key.
			_, gotForm, err := VerifySignatureForm(card, sigs[0], pub)
			switch {
			case wantAccept && (err != nil || gotForm != form):
				t.Fatalf("VerifySignatureForm: form %q err %v, want %q", gotForm, err, form)
			case !wantAccept && !IsCode(err, CodeInvalidSignature):
				t.Fatalf("VerifySignatureForm: err %v, want %s", err, CodeInvalidSignature)
			}

			// The full anet admission, for network cards.
			if anetCard {
				got, err := Verify(card, newResolver(suite).resolve, t0)
				if wantAccept {
					if err != nil {
						t.Fatalf("Verify: %v", err)
					}
					if got.AID != suite.AID() || got.CanonicalForm != form || got.Seq != 9007199254740993 {
						t.Fatalf("Verified = %+v", got)
					}
					hashes[v.Name] = got.PayloadHash
				} else {
					wantCode(t, err, Code(v.Expect.Verify))
				}
			}

			// The payload a2a-python signed is the one a2acard computes for the accepted form;
			// for a divergent vector it is not, which is the divergence.
			stripped, err := SigningPayload(card)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := RawSigningPayload(card)
			if err != nil {
				t.Fatal(err)
			}
			switch form {
			case FormProtoStripped:
				if string(stripped) != v.PythonPayload {
					t.Fatalf("proto-stripped payload\n got %s\nwant %s", stripped, v.PythonPayload)
				}
			case FormRaw:
				if string(raw) != v.PythonPayload {
					t.Fatalf("raw payload\n got %s\nwant %s", raw, v.PythonPayload)
				}
				if string(stripped) == v.PythonPayload {
					t.Fatal("raw-signed vector: the proto-stripped payload should differ")
				}
			default:
				if string(stripped) == v.PythonPayload || string(raw) == v.PythonPayload {
					t.Fatalf("divergent vector: a2acard computed a2a-python's payload %s", v.PythonPayload)
				}
			}

			// Publish form: MessageToDict output of a card with no empty values is in it; the
			// wire-defaults rendering and the divergent cards are not.
			if err := CheckPublishForm(card); (err == nil) != v.Expect.PublishForm {
				t.Fatalf("CheckPublishForm(card) = %v, want publish form %v", err, v.Expect.PublishForm)
			}
			if v.CardUnsigned != nil {
				if err := CheckPublishForm(v.CardUnsigned); (err == nil) != v.Expect.PublishForm {
					t.Fatalf("CheckPublishForm(card_unsigned) = %v, want publish form %v", err, v.Expect.PublishForm)
				}
				// Sign reproduces a2a-python's signature byte for byte from the same card and key.
				signed, err := Sign(v.CardUnsigned, key, v.Kid, v.Jku)
				if err != nil {
					t.Fatal(err)
				}
				mine := signaturesOf(t, signed)
				if len(mine) != 1 || mine[0] != sigs[0] {
					t.Fatalf("Sign = %+v\nwant %+v", mine, sigs[0])
				}
				p, err := SigningPayload(v.CardUnsigned)
				if err != nil {
					t.Fatal(err)
				}
				if string(p) != v.PythonPayload {
					t.Fatalf("payload of card_unsigned\n got %s\nwant %s", p, v.PythonPayload)
				}
			}
		})
	}

	// Variants of one card are one statement: same PayloadHash whatever their bytes and
	// whichever form their signature verified under.
	for _, v := range pv.Vectors {
		if v.Expect.SameStatementAs == "" {
			continue
		}
		a, okA := hashes[v.Name]
		b, okB := hashes[v.Expect.SameStatementAs]
		if !okA || !okB || a != b {
			t.Errorf("%s: PayloadHash differs from %s", v.Name, v.Expect.SameStatementAs)
		}
	}
}

// schema.go is the AgentCard schema of a2a.proto. The generator dumps the same table from the
// a2a-python SDK's compiled descriptors (field_behavior REQUIRED, has_presence, map and
// repeated labels), so a transcription error here, or a schema change in a new A2A version,
// shows up as a difference.
func TestSchemaMatchesReferenceDescriptors(t *testing.T) {
	b, err := os.ReadFile("testdata/a2a-agentcard-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	type fieldDesc struct {
		Type     string `json:"type"`
		Presence string `json:"presence"`
		Message  string `json:"message,omitempty"`
	}
	var want map[string]map[string]fieldDesc
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}

	typeName := map[fieldType]string{
		tString: "string", tBool: "bool", tMessage: "message", tStruct: "struct",
		tStrings: "repeated_string", tMessages: "repeated_message",
		tStringMap: "map_string", tMessageMap: "map_message",
	}
	presenceName := map[presence]string{implicit: "implicit", explicit: "explicit", required: "required"}

	got := map[string]map[string]fieldDesc{}
	var walk func(m *message)
	walk = func(m *message) {
		if _, done := got[m.name]; done {
			return
		}
		fields := map[string]fieldDesc{}
		got[m.name] = fields
		for name, f := range m.fields {
			d := fieldDesc{Type: typeName[f.typ], Presence: presenceName[f.pres]}
			if f.msg != nil {
				d.Message = f.msg.name
				walk(f.msg)
			}
			fields[name] = d
		}
	}
	walk(schemaAgentCard)

	if !reflect.DeepEqual(got, want) {
		var names []string
		for n := range want {
			names = append(names, n)
		}
		for n := range got {
			if _, ok := want[n]; !ok {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			if !reflect.DeepEqual(got[n], want[n]) {
				t.Errorf("%s:\n got %+v\nwant %+v", n, got[n], want[n])
			}
		}
	}
}
