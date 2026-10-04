package seal

// RC-1's acceptance of the ack_key that CORE-2's Seal and Open export (DLV §2.6.1, §4.1;
// DLV-C-1, DLV-C-2, DLV-C-API-1, DLV-C-API-2; §7.1 G3):
//   - Seal returns the layer-1 export, and Open of the same envelope exports the same bytes, with
//     one layer or two (FS-C14);
//   - every failure of Open after layer 1 opened carries that key (AckKeyOf true), so the
//     recipient can still answer with a token, and no failure before it does;
//   - each step of Open is covered: the reasons the step functions can return are read from the
//     source, so a new failure step without a case here fails.

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
)

// sealCase seals in from a to b with hooks, as Seal does, and returns the envelope with a
// session access and Seal's ack_key.
func sealCase(t *testing.T, in *SealedInner, to *EncKey, sign SignFunc, o SealOpts, h sealHooks) ([]byte, AckKey) {
	t.Helper()
	env, ack, err := seal(in, to, sign, o, &h)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return withSession(t, env), ack
}

// outerEdit returns env with its outer field map changed by edit and encoded again.
func outerEdit(t *testing.T, env []byte, edit func(fieldMap)) []byte {
	t.Helper()
	m, err := decodeFields(env)
	if err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, err := coredet.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// DLV-C-1: the ack_key Seal returns is the one the recipient's Open exports, for one layer, two
// layers and a one-shot envelope; every seal has its own; none is zero.
func TestSealAckKeyIsTheRecipientsExport(t *testing.T) {
	a, b := newParty(t), newParty(t)
	bk := mustIXKey(t, "ix-1", a.aid())
	seen := map[AckKey]bool{}
	for _, c := range []struct {
		name string
		o    SealOpts
	}{
		{"one layer", SealOpts{}},
		{"two layers", SealOpts{PeerRK: bk.RK()}},
		{"one-shot", SealOpts{Exp: t0 + dayMS}},
		{"two layers, one-shot", SealOpts{PeerRK: bk.RK(), Exp: t0 + dayMS}},
	} {
		t.Run(c.name, func(t *testing.T) {
			for range 3 {
				env, ack := mustSealAck(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign, c.o)
				o, err := Open(env, b.aid(), b.ring(), ixKeys{bk})
				if err != nil {
					t.Fatal(err)
				}
				if ack != o.AckKey || ack != layer1Export(t, env, b.kp) {
					t.Fatalf("Seal's ack_key %x, Open's %x", ack, o.AckKey)
				}
				if ack == (AckKey{}) || seen[ack] {
					t.Fatal("a zero or repeated ack_key")
				}
				seen[ack] = true
				// The token made under the recipient's key verifies under the sender's.
				d := mustDAck(t, o.AckKey, OutcomeProcessed, Note{})
				if _, oc, _, _, ok := VerifyDAck([]AckKey{ack}, d[:]); !ok || oc != OutcomeProcessed {
					t.Fatal("the recipient's token does not verify under Seal's ack_key")
				}
			}
		})
	}
	t.Run("an error returns no key", func(t *testing.T) {
		in := innerFrom(t, a, b, t0)
		in.MID = nil
		if _, ack, err := Seal(in, &b.kp.Public, a.c.Sign, SealOpts{}); err == nil || ack != (AckKey{}) {
			t.Fatalf("Seal of a bad inner: %v, ack_key %x", err, ack)
		}
	})
}

// G3: in SEALED-2B, the two-layer envelope and the same message sealed as one layer under the
// same layer-1 ephemeral key export one ack_key, the file's.
func TestSEALED2BAckKeyIsLayerOne(t *testing.T) {
	var v vecSealed2B
	readVector(t, fileSealed2B, &v)
	kp, _ := v.keys(t, "SEALED-2B")
	two, err := Open(v.Envelope, v.Recipient.AID, StaticKeyRing{kp}, ixKeys{v.RecipientIX.key(t, "SEALED-2B", v.Sender.AID)})
	if err != nil {
		t.Fatal(err)
	}
	one, err := Open(v.SingleLayer.Envelope, v.Recipient.AID, StaticKeyRing{kp}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if two.Layers != 2 || one.Layers != 1 || two.AckKey != one.AckKey || !bytes.Equal(two.AckKey[:], v.AckKey) ||
		!bytes.Equal(one.AckKey[:], v.SingleLayer.AckKey) {
		t.Fatalf("two layers %x, one layer %x, file %x", two.AckKey, one.AckKey, v.AckKey)
	}
	// Without the interaction key the envelope is refused after layer 1, with the same key.
	_, err = Open(v.Envelope, v.Recipient.AID, StaticKeyRing{kp}, nil)
	if k, ok := AckKeyOf(err); !ok || k != two.AckKey {
		t.Fatalf("closed interaction: %v", err)
	}
}

// openCase is one failure of Open: the envelope, who opens it and with what, the reason ("" for
// the lookup's own error) and whether the error carries the ack_key; seal is Seal's ack_key when
// the envelope came out of Seal.
type openCase struct {
	name   string
	env    []byte
	as     *party
	ring   KeyRing
	ix     IXKeyLookup
	reason string
	ack    bool
	seal   *AckKey
}

// openCases are the failures of every step of Open, in step order (FS-C13, engine §4.2). Each
// changes one thing of an envelope that opens.
func openCases(t *testing.T) []openCase {
	t.Helper()
	a, b, c := newParty(t), newParty(t), newParty(t)
	bk := mustIXKey(t, "ix-1", a.aid())
	sealed := func(layers int, h sealHooks) ([]byte, *AckKey) {
		o := SealOpts{}
		if layers == 2 {
			o.PeerRK = bk.RK()
		}
		env, ack := sealCase(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign, o, h)
		return env, &ack
	}
	good, _ := sealed(1, sealHooks{})
	good2, good2Ack := sealed(2, sealHooks{})
	if _, err := Open(good, b.aid(), b.ring(), nil); err != nil {
		t.Fatalf("the base envelope: %v", err)
	}
	if _, err := Open(good2, b.aid(), b.ring(), ixKeys{bk}); err != nil {
		t.Fatalf("the base two-layer envelope: %v", err)
	}
	unsealed, _, err := Seal(innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign, SealOpts{}) // no access yet
	if err != nil {
		t.Fatal(err)
	}
	otherIX := *bk
	otherIX.IX = "ix-2"
	wrongPriv := *bk
	wrongPriv.Private = mustIXKey(t, "ix-1", a.aid()).Private
	storeErr := errors.New("the interaction store cannot be read")

	// Before layer 1 opens: no ack_key.
	pre := func(name string, env []byte, reason string) openCase {
		return openCase{name: name, env: env, as: b, ring: b.ring(), ix: ixKeys{bk}, reason: reason}
	}
	// From step 3a on: the ack_key.
	post := func(name string, env []byte, ack *AckKey, ix IXKeyLookup, reason string) openCase {
		return openCase{name: name, env: env, as: b, ring: b.ring(), ix: ix, reason: reason, ack: true, seal: ack}
	}
	// A failure Seal's hooks build after the signature, with one layer or two.
	hooked := func(name string, layers int, h sealHooks, reason string) openCase {
		env, ack := sealed(layers, h)
		return post(name, env, ack, ixKeys{bk}, reason)
	}
	inner := func(edit func(fieldMap)) sealHooks { return sealHooks{inner: edit} }
	wrap := func(edit func(fieldMap)) sealHooks { return sealHooks{wrap: edit} }
	lookup := func(f func([]byte) (*IXKey, error)) IXKeyLookup { return ixLookupFunc(f) }

	return []openCase{
		// Step 1: the outer, then the recipient.
		pre("1: not CBOR", []byte{0xff}, ReasonBadOuter),
		pre("1: empty", nil, ReasonBadOuter),
		pre("1: not a map", enc(t, "x"), ReasonBadOuter),
		pre("1: v = 1", outerEdit(t, good, func(m fieldMap) { m[outerKeyV] = enc(t, uint64(1)) }), ReasonBadVersion),
		pre("1: v = 3", outerEdit(t, good, func(m fieldMap) { m[outerKeyV] = enc(t, uint64(3)) }), ReasonBadVersion),
		pre("1: outer key 0", outerEdit(t, good, func(m fieldMap) { m[0] = enc(t, uint64(0)) }), ReasonUnknownField),
		pre("1: outer key 9", outerEdit(t, good, func(m fieldMap) { m[9] = enc(t, uint64(0)) }), ReasonUnknownField),
		pre("1: no access", unsealed, ReasonAccessInvalid),
		pre("1: access kind 2", outerEdit(t, good, func(m fieldMap) { m[outerKeyAccess] = enc(t, map[uint64]any{1: uint64(2)}) }), ReasonAccessInvalid),
		pre("1: exp not a number", outerEdit(t, good, func(m fieldMap) { m[outerKeyExp] = enc(t, "x") }), ReasonBadOuter),
		pre("1: no to", outerEdit(t, good, func(m fieldMap) { delete(m, outerKeyTo) }), ReasonBadOuter),
		pre("1: suite 2", outerEdit(t, good, func(m fieldMap) { m[outerKeySuite] = enc(t, uint64(SuiteXWing)) }), ReasonUnknownSuite),
		pre("1: suite 257", outerEdit(t, good, func(m fieldMap) { m[outerKeySuite] = enc(t, uint64(257)) }), ReasonUnknownSuite),
		pre("1: a 15-byte kid", outerEdit(t, good, func(m fieldMap) { m[outerKeyKID] = enc(t, make([]byte, KIDLen-1)) }), ReasonBadOuter),
		pre("1: a 31-byte enc", outerEdit(t, good, func(m fieldMap) { m[outerKeyEnc] = enc(t, make([]byte, 31)) }), ReasonBadOuter),
		pre("1: empty ct", outerEdit(t, good, func(m fieldMap) { m[outerKeyCT] = enc(t, []byte{}) }), ReasonBadOuter),
		{name: "1: another node", env: good, as: c, ring: b.ring(), ix: ixKeys{bk}, reason: ReasonWrongRecipient},
		// Step 2: the kid.
		{name: "2: no key ring", env: good, as: b, ring: nil, ix: ixKeys{bk}, reason: ReasonUnknownKey},
		{name: "2: a ring without the kid", env: good, as: b, ring: c.ring(), ix: ixKeys{bk}, reason: ReasonUnknownKey},
		// Step 3: layer 1.
		pre("3: ct changed", outerEdit(t, good, func(m fieldMap) {
			ct, err := rawBytes(m, outerKeyCT)
			if err != nil {
				t.Fatal(err)
			}
			ct = append([]byte(nil), ct...)
			ct[len(ct)-1] ^= 1
			m[outerKeyCT] = enc(t, ct)
		}), ReasonDecrypt),
		pre("3: the enc of another seal", outerEdit(t, good, func(m fieldMap) {
			other, err := decodeFields(good2)
			if err != nil {
				t.Fatal(err)
			}
			m[outerKeyEnc] = other[outerKeyEnc]
		}), ReasonDecrypt),
		pre("3: a low-order enc", outerEdit(t, good, func(m fieldMap) { m[outerKeyEnc] = enc(t, make([]byte, 32)) }), ReasonDecrypt),

		// Step 3a: the Wrap, the interaction-key lookup and the second layer.
		post("3a: Wrap not a map", encryptWrap(t, enc(t, "x"), b.aid(), &b.kp.Public), nil, ixKeys{bk}, ReasonBadWrap),
		hooked("3a: Wrap key 4", 1, wrap(func(m fieldMap) { m[4] = enc(t, "x") }), ReasonBadWrap),
		hooked("3a: a non-zero pad", 1, wrap(func(m fieldMap) { m[wrapKeyPad] = enc(t, []byte{0, 1}) }), ReasonBadWrap),
		hooked("3a: ikid without enc2", 1, wrap(func(m fieldMap) { m[wrapKeyIKID] = enc(t, bk.KID()) }), ReasonBadWrap),
		post("3a: nil lookup", good2, good2Ack, nil, ReasonSealedToClosedInteraction),
		post("3a: no such key", good2, good2Ack, ixKeys{}, ReasonSealedToClosedInteraction),
		post("3a: the lookup answers another key", good2, good2Ack, lookup(func([]byte) (*IXKey, error) {
			return mustIXKey(t, "ix-1", a.aid()), nil
		}), ReasonSealedToClosedInteraction),
		post("3a: the store fails", good2, good2Ack, lookup(func([]byte) (*IXKey, error) { return nil, storeErr }), ""),
		post("3a: the second layer does not open", good2, good2Ack, ixKeys{&wrongPriv}, ReasonDecrypt),

		// Step 4: the inner, then its comparisons with the interaction key and the outer, then
		// the KEL's caps.
		post("4: inner not a map", encryptPlaintext(t, enc(t, "x"), b.aid(), &b.kp.Public), nil, ixKeys{bk}, ReasonBadInner),
		hooked("4: inner key 0", 1, inner(func(m fieldMap) { m[0] = enc(t, "x") }), ReasonUnknownField),
		hooked("4: inner key 21", 1, inner(func(m fieldMap) { m[21] = enc(t, []byte{0}) }), ReasonUnknownField),
		hooked("4: a 1-byte mid", 1, inner(func(m fieldMap) { m[keyMID] = enc(t, []byte{1}) }), ReasonBadInner),
		hooked("4: from with U+0000", 1, inner(func(m fieldMap) { m[keyFrom] = enc(t, "a\x00b") }), ReasonBadInner),
		hooked("4: a notice without a KEL", 1, inner(func(m fieldMap) { delete(m, keyKEL) }), ReasonBadInner),
		hooked("4: an rk of suite 2", 1, inner(func(m fieldMap) { m[keyRK] = enc(t, &RK{Suite: SuiteXWing, Pub: make([]byte, 32)}) }), ReasonBadRK),
		hooked("4: two layers, a broken inner", 2, inner(func(m fieldMap) { m[keyMID] = enc(t, []byte{1}) }), ReasonBadInner),
		post("4: the interaction key is another interaction's", good2, good2Ack, ixKeys{&otherIX}, ReasonIKeyMismatch),
		hooked("4: inner to is not outer to", 1, inner(func(m fieldMap) { m[keyTo] = enc(t, c.aid()) }), ReasonToMismatch),
		hooked("4: outer exp is not inner exp", 1, sealHooks{outer: func(m fieldMap) { m[outerKeyExp] = enc(t, t0+dayMS+1) }}, ReasonExpMismatch),
		hooked("4: a KEL over its cap", 1, inner(func(m fieldMap) { m[keyKEL] = enc(t, make([]byte, MaxKELBytes+1)) }), ReasonKELTooLarge),
		hooked("4: a KEL that does not decode", 1, inner(func(m fieldMap) { m[keyKEL] = enc(t, []byte{0x01}) }), ReasonBadKEL),
	}
}

// DLV-C-2, DLV-C-API-1, DLV-C-API-2: each failure of Open gives its reason, and the ack_key
// exactly from step 3a on; that key is the layer-1 export and Seal's.
func TestAckKeyOfEveryOpenStep(t *testing.T) {
	for _, c := range openCases(t) {
		t.Run(c.name, func(t *testing.T) {
			_, err := Open(c.env, c.as.aid(), c.ring, c.ix)
			if err == nil {
				t.Fatal("opened")
			}
			if ReasonOf(err) != c.reason {
				t.Fatalf("reason %q, want %q (%v)", ReasonOf(err), c.reason, err)
			}
			k, ok := AckKeyOf(err)
			if ok != c.ack {
				t.Fatalf("AckKeyOf = %v, want %v (%v)", ok, c.ack, err)
			}
			if !ok {
				if k != (AckKey{}) {
					t.Fatal("AckKeyOf false with a key")
				}
				return
			}
			if k == (AckKey{}) || k != layer1Export(t, c.env, c.as.kp) {
				t.Fatal("the ack_key is not the layer-1 export")
			}
			if c.seal != nil && k != *c.seal {
				t.Fatal("the ack_key is not the one Seal returned")
			}
			// Wrapped by a caller, the error still carries the key.
			if w, ok := AckKeyOf(fmt.Errorf("receive: %w", err)); !ok || w != k {
				t.Fatal("a wrapped error lost the ack_key")
			}
		})
	}
	t.Run("not an error of Open", func(t *testing.T) {
		for _, err := range []error{nil, errors.New("x"), fail(ReasonBadInner, "x"), fmt.Errorf("y: %w", fail(ReasonDecrypt, "x"))} {
			if k, ok := AckKeyOf(err); ok || k != (AckKey{}) {
				t.Fatalf("AckKeyOf(%v) = %x, %v", err, k, ok)
			}
		}
	})
}

// openStepFuncs are the functions that make up Open's steps; the reasons they name are the
// reasons Open can return.
var openStepFuncs = []string{"Open", "ParseOuter", "decodeWrap", "openLayer2", "decodeInner", "ParseKEL"}

// Every reason Open's steps can return has a case in openCases (ReasonInternalError, an export
// failure that cannot happen, excepted): a step added to Open without a case here fails.
func TestOpenCasesCoverEveryReason(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	named := map[string]bool{}
	found := map[string]bool{}
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Recv != nil || !slices.Contains(openStepFuncs, fd.Name.Name) {
					continue
				}
				found[fd.Name.Name] = true
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if id, ok := n.(*ast.Ident); ok && strings.HasPrefix(id.Name, "Reason") && id.Name != "ReasonOf" {
						named[id.Name] = true
					}
					return true
				})
			}
		}
	}
	if len(found) != len(openStepFuncs) {
		t.Fatalf("found %v of %v", found, openStepFuncs)
	}
	values := reasonValues(t, pkgs)
	covered := map[string]bool{}
	for _, c := range openCases(t) {
		covered[c.reason] = true
	}
	for name := range named {
		v, ok := values[name]
		if !ok {
			t.Fatalf("%s is not a reason constant", name)
		}
		if name != "ReasonInternalError" && !covered[v] {
			t.Errorf("Open can return %s (%q); openCases has no case for it", name, v)
		}
	}
	if !covered[""] {
		t.Error("no case for the interaction store's own error")
	}
}

// reasonValues maps each Reason* constant of the package's non-test files to its value.
func reasonValues(t *testing.T, pkgs map[string]*ast.Package) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, sp := range gd.Specs {
					vs := sp.(*ast.ValueSpec)
					for i, id := range vs.Names {
						if !strings.HasPrefix(id.Name, "Reason") || i >= len(vs.Values) {
							continue
						}
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							m[id.Name], _ = strconv.Unquote(lit.Value)
						}
					}
				}
			}
		}
	}
	return m
}
