package relayauth

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// sessionVector is relayauth/testdata/vec-session-1.json (SESSION-1). It was made by
// golden/py/gen_v016.py, which shares no code with this package: an HPKE sender written on top of
// a separate X25519 and ChaCha20-Poly1305, and a separate HMAC. Go only opens and recomputes; it
// cannot seal with a chosen ephemeral key.
type sessionVector struct {
	ID          string `json:"id"`
	KeyDelivery struct {
		HubAID string `json:"hub_aid"`
		SID    string `json:"sid"`
		KSess  string `json:"k_sess"`
		IkmR   string `json:"ikmR"`
		SkR    string `json:"skR"`
		EPK    string `json:"epk"`
		IkmE   string `json:"ikmE"`
		Info   string `json:"info"`
		Enc    string `json:"enc"`
		CT     string `json:"ct"`
	} `json:"key_delivery"`
	KeyDeliveryRefused []struct {
		Name   string `json:"name"`
		HubAID string `json:"hub_aid"`
		SID    string `json:"sid"`
		Enc    string `json:"enc"`
		CT     string `json:"ct"`
		Error  string `json:"error"`
	} `json:"key_delivery_refused"`
	MAC        []sessionMACCase `json:"mac"`
	MACRefused []sessionMACCase `json:"mac_refused"`
}

type sessionMACCase struct {
	Name         string `json:"name"`
	KSess        string `json:"k_sess"`
	SID          string `json:"sid"`
	TS           uint64 `json:"ts"`
	Method       string `json:"method"`
	PathAndQuery string `json:"path_and_query"`
	Home         string `json:"home"`
	Body         string `json:"body"`
	Input        string `json:"input"`
	MAC          string `json:"mac"`
	Error        string `json:"error"`
}

func loadSessionVector(t *testing.T) *sessionVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/vec-session-1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v sessionVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.ID != "SESSION-1" {
		t.Fatalf("vector id %q", v.ID)
	}
	return &v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

// errorKind maps the vector's error names to this package's errors.
var errorKind = map[string]error{
	"session-key": ErrSessionKey,
	"nul":         ErrNUL,
	"input":       ErrSessionInput,
	"mac":         ErrSessionMAC,
}

// vectorKey derives the daemon's one-time key from the vector's ikmR the way RFC 9180
// DeriveKeyPair does, and checks it against the recorded skR and epk.
func vectorKey(t *testing.T, v *sessionVector) *ecdh.PrivateKey {
	t.Helper()
	kd := v.KeyDelivery
	derived, err := hpke.DHKEM(ecdh.X25519()).DeriveKeyPair(unhex(t, kd.IkmR))
	if err != nil {
		t.Fatal(err)
	}
	if got := derived.PublicKey().Bytes(); !bytes.Equal(got, unhex(t, kd.EPK)) {
		t.Fatalf("DeriveKeyPair(ikmR) public key\n got  %x\n want %s", got, kd.EPK)
	}
	esk, err := ecdh.X25519().NewPrivateKey(unhex(t, kd.SkR))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(esk.PublicKey().Bytes(), unhex(t, kd.EPK)) {
		t.Fatal("skR does not belong to epk")
	}
	return esk
}

// SESSION-1, L7: the daemon opens the session key the independent implementation sealed, and the
// HPKE info is byte for byte the one it used.
func TestSessionVectorKeyDelivery(t *testing.T) {
	v := loadSessionVector(t)
	kd := v.KeyDelivery
	esk := vectorKey(t, v)
	info, err := sessionKeyInfo(kd.HubAID, unhex(t, kd.SID))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(info, unhex(t, kd.Info)) {
		t.Fatalf("HPKE info\n got  %x\n want %s", info, kd.Info)
	}
	k, err := OpenSessionKey(esk, kd.HubAID, unhex(t, kd.SID), unhex(t, kd.Enc), unhex(t, kd.CT))
	if err != nil {
		t.Fatalf("the vector's session key does not open: %v", err)
	}
	if !bytes.Equal(k, unhex(t, kd.KSess)) {
		t.Fatalf("k_sess\n got  %x\n want %s", k, kd.KSess)
	}
	if len(v.KeyDeliveryRefused) < 5 {
		t.Fatalf("only %d refused key deliveries", len(v.KeyDeliveryRefused))
	}
	for _, r := range v.KeyDeliveryRefused {
		t.Run(r.Name, func(t *testing.T) {
			want, ok := errorKind[r.Error]
			if !ok {
				t.Fatalf("unknown error kind %q", r.Error)
			}
			_, err := OpenSessionKey(esk, r.HubAID, unhex(t, r.SID), unhex(t, r.Enc), unhex(t, r.CT))
			if !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
		})
	}
}

// SESSION-1, L8: the MAC input and output are byte for byte the independent implementation's,
// and every refused variant is refused for the recorded reason.
func TestSessionVectorMAC(t *testing.T) {
	v := loadSessionVector(t)
	if len(v.MAC) < 3 || len(v.MACRefused) < 10 {
		t.Fatalf("%d MAC cases and %d refused", len(v.MAC), len(v.MACRefused))
	}
	for _, c := range v.MAC {
		t.Run(c.Name, func(t *testing.T) {
			k, sid, body := unhex(t, c.KSess), unhex(t, c.SID), unhex(t, c.Body)
			in, err := sessionMACInput(sid, c.TS, c.Method, c.PathAndQuery, c.Home, body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(in, unhex(t, c.Input)) {
				t.Fatalf("MAC input\n got  %x\n want %s", in, c.Input)
			}
			mac, err := SessionMAC(k, sid, c.TS, c.Method, c.PathAndQuery, c.Home, body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(mac, unhex(t, c.MAC)) {
				t.Fatalf("MAC\n got  %x\n want %s", mac, c.MAC)
			}
			if err := VerifySessionMAC(k, sid, c.TS, c.Method, c.PathAndQuery, c.Home, body, mac); err != nil {
				t.Fatalf("its own MAC is refused: %v", err)
			}
		})
	}
	for _, c := range v.MACRefused {
		t.Run("refused/"+c.Name, func(t *testing.T) {
			want, ok := errorKind[c.Error]
			if !ok {
				t.Fatalf("unknown error kind %q", c.Error)
			}
			err := VerifySessionMAC(unhex(t, c.KSess), unhex(t, c.SID), c.TS, c.Method, c.PathAndQuery, c.Home,
				unhex(t, c.Body), unhex(t, c.MAC))
			if !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
		})
	}
}

// The two ends meet: what the hub seals for a fresh one-time key, the daemon opens; another key,
// another hub or another session id does not open it.
func TestSessionKeyRoundTrip(t *testing.T) {
	esk, epk, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(epk) != SessionPublicKeyLen {
		t.Fatalf("epk is %d bytes", len(epk))
	}
	sid := bytes.Repeat([]byte{0x5a}, SessionIDLen)
	k := bytes.Repeat([]byte{0xa5}, SessionKeyLen)
	const hub = "bafyreihub"
	enc, ct, err := SealSessionKey(epk, hub, sid, k)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenSessionKey(esk, hub, sid, enc, ct)
	if err != nil || !bytes.Equal(got, k) {
		t.Fatalf("round trip: %x, %v", got, err)
	}
	other, _, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	otherSID := bytes.Repeat([]byte{0x5b}, SessionIDLen)
	for name, open := range map[string]func() ([]byte, error){
		"another one-time key": func() ([]byte, error) { return OpenSessionKey(other, hub, sid, enc, ct) },
		"another hub":          func() ([]byte, error) { return OpenSessionKey(esk, "bafyreihub2", sid, enc, ct) },
		"another session id":   func() ([]byte, error) { return OpenSessionKey(esk, hub, otherSID, enc, ct) },
	} {
		if _, err := open(); !errors.Is(err, ErrSessionKey) {
			t.Errorf("%s: got %v, want ErrSessionKey", name, err)
		}
	}
	// Each session draws a fresh HPKE ephemeral key: sealing the same key twice gives two answers.
	enc2, _, err := SealSessionKey(epk, hub, sid, k)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enc, enc2) {
		t.Fatal("two seals share an encapsulated key")
	}
}

// Malformed inputs are refused before anything is computed.
func TestSessionKeyRefusesMalformedInput(t *testing.T) {
	esk, epk, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	sid := make([]byte, SessionIDLen)
	k := make([]byte, SessionKeyLen)
	cases := map[string]struct {
		err  error
		call func() error
	}{
		"short epk": {ErrSessionInput, func() error { _, _, err := SealSessionKey(epk[:31], "h", sid, k); return err }},
		"low-order epk (all zero)": {ErrSessionInput, func() error {
			_, _, err := SealSessionKey(make([]byte, 32), "h", sid, k)
			return err
		}},
		"short key":      {ErrSessionInput, func() error { _, _, err := SealSessionKey(epk, "h", sid, k[:31]); return err }},
		"long sid":       {ErrSessionInput, func() error { _, _, err := SealSessionKey(epk, "h", append(sid, 0), k); return err }},
		"empty hub AID":  {ErrSessionInput, func() error { _, _, err := SealSessionKey(epk, "", sid, k); return err }},
		"NUL in hub AID": {ErrNUL, func() error { _, _, err := SealSessionKey(epk, "h\x00", sid, k); return err }},
		"open: NUL in hub AID": {ErrNUL, func() error {
			_, err := OpenSessionKey(esk, "\x00h", sid, make([]byte, 32), make([]byte, 48))
			return err
		}},
		"open: no key": {ErrSessionInput, func() error {
			_, err := OpenSessionKey(nil, "h", sid, make([]byte, 32), make([]byte, 48))
			return err
		}},
		"open: short sid": {ErrSessionInput, func() error {
			_, err := OpenSessionKey(esk, "h", sid[:15], make([]byte, 32), make([]byte, 48))
			return err
		}},
	}
	for name, c := range cases {
		if err := c.call(); !errors.Is(err, c.err) {
			t.Errorf("%s: got %v, want %v", name, err, c.err)
		}
	}
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSessionKey(p256, "h", sid, make([]byte, 32), make([]byte, 48)); !errors.Is(err, ErrSessionInput) {
		t.Errorf("a P-256 key: got %v, want ErrSessionInput", err)
	}
}

// The session MAC binds every input (M16): a request with another body or another home hint, or
// any other changed field, does not verify under the MAC of the original. A MAC that skipped the
// body digest would let anyone holding a captured sid and MAC send a different envelope; one that
// skipped X-ANet-Home would let a relay redirect a send.
func TestSessionMACBindsEveryInput(t *testing.T) {
	k := bytes.Repeat([]byte{1}, SessionKeyLen)
	sid := bytes.Repeat([]byte{2}, SessionIDLen)
	type in struct {
		k, sid             []byte
		ts                 uint64
		method, path, home string
		body               []byte
	}
	base := in{k, sid, 1767225600000, "POST", "/relay/send", "bafyreihomehub", []byte("envelope bytes")}
	mac, err := SessionMAC(base.k, base.sid, base.ts, base.method, base.path, base.home, base.body)
	if err != nil {
		t.Fatal(err)
	}
	if len(mac) != SessionMACLen {
		t.Fatalf("MAC is %d bytes", len(mac))
	}
	variants := map[string]in{
		"another body":              {k, sid, base.ts, base.method, base.path, base.home, []byte("envelope bytez")},
		"body one byte more":        {k, sid, base.ts, base.method, base.path, base.home, []byte("envelope bytes\x00")},
		"empty body":                {k, sid, base.ts, base.method, base.path, base.home, nil},
		"another home hint":         {k, sid, base.ts, base.method, base.path, "bafyreiotherhub", base.body},
		"home hint removed":         {k, sid, base.ts, base.method, base.path, "", base.body},
		"another time":              {k, sid, base.ts + 1, base.method, base.path, base.home, base.body},
		"another method":            {k, sid, base.ts, "PUT", base.path, base.home, base.body},
		"another target":            {k, sid, base.ts, base.method, "/relay/send?x", base.home, base.body},
		"another session id":        {k, bytes.Repeat([]byte{3}, SessionIDLen), base.ts, base.method, base.path, base.home, base.body},
		"another session key":       {bytes.Repeat([]byte{9}, SessionKeyLen), sid, base.ts, base.method, base.path, base.home, base.body},
		"target byte moved to home": {k, sid, base.ts, base.method, "/relay/sen", "d" + base.home, base.body},
		"home byte moved to target": {k, sid, base.ts, base.method, base.path + "b", base.home[1:], base.body},
	}
	for name, v := range variants {
		if err := VerifySessionMAC(v.k, v.sid, v.ts, v.method, v.path, v.home, v.body, mac); !errors.Is(err, ErrSessionMAC) {
			t.Errorf("%s: got %v, want ErrSessionMAC", name, err)
		}
	}
	if err := VerifySessionMAC(k, sid, base.ts, base.method, base.path, base.home, base.body, mac); err != nil {
		t.Fatalf("the original is refused: %v", err)
	}
	for name, bad := range map[string][]byte{
		"MAC one byte short": mac[:SessionMACLen-1],
		"MAC one byte long":  append(bytes.Clone(mac), 0),
		"MAC last bit flipped": func() []byte {
			m := bytes.Clone(mac)
			m[SessionMACLen-1] ^= 1
			return m
		}(),
		"no MAC": nil,
	} {
		if err := VerifySessionMAC(k, sid, base.ts, base.method, base.path, base.home, base.body, bad); !errors.Is(err, ErrSessionMAC) {
			t.Errorf("%s: got %v, want ErrSessionMAC", name, err)
		}
	}
}

// CORE-E9: a text field holding U+0000 is refused, by SessionMAC and VerifySessionMAC alike,
// whatever the MAC; a wrong key or session id length is an input error, not a mismatch.
func TestSessionMACRefusesMalformedInput(t *testing.T) {
	k := make([]byte, SessionKeyLen)
	sid := make([]byte, SessionIDLen)
	for name, c := range map[string]struct {
		k, sid             []byte
		method, path, home string
		err                error
	}{
		"NUL in method":     {k, sid, "PO\x00ST", "/relay/send", "", ErrNUL},
		"NUL in target":     {k, sid, "POST", "/relay/send\x00", "", ErrNUL},
		"NUL in home hint":  {k, sid, "POST", "/relay/send", "\x00", ErrNUL},
		"short session key": {k[:31], sid, "POST", "/relay/send", "", ErrSessionInput},
		"long session id":   {k, append(bytes.Clone(sid), 0), "POST", "/relay/send", "", ErrSessionInput},
	} {
		if _, err := SessionMAC(c.k, c.sid, 1, c.method, c.path, c.home, nil); !errors.Is(err, c.err) {
			t.Errorf("SessionMAC %s: got %v, want %v", name, err, c.err)
		}
		if err := VerifySessionMAC(c.k, c.sid, 1, c.method, c.path, c.home, nil, make([]byte, 32)); !errors.Is(err, c.err) {
			t.Errorf("VerifySessionMAC %s: got %v, want %v", name, err, c.err)
		}
	}
}

// TestVerifySessionMACUsesHMACEqual: the comparison of the received MAC is constant-time. A
// byte-by-byte comparison that stops at the first difference tells a forger, through the hub's
// response time, how many leading bytes of a guess were right, and a MAC can then be found one
// byte at a time. The check reads the source: VerifySessionMAC must call hmac.Equal, and must not
// compare with bytes.Equal, bytes.Compare, == or != on byte or string values.
func TestVerifySessionMACUsesHMACEqual(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "session.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "VerifySessionMAC" {
			fn = fd
		}
	}
	if fn == nil {
		t.Fatal("VerifySessionMAC not found in session.go")
	}
	hmacEqual := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok {
					switch pkg.Name + "." + sel.Sel.Name {
					case "hmac.Equal":
						hmacEqual++
					case "bytes.Equal", "bytes.Compare", "subtle.ConstantTimeCompare", "reflect.DeepEqual", "slices.Equal":
						t.Errorf("%s: VerifySessionMAC compares with %s.%s, not hmac.Equal",
							fset.Position(x.Pos()), pkg.Name, sel.Sel.Name)
					}
				}
			}
		case *ast.BinaryExpr:
			if x.Op == token.EQL || x.Op == token.NEQ {
				for _, side := range []ast.Expr{x.X, x.Y} {
					if call, ok := side.(*ast.CallExpr); ok {
						if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "string" {
							t.Errorf("%s: VerifySessionMAC compares string conversions with %s",
								fset.Position(x.Pos()), x.Op)
						}
					}
					if ix, ok := side.(*ast.IndexExpr); ok {
						t.Errorf("%s: VerifySessionMAC compares bytes one at a time (%v)", fset.Position(ix.Pos()), x.Op)
					}
				}
			}
		case *ast.RangeStmt, *ast.ForStmt:
			t.Errorf("%s: VerifySessionMAC loops; the comparison belongs to hmac.Equal", fset.Position(n.Pos()))
		}
		return true
	})
	if hmacEqual != 1 {
		t.Fatalf("VerifySessionMAC calls hmac.Equal %d times, want exactly once", hmacEqual)
	}
}

// The session header values have one accepted spelling each.
func TestSessionHeaderEncoding(t *testing.T) {
	sid := make([]byte, SessionIDLen)
	mac := make([]byte, SessionMACLen)
	for i := range mac {
		mac[i] = byte(0xf0 + i)
	}
	for i := range sid {
		sid[i] = byte(0xfa + i)
	}
	es, em := EncodeSessionID(sid), EncodeMAC(mac)
	if len(es) != 22 || len(em) != 43 || strings.ContainsAny(es+em, "=+/") {
		t.Fatalf("EncodeSessionID = %q, EncodeMAC = %q: want 22 and 43 unpadded URL-safe characters", es, em)
	}
	if b, err := DecodeSessionID(es); err != nil || !bytes.Equal(b, sid) {
		t.Fatalf("session id round trip: %x, %v", b, err)
	}
	if b, err := DecodeMAC(em); err != nil || !bytes.Equal(b, mac) {
		t.Fatalf("MAC round trip: %x, %v", b, err)
	}
	for name, bad := range map[string]string{
		"padded":            es + "==",
		"standard alphabet": strings.NewReplacer("-", "+", "_", "/").Replace(es),
		"15 bytes":          EncodeSessionID(sid[:15]),
		"17 bytes":          EncodeSessionID(append(bytes.Clone(sid), 0)),
		"a MAC":             em,
		"empty":             "",
		"embedded LF":       es[:10] + "\n" + es[10:21],
		"trailing bits":     es[:21] + string(es[21]+1),
		// The decoder skips CR and LF: these decode to the right 16 bytes, and only the length
		// check refuses them.
		"trailing LF":           es + "\n",
		"embedded LF, all data": es[:10] + "\n" + es[10:],
	} {
		if _, err := DecodeSessionID(bad); !errors.Is(err, ErrBadSessionHeader) {
			t.Errorf("session id %s: want ErrBadSessionHeader, got %v", name, err)
		}
	}
	for name, bad := range map[string]string{
		"padded":        em + "=",
		"31 bytes":      EncodeMAC(mac[:31]),
		"session id":    es,
		"embedded CRLF": em[:20] + "\r\n" + em[20:41],
		// Decodes to the right 32 bytes; only the length check refuses it.
		"embedded CRLF, all data": em[:20] + "\r\n" + em[20:],
	} {
		if _, err := DecodeMAC(bad); !errors.Is(err, ErrBadSessionHeader) {
			t.Errorf("MAC %s: want ErrBadSessionHeader, got %v", name, err)
		}
	}
}

func TestSessionHeaderNamesArePinned(t *testing.T) {
	for _, h := range []struct{ got, want string }{
		{HeaderSession, "X-ANet-Session"}, {HeaderMAC, "X-ANet-MAC"}, {HeaderHome, "X-ANet-Home"},
	} {
		if h.got != h.want {
			t.Errorf("header %q, want %q", h.got, h.want)
		}
	}
}
