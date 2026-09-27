package a2acard

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
)

// The example of A2A §8.4.1, verbatim: REQUIRED members stay at their default, explicitly set
// optional bools stay, an empty repeated field that is not REQUIRED goes.
func TestSigningPayloadSpecExample(t *testing.T) {
	in := `{
	  "name": "Example Agent",
	  "description": "",
	  "capabilities": {
	    "streaming": false,
	    "pushNotifications": false,
	    "extensions": []
	  },
	  "skills": []
	}`
	got, err := SigningPayload([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"capabilities":{"pushNotifications":false,"streaming":false},"description":"","name":"Example Agent","skills":[]}`
	if string(got) != want {
		t.Fatalf("payload\n got %s\nwant %s", got, want)
	}
	raw, err := RawSigningPayload([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"extensions":[]`) {
		t.Fatalf("raw payload lost a member: %s", raw)
	}
}

// Each presence class of schema.go, one member at a time. in is a card fragment; want is the
// proto-stripped payload.
func TestStripDefaultsRules(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		// Implicit presence: the default goes, anything else stays.
		{"implicit empty string", `{"supportedInterfaces":[{"url":"u","tenant":""}]}`, `{"supportedInterfaces":[{"url":"u"}]}`},
		{"implicit set string", `{"supportedInterfaces":[{"tenant":"x"}]}`, `{"supportedInterfaces":[{"tenant":"x"}]}`},
		{"implicit false", `{"capabilities":{"extensions":[{"uri":"u","required":false}]}}`, `{"capabilities":{"extensions":[{"uri":"u"}]}}`},
		{"implicit true", `{"capabilities":{"extensions":[{"required":true}]}}`, `{"capabilities":{"extensions":[{"required":true}]}}`},
		{"implicit empty repeated", `{"skills":[{"id":"s","examples":[],"inputModes":[],"outputModes":[],"securityRequirements":[]}]}`, `{"skills":[{"id":"s"}]}`},
		{"implicit empty map", `{"securitySchemes":{}}`, `{}`},
		{"implicit null", `{"capabilities":{"extensions":null},"securityRequirements":null}`, `{"capabilities":{}}`},
		{"extension description empty", `{"capabilities":{"extensions":[{"uri":"u","description":""}]}}`, `{"capabilities":{"extensions":[{"uri":"u"}]}}`},
		{"plain bool pkceRequired", `{"securitySchemes":{"o":{"oauth2SecurityScheme":{"flows":{"authorizationCode":{"pkceRequired":false,"scopes":{}}}}}}}`,
			`{"securitySchemes":{"o":{"oauth2SecurityScheme":{"flows":{"authorizationCode":{"scopes":{}}}}}}}`},

		// Explicit presence (optional keyword, messages, oneof members): set stays at any value.
		{"optional false", `{"capabilities":{"streaming":false,"extendedAgentCard":false}}`, `{"capabilities":{"extendedAgentCard":false,"streaming":false}}`},
		{"optional empty string", `{"iconUrl":"","documentationUrl":""}`, `{"documentationUrl":"","iconUrl":""}`},
		{"optional null", `{"iconUrl":null,"capabilities":{"streaming":null}}`, `{"capabilities":{}}`},
		{"empty message", `{"provider":{}}`, `{"provider":{}}`},
		{"message null", `{"provider":null}`, `{}`},
		{"empty params", `{"capabilities":{"extensions":[{"params":{}}]}}`, `{"capabilities":{"extensions":[{"params":{}}]}}`},
		{"oneof member empty", `{"securitySchemes":{"m":{"mtlsSecurityScheme":{"description":""}}}}`, `{"securitySchemes":{"m":{"mtlsSecurityScheme":{}}}}`},

		// REQUIRED: stays even at the default.
		{"required empty", `{"name":"","description":"","version":"","skills":[],"defaultInputModes":[],"defaultOutputModes":[],"supportedInterfaces":[]}`,
			`{"defaultInputModes":[],"defaultOutputModes":[],"description":"","name":"","skills":[],"supportedInterfaces":[],"version":""}`},
		{"required null", `{"name":null}`, `{"name":null}`},
		{"required nested", `{"skills":[{"id":"","tags":[]}],"supportedInterfaces":[{"protocolVersion":""}]}`, `{"skills":[{"id":"","tags":[]}],"supportedInterfaces":[{"protocolVersion":""}]}`},
		{"required map", `{"securitySchemes":{"o":{"oauth2SecurityScheme":{"flows":{"clientCredentials":{"scopes":{},"refreshUrl":""}}}}}}`,
			`{"securitySchemes":{"o":{"oauth2SecurityScheme":{"flows":{"clientCredentials":{"scopes":{}}}}}}}`},

		// Map values are always emitted; a map value message is stripped inside.
		{"map value message", `{"securityRequirements":[{"schemes":{"a":{},"b":{"list":[]}}}]}`, `{"securityRequirements":[{"schemes":{"a":{},"b":{}}}]}`},
		{"string map value", `{"securitySchemes":{"o":{"oauth2SecurityScheme":{"flows":{"implicit":{"scopes":{"read":""}}}}}}}`,
			`{"securitySchemes":{"o":{"oauth2SecurityScheme":{"flows":{"implicit":{"scopes":{"read":""}}}}}}}`},
		{"scheme description", `{"securitySchemes":{"b":{"httpAuthSecurityScheme":{"scheme":"Bearer","description":"","bearerFormat":""}}}}`,
			`{"securitySchemes":{"b":{"httpAuthSecurityScheme":{"scheme":"Bearer"}}}}`},

		// Struct content is not a message and is never stripped.
		{"struct content", `{"capabilities":{"extensions":[{"params":{"a":"","b":[],"c":{},"d":null,"e":false,"f":0}}]}}`,
			`{"capabilities":{"extensions":[{"params":{"a":"","b":[],"c":{},"d":null,"e":false,"f":0}}]}}`},
		{"struct content nested", `{"capabilities":{"extensions":[{"params":{"x":{"required":false,"tenant":""}}}]}}`,
			`{"capabilities":{"extensions":[{"params":{"x":{"required":false,"tenant":""}}}]}}`},

		// Unknown members and type mismatches stay: they are covered by the signature.
		{"unknown members", `{"x-a":"","x-b":null,"x-c":[],"supported_interfaces":[]}`, `{"supported_interfaces":[],"x-a":"","x-b":null,"x-c":[]}`},
		{"unknown nested", `{"skills":[{"id":"s","x":""}]}`, `{"skills":[{"id":"s","x":""}]}`},
		{"type mismatch", `{"supportedInterfaces":[{"tenant":0}],"capabilities":{"extensions":[{"required":"false"}]}}`,
			`{"capabilities":{"extensions":[{"required":"false"}]},"supportedInterfaces":[{"tenant":0}]}`},
		{"message as array", `{"capabilities":[],"skills":["x"]}`, `{"capabilities":[],"skills":["x"]}`},

		// Only the top-level signatures member is excluded.
		{"signatures", `{"signatures":[{"protected":"p","signature":"s","header":{}}],"name":"n"}`, `{"name":"n"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SigningPayload([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("payload\n got %s\nwant %s", got, tc.want)
			}
			// Idempotent: stripping the stripped form changes nothing.
			again, err := SigningPayload(got)
			if err != nil {
				t.Fatal(err)
			}
			if string(again) != string(got) {
				t.Fatalf("not idempotent:\n%s\n%s", got, again)
			}
		})
	}
}

// Every card that CheckPublishForm accepts has one payload: the proto-stripped and the raw
// form coincide, so each verifier computes the same bytes.
func TestPublishFormPayloadsCoincide(t *testing.T) {
	c := incept(t)
	for name, card := range map[string]map[string]any{
		"base":   baseCard(c.AID()),
		"golden": goldenCard(c.AID()),
		"full":   fullCard(c.AID()),
	} {
		cj := marshal(t, card)
		if err := CheckPublishForm(cj); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		s, err := SigningPayload(cj)
		if err != nil {
			t.Fatal(err)
		}
		r, err := RawSigningPayload(cj)
		if err != nil {
			t.Fatal(err)
		}
		if string(s) != string(r) {
			t.Fatalf("%s: payloads differ:\n%s\n%s", name, s, r)
		}
	}
}

// fullCard is a publish-form card that uses every kind of member: provider, optional strings,
// a security scheme and requirement with a scope, skill modes and examples, extension
// description, required and params with a nested false.
func fullCard(aid string) map[string]any {
	card := baseCard(aid)
	card["provider"] = map[string]any{"url": "https://example.org", "organization": "Example"}
	card["documentationUrl"] = "https://example.org/docs"
	card["iconUrl"] = "https://example.org/icon.png"
	card["securitySchemes"] = map[string]any{
		"bearer": map[string]any{"httpAuthSecurityScheme": map[string]any{"scheme": "Bearer", "bearerFormat": "opaque"}},
		"oauth": map[string]any{"oauth2SecurityScheme": map[string]any{"flows": map[string]any{
			"authorizationCode": map[string]any{
				"authorizationUrl": "https://example.org/auth", "tokenUrl": "https://example.org/token",
				"scopes": map[string]any{"read": "Read access"}, "pkceRequired": true,
			},
		}}},
		// The deprecated implicit flow with the members a2a-go always writes (goWrites).
		"legacy": map[string]any{"oauth2SecurityScheme": map[string]any{"flows": map[string]any{
			"implicit": map[string]any{"authorizationUrl": "https://example.org/auth", "scopes": map[string]any{"read": "Read access"}},
		}}},
	}
	card["securityRequirements"] = []any{map[string]any{"schemes": map[string]any{"bearer": map[string]any{"list": []any{"a2a"}}}}}
	caps := card["capabilities"].(map[string]any)
	caps["extendedAgentCard"] = true
	caps["extensions"] = append(extensions(card), map[string]any{
		"uri": "https://example.org/ext/v1", "description": "An extension.", "required": true,
		"params": map[string]any{"clientPayload": false, "n": 1.5, "list": []any{"a", map[string]any{"b": "c"}}},
	})
	sk := skill(card, 0)
	sk["examples"] = []any{"echo hi"}
	sk["inputModes"] = []any{"text/plain"}
	sk["outputModes"] = []any{"text/plain"}
	sk["securityRequirements"] = []any{map[string]any{"schemes": map[string]any{"oauth": map[string]any{"list": []any{"read"}}}}}
	return card
}

// Each rule of CheckPublishForm, with the path its error names.
func TestCheckPublishFormRejections(t *testing.T) {
	c := incept(t)
	cases := []struct {
		name string
		f    func(m map[string]any)
		path string
		code Code
	}{
		{"x402 required false (A2A-DESIGN §8.7)", func(m map[string]any) {
			caps := m["capabilities"].(map[string]any)
			caps["extensions"] = append(extensions(m), map[string]any{"uri": "https://github.com/google-agentic-commerce/a2a-x402/blob/main/spec/v0.2", "required": false})
		}, "capabilities.extensions[1].required", CodeNotPublishForm},
		{"extension description empty", func(m map[string]any) { extensions(m)[0].(map[string]any)["description"] = "" }, "capabilities.extensions[0].description", CodeNotPublishForm},
		{"tenant empty", func(m map[string]any) { iface(m, 0)["tenant"] = "" }, "supportedInterfaces[0].tenant", CodeNotPublishForm},
		{"examples empty", func(m map[string]any) { skill(m, 0)["examples"] = []any{} }, "skills[0].examples", CodeNotPublishForm},
		{"securitySchemes empty", func(m map[string]any) { m["securitySchemes"] = map[string]any{} }, "securitySchemes", CodeNotPublishForm},
		{"null member", func(m map[string]any) { m["iconUrl"] = nil }, "iconUrl", CodeNotPublishForm},
		{"optional string empty", func(m map[string]any) { m["documentationUrl"] = "" }, "documentationUrl", CodeNotPublishForm},

		{"REQUIRED description empty", func(m map[string]any) { m["description"] = "" }, "description", CodeNotPublishForm},
		{"REQUIRED skill description empty", func(m map[string]any) { skill(m, 0)["description"] = "" }, "skills[0].description", CodeNotPublishForm},
		{"REQUIRED version missing", func(m map[string]any) { delete(m, "version") }, "version", CodeNotPublishForm},
		{"REQUIRED skills empty", func(m map[string]any) { m["skills"] = []any{} }, "skills", CodeNotPublishForm},
		{"REQUIRED tags missing", func(m map[string]any) { delete(skill(m, 0), "tags") }, "skills[0].tags", CodeNotPublishForm},
		{"REQUIRED defaultInputModes empty", func(m map[string]any) { m["defaultInputModes"] = []any{} }, "defaultInputModes", CodeNotPublishForm},
		{"REQUIRED protocolVersion empty", func(m map[string]any) { iface(m, 0)["protocolVersion"] = "" }, "supportedInterfaces[0].protocolVersion", CodeNotPublishForm},
		{"REQUIRED provider organization missing", func(m map[string]any) { m["provider"] = map[string]any{"url": "https://example.org"} }, "provider.organization", CodeNotPublishForm},
		{"empty string in a repeated field", func(m map[string]any) { skill(m, 0)["tags"] = []any{"a", ""} }, "skills[0].tags[1]", CodeNotPublishForm},

		{"unknown member", func(m map[string]any) { m["x-count"] = 1 }, "x-count", CodeNotPublishForm},
		{"snake_case alias", func(m map[string]any) { m["default_input_modes"] = []any{"text/plain"} }, "default_input_modes", CodeNotPublishForm},
		{"pre-1.0 member", func(m map[string]any) { m["url"] = "https://example.org/a2a" }, "url", CodeNotPublishForm},
		{"unknown nested member", func(m map[string]any) { skill(m, 0)["weight"] = "1" }, "skills[0].weight", CodeNotPublishForm},

		{"wrong type string", func(m map[string]any) { m["version"] = 1 }, "version", CodeNotPublishForm},
		{"wrong type bool", func(m map[string]any) { m["capabilities"].(map[string]any)["streaming"] = "false" }, "capabilities.streaming", CodeNotPublishForm},
		{"wrong type message", func(m map[string]any) { m["capabilities"] = []any{"x"} }, "capabilities", CodeNotPublishForm},
		{"wrong type params", func(m map[string]any) { extensions(m)[0].(map[string]any)["params"] = "x" }, "capabilities.extensions[0].params", CodeNotPublishForm},

		{"empty string in params", func(m map[string]any) { params(m)["note"] = "" }, "capabilities.extensions[0].params.note", CodeNotPublishForm},
		{"empty array in params", func(m map[string]any) { params(m)["list"] = []any{} }, "capabilities.extensions[0].params.list", CodeNotPublishForm},
		{"empty object in params", func(m map[string]any) { params(m)["obj"] = map[string]any{"x": map[string]any{}} }, "capabilities.extensions[0].params.obj.x", CodeNotPublishForm},
		{"null in params", func(m map[string]any) { params(m)["n"] = nil }, "capabilities.extensions[0].params.n", CodeNotPublishForm},
		{"empty params", func(m map[string]any) {
			caps := m["capabilities"].(map[string]any)
			caps["extensions"] = append(extensions(m), map[string]any{"uri": "https://example.org/e", "params": map[string]any{}})
		}, "capabilities.extensions[1].params", CodeNotPublishForm},
		{"empty scope list", func(m map[string]any) {
			m["securitySchemes"] = map[string]any{"anetLocal": map[string]any{"httpAuthSecurityScheme": map[string]any{"scheme": "Bearer"}}}
			m["securityRequirements"] = []any{map[string]any{"schemes": map[string]any{"anetLocal": map[string]any{}}}}
		}, "securityRequirements[0].schemes.anetLocal", CodeNotPublishForm},

		// oneof: a2a-python's ParseDict and a2a-go refuse two members, so no verifier parses it.
		{"two security scheme members", func(m map[string]any) {
			m["securitySchemes"] = map[string]any{"s": map[string]any{
				"httpAuthSecurityScheme": map[string]any{"scheme": "Bearer"},
				"apiKeySecurityScheme":   map[string]any{"location": "header", "name": "X-Key"},
			}}
		}, "securitySchemes.s", CodeNotPublishForm},
		{"two OAuth flows", func(m map[string]any) {
			m["securitySchemes"] = map[string]any{"o": map[string]any{"oauth2SecurityScheme": map[string]any{"flows": map[string]any{
				"authorizationCode": map[string]any{"authorizationUrl": "https://e.org/a", "tokenUrl": "https://e.org/t", "scopes": map[string]any{"r": "R"}},
				"clientCredentials": map[string]any{"tokenUrl": "https://e.org/t", "scopes": map[string]any{"r": "R"}},
			}}}}
		}, "securitySchemes.o.oauth2SecurityScheme.flows", CodeNotPublishForm},

		// Members a2a-go writes on every serialization although a2a.proto does not require them.
		{"implicit flow without authorizationUrl", func(m map[string]any) {
			m["securitySchemes"] = map[string]any{"o": map[string]any{"oauth2SecurityScheme": map[string]any{"flows": map[string]any{
				"implicit": map[string]any{"scopes": map[string]any{"r": "R"}},
			}}}}
		}, "securitySchemes.o.oauth2SecurityScheme.flows.implicit.authorizationUrl", CodeNotPublishForm},
		{"password flow without scopes", func(m map[string]any) {
			m["securitySchemes"] = map[string]any{"o": map[string]any{"oauth2SecurityScheme": map[string]any{"flows": map[string]any{
				"password": map[string]any{"tokenUrl": "https://e.org/t"},
			}}}}
		}, "securitySchemes.o.oauth2SecurityScheme.flows.password.scopes", CodeNotPublishForm},
		{"streaming missing", func(m map[string]any) { delete(m["capabilities"].(map[string]any), "streaming") }, "capabilities.streaming", CodeNotPublishForm},
		{"pushNotifications missing", func(m map[string]any) { delete(m["capabilities"].(map[string]any), "pushNotifications") }, "capabilities.pushNotifications", CodeNotPublishForm},
		{"extendedAgentCard false", func(m map[string]any) { m["capabilities"].(map[string]any)["extendedAgentCard"] = false }, "capabilities.extendedAgentCard", CodeNotPublishForm},

		{"case-folded names", func(m map[string]any) { params(m)["AID"] = "x" }, "", CodeInvalidCard},
		{"signatures not an array", func(m map[string]any) { m["signatures"] = map[string]any{} }, "", CodeInvalidCard},
		// An existing entry is outside the payload, but a malformed one makes every SDK refuse
		// to parse the card.
		{"existing signature entry without signature", func(m map[string]any) {
			m["signatures"] = []any{map[string]any{"protected": "eyJhbGciOiJFZERTQSJ9"}}
		}, "signatures[0].signature", CodeNotPublishForm},
		{"existing signature entry header not an object", func(m map[string]any) {
			m["signatures"] = []any{map[string]any{"protected": "eyJhbGciOiJFZERTQSJ9", "signature": "c2ln", "header": "h"}}
		}, "signatures[0].header", CodeNotPublishForm},
		{"existing signature entry not an object", func(m map[string]any) { m["signatures"] = []any{"x"} }, "signatures[0]", CodeNotPublishForm},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			card := baseCard(c.AID())
			tc.f(card)
			cj := marshal(t, card)
			err := CheckPublishForm(cj)
			wantCode(t, err, tc.code)
			if tc.path != "" && !strings.Contains(err.Error(), ": "+tc.path+": ") {
				t.Fatalf("error %q does not name %s", err, tc.path)
			}
			// Sign refuses the same card and signs nothing.
			out, serr := SignWithController(cj, c, "")
			if out != nil || !IsCode(serr, tc.code) {
				t.Fatalf("Sign: out %q err %v, want %s", out, serr, tc.code)
			}
		})
	}
	if err := CheckPublishForm([]byte(`[]`)); !IsCode(err, CodeInvalidCard) {
		t.Fatalf("array: %v", err)
	}
	if err := CheckPublishForm([]byte(`{"a":1,"a":1}`)); !IsCode(err, CodeMalformedJSON) {
		t.Fatalf("duplicate member: %v", err)
	}
}

// A signed card in publish form still verifies after a relaying party adds members that
// proto3 treats as unset, and PayloadHash does not move: A2A §8.4.3 strips them before
// verifying. Members with a value, or unknown ones, are covered and break the signature.
func TestVerifyToleratesAddedDefaults(t *testing.T) {
	c := incept(t)
	card := baseCard(c.AID())
	addIface(card, nil)
	good := signCard(t, card, c)
	base, err := Verify(good, newResolver(c).resolve, t0)
	if err != nil {
		t.Fatal(err)
	}
	if base.CanonicalForm != FormProtoStripped {
		t.Fatalf("CanonicalForm = %q", base.CanonicalForm)
	}

	tolerated := map[string]func(m map[string]any){
		"extension required false": func(m map[string]any) { extensions(m)[0].(map[string]any)["required"] = false },
		"extension description":    func(m map[string]any) { extensions(m)[0].(map[string]any)["description"] = "" },
		"tenant empty":             func(m map[string]any) { iface(m, 1)["tenant"] = "" },
		"skill examples empty":     func(m map[string]any) { skill(m, 0)["examples"] = []any{} },
		"security members empty":   func(m map[string]any) { m["securitySchemes"] = map[string]any{}; m["securityRequirements"] = []any{} },
		"optional null":            func(m map[string]any) { m["iconUrl"] = nil; m["provider"] = nil },
		"skill inputModes null":    func(m map[string]any) { skill(m, 0)["inputModes"] = nil },
	}
	for name, f := range tolerated {
		v, err := Verify(edit(t, good, f), newResolver(c).resolve, t0)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if v.CanonicalForm != FormProtoStripped || v.PayloadHash != base.PayloadHash {
			t.Errorf("%s: form %q, hash changed %v", name, v.CanonicalForm, v.PayloadHash != base.PayloadHash)
		}
	}

	covered := map[string]func(m map[string]any){
		"extension required true":    func(m map[string]any) { extensions(m)[0].(map[string]any)["required"] = true },
		"optional explicit false":    func(m map[string]any) { m["capabilities"].(map[string]any)["extendedAgentCard"] = false },
		"optional explicit empty":    func(m map[string]any) { m["iconUrl"] = "" },
		"empty provider message":     func(m map[string]any) { m["provider"] = map[string]any{} },
		"unknown member":             func(m map[string]any) { m["x-extra"] = "" },
		"empty string inside params": func(m map[string]any) { params(m)["note"] = "" },
		"streaming removed":          func(m map[string]any) { delete(m["capabilities"].(map[string]any), "streaming") },
	}
	for name, f := range covered {
		_, err := Verify(edit(t, good, f), newResolver(c).resolve, t0)
		if !IsCode(err, CodeInvalidSignature) {
			t.Errorf("%s: err %v, want %s", name, err, CodeInvalidSignature)
		}
	}
}

// uri has implicit presence, so an extension without it declares the empty uri: Verify skips
// it instead of rejecting the card. a2a-python omits an empty uri when it renders a card.
func TestVerifySkipsExtensionWithoutURI(t *testing.T) {
	c := incept(t)
	for name, ext := range map[string]map[string]any{
		"no uri":   {"description": "An extension without a uri."},
		"null uri": {"uri": nil, "required": true},
	} {
		card := baseCard(c.AID())
		caps := card["capabilities"].(map[string]any)
		caps["extensions"] = append([]any{ext}, extensions(card)...)
		if _, err := Verify(signLoose(t, card, c), newResolver(c).resolve, t0); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func addIface(m map[string]any, extra map[string]any) {
	it := map[string]any{"url": "https://direct.example.org/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
	for k, v := range extra {
		it[k] = v
	}
	m["supportedInterfaces"] = append(m["supportedInterfaces"].([]any), it)
}

// A card signed over its raw form while carrying default values (what a2a-go does) verifies
// through the fallback. Its PayloadHash is the proto-stripped one, so it is the same statement
// as the publish-form card without those members, and the high-water rule treats the pair as
// the same card rather than a fork.
func TestVerifyRawFallback(t *testing.T) {
	c := incept(t)
	withDefaults := baseCard(c.AID())
	extensions(withDefaults)[0].(map[string]any)["required"] = false
	skill(withDefaults, 0)["examples"] = []any{}
	iface(withDefaults, 0)["tenant"] = c.AID()
	addIface(withDefaults, map[string]any{"tenant": ""})

	raw := signRaw(t, withDefaults, c)
	v, err := Verify(raw, newResolver(c).resolve, t0)
	if err != nil {
		t.Fatalf("raw-signed card rejected: %v", err)
	}
	if v.CanonicalForm != FormRaw {
		t.Fatalf("CanonicalForm = %q, want %q", v.CanonicalForm, FormRaw)
	}
	stripped, err := SigningPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if v.PayloadHash != sha256.Sum256(stripped) {
		t.Fatal("PayloadHash is not the proto-stripped payload's hash")
	}

	clean := baseCard(c.AID())
	addIface(clean, nil)
	pv, err := Verify(signCard(t, clean, c), newResolver(c).resolve, t0)
	if err != nil {
		t.Fatal(err)
	}
	if pv.PayloadHash != v.PayloadHash {
		t.Fatal("the raw-signed card and its publish-form twin have different PayloadHash")
	}
	if d, err := CheckHighWater(&Mark{Seq: pv.Seq, PayloadHash: pv.PayloadHash}, v.Mark()); err != nil || d != Same {
		t.Fatalf("high water: %v %v, want same", d, err)
	}

	// The raw form covers every member: removing a default-valued one breaks it, and the
	// stripped form does not match either.
	for name, f := range map[string]func(m map[string]any){
		"default removed": func(m map[string]any) { delete(extensions(m)[0].(map[string]any), "required") },
		"default added":   func(m map[string]any) { skill(m, 0)["inputModes"] = []any{} },
		"value changed":   func(m map[string]any) { m["name"] = "Other" },
	} {
		_, err := Verify(edit(t, raw, f), newResolver(c).resolve, t0)
		if !IsCode(err, CodeInvalidSignature) {
			t.Errorf("%s: err %v, want %s", name, err, CodeInvalidSignature)
		}
	}

	// VerifySignatureForm reports the same form for a trusted key.
	sigs := signaturesOf(t, raw)
	if _, form, err := VerifySignatureForm(raw, sigs[0], c.CurrentPrivateKey().Public().(ed25519.PublicKey)); err != nil || form != FormRaw {
		t.Fatalf("VerifySignatureForm: %q %v", form, err)
	}
}
