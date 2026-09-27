package a2acard

import "strconv"

// CanonicalForm names the payload a signature was checked against.
type CanonicalForm string

const (
	// FormProtoStripped is the A2A §8.4.1 payload: the card with the top-level "signatures"
	// member removed and every member that proto3 field presence treats as unset removed (see
	// stripDefaults), in RFC 8785 form. This is what the A2A specification and a2a-python sign,
	// and what Sign signs.
	FormProtoStripped CanonicalForm = "proto-stripped"
	// FormRaw is the card with only the top-level "signatures" member removed, in RFC 8785
	// form. a2a-go signs and verifies this payload; Verify falls back to it so that a card
	// a2a-go signed while carrying default values (for example "required": false on an
	// extension) is still accepted.
	FormRaw CanonicalForm = "raw"
)

// stripDefaults returns v, parsed as a message of schema m, with the members removed that the
// proto3 JSON mapping would not emit for the message v decodes to (A2A §8.4.1 rule 1):
//
//   - a member of a field with implicit presence that holds its type's default: "" for a
//     string, false for a bool, [] for a repeated field, {} for a map;
//   - null for any field that is not REQUIRED (proto3 JSON reads null as "unset");
//   - nothing else: REQUIRED members stay even at their default, members of explicit-presence
//     fields (optional scalars, messages, Struct) stay whatever their value, and so do members
//     the schema does not know.
//
// Messages nested in message, repeated-message and map-of-message fields are stripped by the
// same rule. The inside of a google.protobuf.Struct (AgentExtension.params, the signature
// header) is free-form JSON, not a message, and is kept as it is. A member whose JSON type does
// not match the schema is kept unchanged: it is not a default of its field.
//
// Unknown members are kept rather than dropped because the signature must cover everything a
// consumer of the stored bytes may read. A verifier that parses the card into the schema drops
// them and computes another payload, so a card with unknown members does not verify there; the
// publish form (CheckPublishForm) excludes them.
//
// The result shares unchanged subtrees with v. stripDefaults is idempotent.
func stripDefaults(v *value, m *message) *value {
	if v.kind != kindObject {
		return v
	}
	out := &value{kind: kindObject, obj: make(map[string]*value, len(v.obj))}
	for name, mv := range v.obj {
		f, known := m.fields[name]
		if !known {
			out.obj[name] = mv
			continue
		}
		if f.pres != required {
			if mv.kind == kindNull {
				continue
			}
			if f.pres == implicit && isDefault(mv, f.typ) {
				continue
			}
		}
		out.obj[name] = stripField(mv, f)
	}
	return out
}

func stripField(v *value, f field) *value {
	switch f.typ {
	case tMessage:
		return stripDefaults(v, f.msg)
	case tMessages:
		if v.kind != kindArray {
			return v
		}
		out := &value{kind: kindArray, arr: make([]*value, len(v.arr))}
		for i, e := range v.arr {
			out.arr[i] = stripDefaults(e, f.msg)
		}
		return out
	case tMessageMap:
		if v.kind != kindObject {
			return v
		}
		out := &value{kind: kindObject, obj: make(map[string]*value, len(v.obj))}
		for k, e := range v.obj {
			out.obj[k] = stripDefaults(e, f.msg)
		}
		return out
	default:
		return v
	}
}

// isDefault reports whether v is the proto3 default of a field of type t. Singular message
// fields have explicit presence and no default in this sense.
func isDefault(v *value, t fieldType) bool {
	switch t {
	case tString:
		return v.kind == kindString && v.str == ""
	case tBool:
		return v.kind == kindBool && !v.b
	case tStrings, tMessages:
		return v.kind == kindArray && len(v.arr) == 0
	case tStringMap, tMessageMap:
		return v.kind == kindObject && len(v.obj) == 0
	}
	return false
}

// payloads computes the proto-stripped and the raw payload of a parsed card.
func payloads(card *value) (stripped, raw []byte, err error) {
	if raw, err = canonicalPayload(card); err != nil {
		return nil, nil, err
	}
	if stripped, err = canonicalPayload(stripDefaults(card, schemaAgentCard)); err != nil {
		return nil, nil, err
	}
	return stripped, raw, nil
}

// CheckPublishForm reports whether cardJSON is an AgentCard in publish form: the form Sign
// accepts, on which every verifier this package knows computes the same payload. The A2A
// specification's rule (§8.4.1), a2a-python (proto → MessageToDict → drop empty strings,
// arrays and objects → RFC 8785) and a2a-go (RFC 8785 over the bytes as given, and over its
// own re-serialization) agree exactly on cards in this form, so a signature made here verifies
// under all of them.
//
// A card is in publish form when:
//
//  1. it is a strict I-JSON object (see Canonicalize) with no two member names equal under
//     case folding (see Verify);
//  2. every member of every schema message is a field of that message (schema.go): a
//     verifier that parses the card into the A2A schema drops unknown members, including the
//     snake_case spellings of field names and the pre-1.0 members (url, preferredTransport,
//     ...);
//  3. every REQUIRED field is present and every member has its field's JSON type;
//  4. no member anywhere in the payload is null, an empty string, an empty array or an empty
//     object, and no plain (non-optional) bool is false. For fields with implicit presence
//     this is A2A §8.4.1's "default values MUST be omitted". For REQUIRED fields, optional
//     strings, map values and the inside of google.protobuf.Struct values it is where
//     a2a-python and the specification disagree: the specification keeps "description": ""
//     and "params": {"note": ""}, a2a-python removes them, so no card holding them verifies in
//     both;
//  5. capabilities has streaming and pushNotifications, and extendedAgentCard, when present,
//     is true. a2a-go always writes the first two and omits the third when false, so any other
//     card changes when a2a-go parses and re-serializes it (A2A-DESIGN §10.1).
//
// Consequences for card builders: an extension that is not required omits "required" (never
// "required": false, A2A-DESIGN §8.7); a skill always has a non-empty description and at least
// one tag (see DefaultSkillDescription); a security requirement names each scheme with a
// non-empty scope list, because {"schemes": {"s": {}}} is dropped whole by a2a-python.
//
// The top-level "signatures" member is not part of the payload and is only checked to be an
// array. Violations are reported as CodeNotPublishForm with the member's path; parse failures
// keep their own codes.
func CheckPublishForm(cardJSON []byte) error {
	card, err := parseCard(cardJSON)
	if err != nil {
		return err
	}
	return checkPublishForm(card)
}

func checkPublishForm(card *value) error {
	if err := checkCaseDistinctNames(card); err != nil {
		return err
	}
	if sigs, ok := card.member("signatures"); ok && sigs.kind != kindArray {
		return newErr(CodeInvalidCard, "signatures is not an array")
	}
	if err := publishMessage(card, schemaAgentCard, "", "signatures"); err != nil {
		return err
	}
	caps := card.obj["capabilities"] // present and an object: checked above
	for _, name := range []string{"streaming", "pushNotifications"} {
		if _, ok := caps.member(name); !ok {
			return notPublish("capabilities."+name, "missing; a2a-go writes it on re-serialization, so the payload would change")
		}
	}
	if e, ok := caps.member("extendedAgentCard"); ok && !e.b {
		return notPublish("capabilities.extendedAgentCard", "false; a2a-go omits it on re-serialization, so the payload would change")
	}
	return nil
}

func notPublish(path, why string) *Error {
	return newErr(CodeNotPublishForm, path+": "+why)
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

func index(path string, i int) string { return path + "[" + strconv.Itoa(i) + "]" }

// publishMessage checks v against schema m. skip names a member excluded from the payload.
func publishMessage(v *value, m *message, path, skip string) error {
	where := path
	if where == "" {
		where = "card"
	}
	if v.kind != kindObject {
		return notPublish(where, "not a JSON object ("+m.name+")")
	}
	if len(v.obj) == 0 {
		return notPublish(where, "empty object ("+m.name+"); a2a-python drops empty objects")
	}
	for _, name := range sortedNames(v.obj) {
		if name == skip {
			continue
		}
		f, known := m.fields[name]
		if !known {
			return notPublish(join(path, name), "not a field of "+m.name+"; a verifier that parses the card into the A2A schema drops it")
		}
		if err := publishField(v.obj[name], f, join(path, name)); err != nil {
			return err
		}
	}
	for _, name := range sortedFieldNames(m) {
		if m.fields[name].pres != required {
			continue
		}
		if _, ok := v.obj[name]; !ok {
			return notPublish(join(path, name), "missing; the field is REQUIRED in "+m.name)
		}
	}
	return nil
}

func publishField(v *value, f field, path string) error {
	if v.kind == kindNull {
		return notPublish(path, "null; omit the member")
	}
	switch f.typ {
	case tString:
		if v.kind != kindString {
			return notPublish(path, "not a string")
		}
		if v.str == "" {
			return notPublish(path, emptyWhy(f))
		}
	case tBool:
		if v.kind != kindBool {
			return notPublish(path, "not a boolean")
		}
		if !v.b && f.pres == implicit {
			return notPublish(path, "false is the default of this field; omit the member (A2A §8.4.1)")
		}
	case tMessage:
		return publishMessage(v, f.msg, path, "")
	case tStruct:
		if v.kind != kindObject {
			return notPublish(path, "not a JSON object (google.protobuf.Struct)")
		}
		return publishStruct(v, path)
	case tStrings, tMessages:
		if v.kind != kindArray {
			return notPublish(path, "not an array")
		}
		if len(v.arr) == 0 {
			return notPublish(path, emptyWhy(f))
		}
		for i, e := range v.arr {
			p := index(path, i)
			if f.typ == tMessages {
				if err := publishMessage(e, f.msg, p, ""); err != nil {
					return err
				}
				continue
			}
			if e.kind != kindString {
				return notPublish(p, "not a string")
			}
			if e.str == "" {
				return notPublish(p, "empty string; a2a-python drops empty strings from arrays")
			}
		}
	case tStringMap, tMessageMap:
		if v.kind != kindObject {
			return notPublish(path, "not a JSON object (map)")
		}
		if len(v.obj) == 0 {
			return notPublish(path, emptyWhy(f))
		}
		for _, k := range sortedNames(v.obj) {
			e, p := v.obj[k], join(path, k)
			if f.typ == tMessageMap {
				if err := publishMessage(e, f.msg, p, ""); err != nil {
					return err
				}
				continue
			}
			if e.kind != kindString {
				return notPublish(p, "not a string")
			}
			if e.str == "" {
				return notPublish(p, "empty string; a2a-python drops empty strings")
			}
		}
	}
	return nil
}

func emptyWhy(f field) string {
	switch f.pres {
	case implicit:
		return "the default value of this field; omit the member (A2A §8.4.1)"
	case required:
		return "empty, but the field is REQUIRED; the specification keeps it and a2a-python drops it, so no verifier pair agrees"
	default:
		return "empty; the specification keeps an explicitly set empty value and a2a-python drops it, so no verifier pair agrees"
	}
}

// publishStruct checks the inside of a google.protobuf.Struct: a2a-python's canonicalization
// removes null, "", [] and {} at any depth there, and the specification does not, so none may
// occur.
func publishStruct(v *value, path string) error {
	switch v.kind {
	case kindNull:
		return notPublish(path, "null inside a Struct; a2a-python drops it")
	case kindString:
		if v.str == "" {
			return notPublish(path, "empty string inside a Struct; a2a-python drops it")
		}
	case kindArray:
		if len(v.arr) == 0 {
			return notPublish(path, "empty array inside a Struct; a2a-python drops it")
		}
		for i, e := range v.arr {
			if err := publishStruct(e, index(path, i)); err != nil {
				return err
			}
		}
	case kindObject:
		if len(v.obj) == 0 {
			return notPublish(path, "empty object inside a Struct; a2a-python drops it")
		}
		for _, k := range sortedNames(v.obj) {
			if err := publishStruct(v.obj[k], join(path, k)); err != nil {
				return err
			}
		}
	}
	return nil
}

func sortedFieldNames(m *message) []string {
	names := make(map[string]*value, len(m.fields))
	for k := range m.fields {
		names[k] = nil
	}
	return sortedNames(names)
}
