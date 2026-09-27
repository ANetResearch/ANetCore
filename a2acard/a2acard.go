// Package a2acard signs and verifies A2A AgentCards for anet agents (A2A-DESIGN §10.3).
//
// An anet network card is an A2A AgentCard (A2A specification §4.4, §8.4) signed with the
// Ed25519 key that the agent's KEL currently designates. The package provides:
//
//   - Canonicalize: RFC 8785 JSON Canonicalization Scheme (JCS) over strict I-JSON input.
//   - CheckPublishForm: whether a card is in publish form, the form on which the A2A rule,
//     a2a-python and a2a-go compute the same payload (see below).
//   - Sign: an A2A §8.4.2 JWS signature (EdDSA) over the §8.4.1 payload of a card in publish
//     form, appended to the card's "signatures" array.
//   - Verify: the anet admission rules for a network card (§10.3): a current KEL key state,
//     the anet-card extension bound to the signing AID, relay interfaces addressed to that
//     AID, notBefore, REQUIRED members and size limits, and member names that stay distinct
//     under case folding (so struct decoders read the members Verify checked).
//   - CheckHighWater: the three-branch params.seq rule that consumers and publishers apply.
//   - JWKS: the JSON Web Key Set that a hub serves at /agents/{aid}/jwks.json.
//   - DefaultSkillDescription, Skill.WithDefaults, ExtensionDecl: publish-form building blocks
//     for card builders.
//
// The package uses only the Go standard library and the identity package. It does not import
// a2a-go: ANetCore's dependency list is frozen (docs/scope.md), and a card signed here must be
// verifiable by a2a-go's a2acrypto, which ANet checks in a contract test. To keep the two
// byte-compatible, the JWS construction follows a2a-go and the A2A reference SDK exactly: the
// protected header is the JSON object {"alg","jku","kid","typ"} serialized with sorted keys and
// no whitespace; the JWS payload is the canonical card, which the signature entry does not
// carry (detached content, RFC 7515 Appendix F); and the signing input is
// BASE64URL(header) "." BASE64URL(payload), with the payload base64url-encoded (RFC 7797
// unencoded payloads are not used).
//
// # Payload forms
//
// A2A §8.4.1 signs the card after removing "signatures" and every member that proto3 field
// presence treats as unset: defaults ("", false, [], {}) of fields without the optional
// keyword, and null. REQUIRED members stay even at their default; optional and message fields
// stay whenever set; the inside of a google.protobuf.Struct (extension params) is not touched.
// schema.go holds the field table this needs, transcribed from a2a.proto and checked against
// the a2a-python descriptors. That payload is FormProtoStripped (SigningPayload). a2a-go
// instead signs the card as written, minus "signatures": FormRaw (RawSigningPayload).
//
// Sign accepts only cards in publish form (CheckPublishForm), on which the two forms are the
// same bytes and a2a-python's own canonicalization (which additionally drops every empty
// string, array and object, even inside Struct values and REQUIRED fields) agrees as well. It
// refuses other cards instead of rewriting them, so a card builder that writes
// "required": false or an empty REQUIRED description learns it at signing time rather than
// from a verifier in another language. Verify checks FormProtoStripped first and falls back
// to FormRaw, which admits a2a-go-signed cards that carry default values; Verified records the
// form. testdata/python-vectors.json pins all of this against a2a-python.
//
// Times in the anet-card extension (issuedAt, notBefore) and the now argument of Verify are
// unix milliseconds, the unit used by the identity package and the rest of the v0.2 wire.
package a2acard

// URIs that anet defines for A2A cards. They are part of signed bytes and of hub indexes, so
// they are fixed strings, not configuration.
const (
	// ExtCardURI identifies the anet-card extension in capabilities.extensions. Its params are
	// {"aid": <AID>, "seq": <decimal string>, "issuedAt": <decimal string>, "notBefore": <decimal string>}.
	ExtCardURI = "https://agentnetwork.org.cn/a2a/ext/anet-card/v1"
	// BindingRelayURI is the protocolBinding of an AgentInterface reached through an anet hub
	// relay. Such an interface routes by tenant, so its tenant must be the card's AID.
	BindingRelayURI = "https://agentnetwork.org.cn/a2a/bindings/anet-relay/v1"
)

// JWS header values this package produces and accepts.
const (
	AlgEdDSA  = "EdDSA"
	TypJOSE   = "JOSE"
	KIDPrefix = "did:anet:"
)

// Limits enforced by Verify (A2A-DESIGN §10.3). Lengths are in bytes of UTF-8, the same unit
// the ADP card limits use; a hub stores cards as bytes, so a byte bound is what caps storage.
const (
	MaxCardBytes        = 64 << 10
	MaxNameBytes        = 128
	MaxDescriptionBytes = 4096
	MaxSkills           = 256
	MaxTagsPerSkill     = 16
	// MaxSignatures bounds the signatures array. The design does not set this limit. Without it a
	// 64 KiB card can carry several hundred signature entries, and each entry whose kid names
	// the card's AID costs the verifier one Ed25519 verification. Eight leaves room for key
	// rotation overlap, which is the use the A2A specification gives for multiple signatures.
	MaxSignatures = 8
	// NotBeforeSkewMillis is how far in the future a card's notBefore may lie (300 s).
	NotBeforeSkewMillis = 300_000
)
