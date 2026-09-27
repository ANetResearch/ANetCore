// Package a2acard signs and verifies A2A AgentCards for anet agents (A2A-DESIGN §10.3).
//
// An anet network card is an A2A AgentCard (A2A specification §4.4, §8.4) signed with the
// Ed25519 key that the agent's KEL currently designates. The package provides:
//
//   - Canonicalize: RFC 8785 JSON Canonicalization Scheme (JCS) over strict I-JSON input.
//   - Sign: an A2A §8.4.2 JWS signature (EdDSA) over the canonical card with the top-level
//     "signatures" member removed, appended to the card's "signatures" array.
//   - Verify: the anet admission rules for a network card (§10.3): a current KEL key state,
//     the anet-card extension bound to the signing AID, relay interfaces addressed to that
//     AID, notBefore, required fields and size limits, and member names that stay distinct
//     under case folding (so struct decoders read the members Verify checked).
//   - CheckHighWater: the three-branch params.seq rule that consumers and publishers apply.
//   - JWKS: the JSON Web Key Set that a hub serves at /agents/{aid}/jwks.json.
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
// Canonicalization is applied to the card bytes as given. The A2A specification (§8.4.1)
// additionally asks signers to drop protobuf default values before canonicalizing; a2a-go does
// not do this and neither does this package. A card builder that wants a2a-go's
// parse-and-reserialize round trip to preserve the signature must therefore emit exactly the
// members a2a-go emits (A2A-DESIGN §10.1: required slices non-nil, streaming and
// pushNotifications always present, numbers as strings).
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
