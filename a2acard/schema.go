package a2acard

// The AgentCard schema as the proto3 JSON mapping sees it: for every message reachable from
// AgentCard, each field's JSON name, its type and its presence. A2A §8.4.1 rule 1 decides which
// members the signed payload keeps from exactly these two properties, so this table is the
// part of the canonicalization that comes from the schema rather than from RFC 8785.
//
// Source: specification/a2a.proto of A2A v1.0.1 (package lf.a2a.v1), messages AgentCard (field
// numbers 1-14), AgentInterface, AgentProvider, AgentCapabilities, AgentExtension, AgentSkill,
// AgentCardSignature, SecurityRequirement, StringList, SecurityScheme and the security-scheme
// and OAuth-flow messages under it. JSON names are the proto3 lowerCamelCase names; the
// original snake_case spellings, which proto3 JSON parsers also accept, are not listed and are
// therefore treated as unknown members. testdata/a2a-agentcard-schema.json is the same table
// dumped from the descriptors of the a2a-python SDK (gen_python_vectors.py), and
// TestSchemaMatchesReferenceDescriptors keeps the two equal.

// presence is how a field's absence is told apart from its default value.
type presence uint8

const (
	// implicit: a proto3 singular scalar, repeated or map field without the optional keyword.
	// Absent and default are one state, so the payload omits the default: "", false, [], {}
	// and null (A2A §8.4.1 rule 1, "Default values").
	implicit presence = iota
	// explicit: a field with the optional keyword, a singular message field (including
	// google.protobuf.Struct) or a oneof member. Set and unset are different states; a set
	// field stays whatever its value, and only null, which proto3 JSON reads as unset, is
	// omitted.
	explicit
	// required: [(google.api.field_behavior) = REQUIRED]. Always kept, even at the default.
	required
)

// fieldType is the JSON shape of a field.
type fieldType uint8

const (
	tString     fieldType = iota // string
	tBool                        // bool
	tMessage                     // singular message; field.msg is its schema
	tStruct                      // google.protobuf.Struct: a free-form object, never stripped inside
	tStrings                     // repeated string
	tMessages                    // repeated message; field.msg is the element schema
	tStringMap                   // map<string, string>
	tMessageMap                  // map<string, message>; field.msg is the value schema
)

type field struct {
	typ  fieldType
	pres presence
	msg  *message
}

type message struct {
	name string // proto message name, for error text and the descriptor comparison
	// oneof names the proto oneof that every field of the message belongs to (SecurityScheme's
	// scheme, OAuthFlows' flow), or is "" when the message has none. At most one member of a
	// oneof may be set; proto3 JSON parsers (a2a-python's ParseDict) and a2a-go reject an object
	// that sets two.
	oneof  string
	fields map[string]field
}

func strField(p presence) field                { return field{typ: tString, pres: p} }
func boolField(p presence) field               { return field{typ: tBool, pres: p} }
func strsField(p presence) field               { return field{typ: tStrings, pres: p} }
func strMapField(p presence) field             { return field{typ: tStringMap, pres: p} }
func structField() field                       { return field{typ: tStruct, pres: explicit} }
func msgField(p presence, m *message) field    { return field{typ: tMessage, pres: p, msg: m} }
func msgsField(p presence, m *message) field   { return field{typ: tMessages, pres: p, msg: m} }
func msgMapField(p presence, m *message) field { return field{typ: tMessageMap, pres: p, msg: m} }

var schemaAgentCard = &message{name: "AgentCard", fields: map[string]field{
	"name":                 strField(required),
	"description":          strField(required),
	"supportedInterfaces":  msgsField(required, schemaAgentInterface),
	"provider":             msgField(explicit, schemaAgentProvider),
	"version":              strField(required),
	"documentationUrl":     strField(explicit), // optional string
	"capabilities":         msgField(required, schemaAgentCapabilities),
	"securitySchemes":      msgMapField(implicit, schemaSecurityScheme),
	"securityRequirements": msgsField(implicit, schemaSecurityRequirement),
	"defaultInputModes":    strsField(required),
	"defaultOutputModes":   strsField(required),
	"skills":               msgsField(required, schemaAgentSkill),
	"signatures":           msgsField(implicit, schemaAgentCardSignature),
	"iconUrl":              strField(explicit), // optional string
}}

var schemaAgentInterface = &message{name: "AgentInterface", fields: map[string]field{
	"url":             strField(required),
	"protocolBinding": strField(required),
	"tenant":          strField(implicit),
	"protocolVersion": strField(required),
}}

var schemaAgentProvider = &message{name: "AgentProvider", fields: map[string]field{
	"url":          strField(required),
	"organization": strField(required),
}}

var schemaAgentCapabilities = &message{name: "AgentCapabilities", fields: map[string]field{
	"streaming":         boolField(explicit), // optional bool
	"pushNotifications": boolField(explicit), // optional bool
	"extensions":        msgsField(implicit, schemaAgentExtension),
	"extendedAgentCard": boolField(explicit), // optional bool
}}

var schemaAgentExtension = &message{name: "AgentExtension", fields: map[string]field{
	"uri":         strField(implicit),
	"description": strField(implicit),
	"required":    boolField(implicit), // plain bool: false is the default and is omitted (A2A-DESIGN §8.7)
	"params":      structField(),
}}

var schemaAgentSkill = &message{name: "AgentSkill", fields: map[string]field{
	"id":                   strField(required),
	"name":                 strField(required),
	"description":          strField(required),
	"tags":                 strsField(required),
	"examples":             strsField(implicit),
	"inputModes":           strsField(implicit),
	"outputModes":          strsField(implicit),
	"securityRequirements": msgsField(implicit, schemaSecurityRequirement),
}}

var schemaAgentCardSignature = &message{name: "AgentCardSignature", fields: map[string]field{
	"protected": strField(required),
	"signature": strField(required),
	"header":    structField(),
}}

var schemaSecurityRequirement = &message{name: "SecurityRequirement", fields: map[string]field{
	"schemes": msgMapField(implicit, schemaStringList),
}}

var schemaStringList = &message{name: "StringList", fields: map[string]field{
	"list": strsField(implicit),
}}

// SecurityScheme is a oneof; each member is a message field with explicit presence.
var schemaSecurityScheme = &message{name: "SecurityScheme", oneof: "scheme", fields: map[string]field{
	"apiKeySecurityScheme":        msgField(explicit, schemaAPIKeySecurityScheme),
	"httpAuthSecurityScheme":      msgField(explicit, schemaHTTPAuthSecurityScheme),
	"oauth2SecurityScheme":        msgField(explicit, schemaOAuth2SecurityScheme),
	"openIdConnectSecurityScheme": msgField(explicit, schemaOpenIDConnectSecurityScheme),
	"mtlsSecurityScheme":          msgField(explicit, schemaMutualTLSSecurityScheme),
}}

var schemaAPIKeySecurityScheme = &message{name: "APIKeySecurityScheme", fields: map[string]field{
	"description": strField(implicit),
	"location":    strField(required),
	"name":        strField(required),
}}

var schemaHTTPAuthSecurityScheme = &message{name: "HTTPAuthSecurityScheme", fields: map[string]field{
	"description":  strField(implicit),
	"scheme":       strField(required),
	"bearerFormat": strField(implicit),
}}

var schemaOAuth2SecurityScheme = &message{name: "OAuth2SecurityScheme", fields: map[string]field{
	"description":       strField(implicit),
	"flows":             msgField(required, schemaOAuthFlows),
	"oauth2MetadataUrl": strField(implicit),
}}

var schemaOpenIDConnectSecurityScheme = &message{name: "OpenIdConnectSecurityScheme", fields: map[string]field{
	"description":      strField(implicit),
	"openIdConnectUrl": strField(required),
}}

var schemaMutualTLSSecurityScheme = &message{name: "MutualTlsSecurityScheme", fields: map[string]field{
	"description": strField(implicit),
}}

// OAuthFlows is a oneof; each member is a message field with explicit presence.
var schemaOAuthFlows = &message{name: "OAuthFlows", oneof: "flow", fields: map[string]field{
	"authorizationCode": msgField(explicit, schemaAuthorizationCodeOAuthFlow),
	"clientCredentials": msgField(explicit, schemaClientCredentialsOAuthFlow),
	"implicit":          msgField(explicit, schemaImplicitOAuthFlow),
	"password":          msgField(explicit, schemaPasswordOAuthFlow),
	"deviceCode":        msgField(explicit, schemaDeviceCodeOAuthFlow),
}}

var schemaAuthorizationCodeOAuthFlow = &message{name: "AuthorizationCodeOAuthFlow", fields: map[string]field{
	"authorizationUrl": strField(required),
	"tokenUrl":         strField(required),
	"refreshUrl":       strField(implicit),
	"scopes":           strMapField(required),
	"pkceRequired":     boolField(implicit),
}}

var schemaClientCredentialsOAuthFlow = &message{name: "ClientCredentialsOAuthFlow", fields: map[string]field{
	"tokenUrl":   strField(required),
	"refreshUrl": strField(implicit),
	"scopes":     strMapField(required),
}}

var schemaImplicitOAuthFlow = &message{name: "ImplicitOAuthFlow", fields: map[string]field{
	"authorizationUrl": strField(implicit),
	"refreshUrl":       strField(implicit),
	"scopes":           strMapField(implicit),
}}

var schemaPasswordOAuthFlow = &message{name: "PasswordOAuthFlow", fields: map[string]field{
	"tokenUrl":   strField(implicit),
	"refreshUrl": strField(implicit),
	"scopes":     strMapField(implicit),
}}

var schemaDeviceCodeOAuthFlow = &message{name: "DeviceCodeOAuthFlow", fields: map[string]field{
	"deviceAuthorizationUrl": strField(required),
	"tokenUrl":               strField(required),
	"refreshUrl":             strField(implicit),
	"scopes":                 strMapField(required),
}}
