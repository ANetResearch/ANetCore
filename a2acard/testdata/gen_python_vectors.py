"""Generate the a2a-python cross-SDK vectors for package a2acard (A2A-DESIGN §10.3, note 0012).

Every card here is built as an lf.a2a.v1.AgentCard protobuf message and signed the way the
a2a-python reference SDK signs: proto -> MessageToDict -> drop "signatures" -> drop empty values
-> RFC 8785 -> JWS EdDSA (a2a.utils.signing.create_agent_card_signer). The Go tests
(python_vectors_test.go) check that a2acard computes the same payload, reproduces the same
signature from the same card and key, and accepts or rejects each published variant as recorded
in "expect".

Outputs, next to this script:
  python-vectors.json         the vectors
  a2a-agentcard-schema.json   field name, shape and presence of AgentCard and every message
                              under it, read from the SDK's proto descriptors; schema.go must
                              match it (TestSchemaMatchesReferenceDescriptors)

Environment used for the committed files (see "generator" in python-vectors.json):
  python3 -m venv --without-pip /data/projs/anet-dev/.venv
  python3 -m pip --python /data/projs/anet-dev/.venv/bin/python install 'a2a-sdk[signing]'
  cd ANetCore/a2acard/testdata && /data/projs/anet-dev/.venv/bin/python gen_python_vectors.py

The signing key is the frozen anet conformance identity (ANetCore identity/suite.go): Ed25519
seed SHA-256("anet-suite-identity-v1/cur"), AID SUITE_AID below, so the Go tests can run the
full anet Verify with identity.SuiteController()'s KEL. Ed25519 is deterministic, so the output
is identical on every run with the same SDK.
"""

import hashlib
import json
from importlib.metadata import version

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from google.api import field_behavior_pb2
from google.protobuf import struct_pb2
from google.protobuf.json_format import MessageToDict
from jwt import api_jws

from a2a import types
from a2a.client.card_resolver import parse_agent_card
from a2a.types import a2a_pb2
from a2a.utils import signing
from a2a.utils._jcs import canonicalize

SEED = hashlib.sha256(b"anet-suite-identity-v1/cur").digest()
# identity.SuiteController().AID(); python_vectors_test.go asserts the two are equal.
SUITE_AID = "bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y"
KID = f"did:anet:{SUITE_AID}#0"
JKU = f"https://hub.example.org/agents/{SUITE_AID}/jwks.json"
T0 = 1767225600000  # 2026-01-01T00:00:00Z, the "now" of the Go tests

EXT_CARD = "https://agentnetwork.org.cn/a2a/ext/anet-card/v1"
EXT_PRICING = "https://agentnetwork.org.cn/a2a/ext/anet-pricing/v1"
EXT_EVIDENCE = "https://agentnetwork.org.cn/a2a/ext/anet-evidence/v1"
EXT_X402 = "https://github.com/google-agentic-commerce/a2a-x402/blob/main/spec/v0.2"
BINDING_RELAY = "https://agentnetwork.org.cn/a2a/bindings/anet-relay/v1"

priv = Ed25519PrivateKey.from_private_bytes(SEED)
pub = priv.public_key()


def struct(d):
    s = struct_pb2.Struct()
    s.update(d)
    return s


def header(jku=True):
    h = {"alg": "EdDSA", "kid": KID, "typ": "JOSE"}
    if jku:
        h["jku"] = JKU
    return h


def python_sign(card, jku=True):
    """Signs card (in place) with the reference SDK's signer and returns the payload it signed."""
    payload = signing._canonicalize_agent_card(card)
    signing.create_agent_card_signer(signing_key=priv, protected_header=header(jku))(card)
    return payload


def python_verifies(card_dict):
    """Parses a published card the way the SDK's card resolver does and verifies it."""
    card = parse_agent_card(json.loads(json.dumps(card_dict)))
    verify = signing.create_signature_verifier(lambda kid, jku: pub, ["EdDSA"])
    try:
        verify(card)
        return True
    except signing.SignatureVerificationError:
        return False


def network_card():
    """An anet network card (A2A-DESIGN §10.1): relay interface bound to the AID, the anet-card
    extension, a2a-x402 declared as not required, pricing params, three skills."""
    return types.AgentCard(
        name="Suite Agent",
        description="Cross-SDK vector: an anet network card signed by a2a-python. 中文说明。",
        version="1.0.0",
        supported_interfaces=[
            types.AgentInterface(
                url="https://hub.example.org/relay/v2",
                protocol_binding=BINDING_RELAY,
                protocol_version="1.0",
                tenant=SUITE_AID,
            ),
            types.AgentInterface(
                url="https://node.example.org/a2a/jsonrpc",
                protocol_binding="JSONRPC",
                protocol_version="1.0",
            ),
        ],
        capabilities=types.AgentCapabilities(
            streaming=False,
            push_notifications=False,
            extensions=[
                types.AgentExtension(
                    uri=EXT_CARD,
                    params=struct({
                        "aid": SUITE_AID,
                        "seq": "9007199254740993",
                        "issuedAt": str(T0),
                        "notBefore": str(T0 - 60_000),
                    }),
                ),
                # required=False is the proto default: MessageToDict leaves it out, which is
                # what A2A-DESIGN §8.7 asks of the x402 declaration.
                types.AgentExtension(uri=EXT_X402, required=False),
                types.AgentExtension(
                    uri=EXT_PRICING,
                    description="Prices in anet credits, per call.",
                    params=struct({
                        "network": "anet",
                        "prices": [{"skillId": "translate", "amount": "25"}],
                    }),
                ),
                types.AgentExtension(uri=EXT_EVIDENCE),
            ],
        ),
        default_input_modes=["text/plain", "application/json"],
        default_output_modes=["text/plain"],
        skills=[
            types.AgentSkill(
                id="echo",
                name="Echo",
                description="Returns the input text.",
                tags=["text", "echo"],
                examples=["echo hello"],
            ),
            types.AgentSkill(
                id="translate",
                name="翻译",
                description="Translates between Chinese and English.",
                tags=["text", "translation", "中文"],
                examples=["translate 你好 to English"],
            ),
            types.AgentSkill(
                id="summarize.json",
                name="Summarize JSON",
                description="Summarizes a JSON document.",
                tags=["json", "summary"],
                input_modes=["application/json"],
                output_modes=["text/plain"],
            ),
        ],
    )


def proxy_like_card():
    """A card shaped like the local interface's proxy card (A2A-DESIGN §11.3): a Bearer
    security scheme and requirement, and an a2a-x402 declaration with params but not required
    (§8.7). No anet-card extension, no jku. The security requirement names a scope, because an
    empty scope list ({}) is dropped by a2a-python (see divergent-empty-scope-list)."""
    return types.AgentCard(
        name="Suite Agent (via local anet)",
        description="Proxy card vector.",
        version="1.0.0",
        supported_interfaces=[
            types.AgentInterface(
                url="http://127.0.0.1:7300/a2a/v1/agents/" + SUITE_AID + "/jsonrpc",
                protocol_binding="JSONRPC",
                protocol_version="1.0",
            ),
        ],
        capabilities=types.AgentCapabilities(
            streaming=True,
            push_notifications=False,
            extensions=[
                types.AgentExtension(
                    uri=EXT_X402,
                    params=struct({"signer": "anet-daemon", "clientPayload": False}),
                ),
            ],
        ),
        security_schemes={
            "anetLocal": types.SecurityScheme(
                http_auth_security_scheme=types.HTTPAuthSecurityScheme(scheme="Bearer"),
            ),
        },
        security_requirements=[
            types.SecurityRequirement(schemes={"anetLocal": types.StringList(list=["a2a"])}),
        ],
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        skills=[
            types.AgentSkill(id="chat", name="Chat", description="Text conversation.", tags=["chat"]),
        ],
    )


def vector(name, note, card_dict, payload, py_ok, expect, unsigned=None, jku=True):
    v = {
        "name": name,
        "note": note,
        "kid": KID,
        "jku": JKU if jku else "",
        "card": card_dict,
        "python_payload": payload,
        "python_verifies": py_ok,
        "expect": expect,
    }
    if unsigned is not None:
        v["card_unsigned"] = unsigned
    return v


def main():
    vectors = []

    # 1. The network card as a2a-python publishes it.
    card = network_card()
    unsigned = MessageToDict(card)
    payload = python_sign(card)
    published = MessageToDict(card)
    vectors.append(vector(
        "network-card",
        "anet network card built as a proto and signed by a2a-python; the published JSON is "
        "MessageToDict output, which is in publish form",
        published, payload, python_verifies(published),
        {"publish_form": True, "verify": "proto-stripped", "same_statement_as": ""},
        unsigned=unsigned,
    ))

    # 2. The same signed card, rendered by a proto-JSON emitter that prints default values.
    wire = MessageToDict(card, always_print_fields_with_no_presence=True)
    vectors.append(vector(
        "network-card-wire-defaults",
        "vector network-card with the same signature, rendered with "
        "always_print_fields_with_no_presence=True: \"required\": false, \"description\": \"\", "
        "\"tenant\": \"\", \"examples\": [], \"securitySchemes\": {} ... appear on the wire. "
        "A2A §8.4.3 strips them before verifying; a2a-go does not",
        wire, payload, python_verifies(wire),
        {"publish_form": False, "verify": "proto-stripped", "same_statement_as": "network-card"},
    ))

    # 3. The wire-defaults JSON signed as written (the payload a2a-go computes).
    raw = json.loads(json.dumps(wire))
    raw.pop("signatures")
    raw_payload = canonicalize(raw)
    jws = api_jws.encode(payload=raw_payload.encode("utf-8"), key=priv, algorithm="EdDSA", headers=header())
    protected, _, signature = jws.split(".")
    raw["signatures"] = [{"protected": protected, "signature": signature}]
    vectors.append(vector(
        "network-card-raw-signed",
        "the wire-defaults JSON signed over its RFC 8785 form without stripping, as a2a-go "
        "signs a card that carries default values; a2a-python strips before verifying and "
        "rejects it, a2acard accepts it through the raw fallback",
        raw, raw_payload, python_verifies(raw),
        {"publish_form": False, "verify": "raw", "same_statement_as": "network-card"},
    ))

    # 4. A proxy-card-shaped card: security scheme, requirement with a scope, x402 params with
    #    a false inside the Struct (kept by every implementation).
    card = proxy_like_card()
    unsigned = MessageToDict(card)
    payload = python_sign(card, jku=False)
    published = MessageToDict(card)
    vectors.append(vector(
        "proxy-card",
        "a card shaped like the local interface's proxy card (A2A-DESIGN §11.3), signed by "
        "a2a-python without jku; no anet-card extension, so only the JWS check applies",
        published, payload, python_verifies(published),
        {"publish_form": True, "verify": "proto-stripped", "same_statement_as": ""},
        unsigned=unsigned, jku=False,
    ))

    # 5-7. Where a2a-python and the A2A specification disagree. The publish form excludes all
    #      three, so a card a2acard signs never lands here.
    card = network_card()
    card.capabilities.extensions[2].params.update({"note": "", "tiers": []})
    payload = python_sign(card)
    published = MessageToDict(card)
    vectors.append(vector(
        "divergent-struct-empty",
        "extension params holding \"\" and []: a2a-python drops them inside the Struct before "
        "signing, the specification keeps a Struct's content, so a2acard (spec) rejects the "
        "signature",
        published, payload, python_verifies(published),
        {"publish_form": False, "verify": "INVALID_SIGNATURE", "same_statement_as": ""},
    ))

    card = proxy_like_card()
    del card.security_requirements[:]
    card.security_requirements.append(
        types.SecurityRequirement(schemes={"anetLocal": types.StringList()}))
    payload = python_sign(card, jku=False)
    published = MessageToDict(card)
    vectors.append(vector(
        "divergent-empty-scope-list",
        "a security requirement with an empty scope list, {\"schemes\":{\"anetLocal\":{}}}: "
        "a2a-python drops the empty object and with it the whole requirement, the "
        "specification keeps it (map values are always emitted)",
        published, payload, python_verifies(published),
        {"publish_form": False, "verify": "INVALID_SIGNATURE", "same_statement_as": ""},
        jku=False,
    ))

    card = network_card()
    card.skills[0].description = ""
    payload = python_sign(card)
    published = MessageToDict(card)
    published["skills"][0]["description"] = ""  # REQUIRED: the specification keeps it
    vectors.append(vector(
        "divergent-required-empty",
        "a skill whose REQUIRED description is \"\", published with the member present as "
        "A2A §8.4.1 requires: MessageToDict (and so a2a-python) omits it before signing, the "
        "specification keeps it; a2acard also refuses the card, since a REQUIRED string must "
        "be set",
        published, payload, python_verifies(published),
        {"publish_form": False, "verify": "INVALID_CARD", "same_statement_as": ""},
    ))

    out = {
        "generator": {
            "script": "gen_python_vectors.py",
            "a2a-sdk": version("a2a-sdk"),
            "protobuf": version("protobuf"),
            "PyJWT": version("PyJWT"),
        },
        "suite_aid": SUITE_AID,
        "ed25519_seed": "SHA-256(\"anet-suite-identity-v1/cur\")",
        "now_ms": T0,
        "vectors": vectors,
    }
    # sort_keys: Struct members come out of MessageToDict in hash order, which changes from
    # run to run; sorting makes the file reproducible. Member order does not reach any payload.
    with open("python-vectors.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")

    with open("a2a-agentcard-schema.json", "w", encoding="utf-8") as f:
        json.dump(dump_schema(a2a_pb2.AgentCard.DESCRIPTOR), f, indent=2, sort_keys=True)
        f.write("\n")

    for v in vectors:
        print(f"{v['name']:32} python_verifies={v['python_verifies']}")


def dump_schema(root):
    """Every message reachable from root: {message: {json_name: {type, presence, message}}}."""
    out = {}

    def short(d):
        return d.full_name.rsplit(".", 1)[-1]

    def walk(md):
        if short(md) in out:
            return
        fields = {}
        out[short(md)] = fields
        for f in md.fields:
            behaviors = f.GetOptions().Extensions[field_behavior_pb2.field_behavior]
            mt = f.message_type
            is_map = mt is not None and mt.GetOptions().map_entry
            if is_map:
                mt = mt.fields_by_name["value"].message_type
            if mt is not None and mt.full_name == "google.protobuf.Struct":
                kind, mt = "struct", None
            elif is_map:
                kind = "map_message" if mt is not None else "map_string"
            elif f.is_repeated:
                kind = "repeated_message" if mt is not None else "repeated_string"
            elif mt is not None:
                kind = "message"
            else:
                kind = {f.TYPE_STRING: "string", f.TYPE_BOOL: "bool"}[f.type]
            if field_behavior_pb2.REQUIRED in behaviors:
                presence = "required"
            elif f.has_presence:
                presence = "explicit"
            else:
                presence = "implicit"
            entry = {"type": kind, "presence": presence}
            if mt is not None:
                entry["message"] = short(mt)
            fields[f.json_name] = entry
            if mt is not None:
                walk(mt)

    walk(root)
    return out


if __name__ == "__main__":
    main()
