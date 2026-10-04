package identity

import "encoding/base32"

// aidLen is the length of every AID: "b" and 58 base32 characters, the 36 bytes of a CIDv1 dag-cbor
// sha2-256 identifier (anetcid.Sum).
const aidLen = 59

// aidPrefix is the first four bytes of every decoded AID: CIDv1, dag-cbor, sha2-256, 32 bytes.
var aidPrefix = [4]byte{0x01, 0x71, 0x12, 0x20}

var aidEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ValidAID reports whether s is an AID as anetcid.Sum writes one: "b" and the lower-case base32,
// without padding, of a CIDv1 dag-cbor sha2-256 identifier, in its one canonical spelling. The
// empty string, a prefix or a short form, upper case, a string with U+0000 or any other byte
// outside the alphabet, and another CID codec are not AIDs.
//
// It says nothing about whether the AID exists: only its KEL does. It is the one AID syntax check
// of ANetCore, used wherever an AID read from the wire must be well formed before it is compared
// or stored: the witness a rot names (KEL R-3), and a hub's X-ANet-AID.
func ValidAID(s string) bool {
	if len(s) != aidLen || s[0] != 'b' {
		return false
	}
	raw, err := aidEncoding.DecodeString(s[1:])
	if err != nil || len(raw) != len(aidPrefix)+32 || [4]byte(raw[:4]) != aidPrefix {
		return false
	}
	// The last character carries two bits beyond the 36 bytes; only the spelling with both zero
	// is the AID, so an AID has exactly one string.
	return aidEncoding.EncodeToString(raw) == s[1:]
}
