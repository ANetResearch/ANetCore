package seal

import "github.com/ANetResearch/ANetCore/identity"

// smallOrder reports whether pub is an encoding of an Ed25519 point of small order (core
// CORE-K8a), canonical or not. The list itself lives in identity (identity.SmallOrderKey), which
// needs it for KEL keys and which seal imports.
func smallOrder(pub []byte) bool { return identity.SmallOrderKey(pub) }
