package legacy

// Old is a v0.2 struct the transition list carries.
type Old struct {
	X string `cbor:"1,keyasint"`
	Y []byte `cbor:"2,keyasint,omitempty"`
}

// OldLabel is a v0.2 label the transition list carries.
const OldLabel = "anet-fx-old/v1"
