package identity

// Controller stands in for the identity key holder.
type Controller struct{}

// Sign is the registered signing method.
func (c *Controller) Sign(preimage []byte) ([]byte, uint64) { return preimage, 0 }

// Signer is the signing interface; whatever implements it signs with an identity key.
type Signer interface {
	Sign(preimage []byte) ([]byte, uint64)
}
