package relayauth

const (
	ActionPoll = "poll"
	ActionKeys = "keys"
)

// PreimageV2 builds a relayauth preimage.
func PreimageV2(action, aid string) []byte { return []byte("anet-fx-relay/v2/" + action + "/" + aid) }
