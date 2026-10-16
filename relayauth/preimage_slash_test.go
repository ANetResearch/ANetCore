package relayauth

import (
	"bytes"
	"testing"
)

// TestPreimageV2SlashCannotShiftFields: PreimageV2("poll","A/B","H") and ("poll","A","B/H") were
// the same bytes. The function now keeps the fields apart whatever the caller passes.
func TestPreimageV2SlashCannotShiftFields(t *testing.T) {
	a := PreimageV2("poll", "A/B", "H", 1, "GET", "/x", nil)
	b := PreimageV2("poll", "A", "B/H", 1, "GET", "/x", nil)
	if bytes.Equal(a, b) {
		t.Fatal("two different (aid, hubAID) pairs give one preimage")
	}
	c := PreimageV2("poll", "A%2FB", "H", 1, "GET", "/x", nil)
	if bytes.Equal(a, c) {
		t.Fatal("an escaped slash collides with a literal escape")
	}
	// valid values are unchanged
	if got := string(PreimageV2("poll", "AID", "HUB", 1, "GET", "/x", nil)); got[:len("anet-relay/v2/poll/AID/HUB/1/")] != "anet-relay/v2/poll/AID/HUB/1/" {
		t.Fatalf("valid preimage changed: %s", got)
	}
}
