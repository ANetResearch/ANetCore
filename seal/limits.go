package seal

// Time values on the wire are unix milliseconds (§3). The constants below
// share that unit so they can be added to wire fields without conversion.
const (
	minuteMS uint64 = 60 * 1000
	dayMS    uint64 = 24 * 60 * minuteMS
)

const (
	// ClockSkewMS is the tolerance for a peer's clock running ahead of ours:
	// a key set is acceptable when one key becomes valid within it (§3.1
	// rule 3), and a message may carry a ts up to this far in the future
	// (§3.6 step 5).
	ClockSkewMS = 5 * minuteMS

	// MaxKeyValidityMS bounds not_after - not_before of one EncKey (§3.1).
	MaxKeyValidityMS = 30 * dayMS

	// KeyRotationIntervalMS, KeyLifetimeMS and KeyRetentionMS are the key
	// ring policy of §3.1 and the "encryption key" row of §2: a new key every
	// 7 days, each valid for 14, its private half kept 15 days past
	// not_after so that messages still queued at a hub can be opened.
	//
	// These numbers set the forward-secrecy bound stated in §21 item 2. A
	// message sent at time t is sealed to a key valid at t, whose not_after
	// is therefore at most t + KeyLifetimeMS; the private half exists until
	// not_after + KeyRetentionMS. A party that obtains the recipient's disk
	// can thus open the message for at most KeyLifetimeMS + KeyRetentionMS
	// = 29 days after it was sent. Shortening the retention narrows that
	// window and loses messages that wait in a mailbox longer than the
	// retention. The bound holds for a recipient that follows this policy;
	// the wire rule (MaxKeyValidityMS) lets a recipient publish keys valid
	// for up to 30 days, which widens its own window accordingly.
	KeyRotationIntervalMS = 7 * dayMS
	KeyLifetimeMS         = 14 * dayMS
	KeyRetentionMS        = 15 * dayMS

	// ForwardSecrecyWindowMS is the bound derived above (§21 item 2).
	ForwardSecrecyWindowMS = KeyLifetimeMS + KeyRetentionMS

	// MaxMessageLifetimeMS bounds exp - ts of one inner message (§3.6 step
	// 5). It does not exceed KeyRetentionMS: a message sent at t under a key
	// valid at t expires by t + 15 days, while that key's private half is
	// kept until not_after + 15 days > t + 15 days. A message inside its
	// lifetime therefore never arrives after its key was discarded.
	MaxMessageLifetimeMS = 15 * dayMS
)

const (
	// MaxKeysPerSet is the upper bound of EncKeySet.keys (§3.1 "[1*4 EncKey]").
	MaxKeysPerSet = 4

	// MaxKELEvents and MaxKELBytes cap the sender KEL carried in every inner
	// message (§3.3 key 10). A KEL is replayed on every receive, one Ed25519
	// verification per event, before the sender is known to be anyone the
	// recipient wants to hear from; the caps bound that cost per message.
	MaxKELEvents = 256
	MaxKELBytes  = 64 << 10

	// MIDLen is the length of the inner message id (§3.3 key 6).
	MIDLen = 16

	// SigLen is the length of an Ed25519 signature (§3.3 key 20, §3.1 sig).
	SigLen = 64

	// FirstIgnorableKey is the smallest inner or outer map key a receiver
	// may skip without understanding it (§3.3). Keys below it are
	// must-understand.
	FirstIgnorableKey = 64
)
