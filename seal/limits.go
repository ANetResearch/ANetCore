package seal

// Time values on the wire are unix milliseconds (§3). The constants below
// share that unit so they can be added to wire fields without conversion.
const (
	minuteMS uint64 = 60 * 1000
	hourMS   uint64 = 60 * minuteMS
	dayMS    uint64 = 24 * hourMS
)

const (
	// ClockSkewMS is the tolerance for a peer's clock running ahead of ours:
	// a key set is acceptable when one key becomes valid within it (§3.1
	// rule 3), and a message may carry a ts up to this far in the future
	// (§3.6 step 5).
	ClockSkewMS = 5 * minuteMS

	// EpochMS is the length E of one encryption epoch. Epoch e is the UTC
	// day floor(t / EpochMS); its key is valid in [e·E, (e+1)·E), so every
	// node changes keys at the same instant and the change says nothing
	// about the node.
	EpochMS = dayMS

	// PublishAheadMS is how far ahead H a recipient publishes epoch keys:
	// its key set holds the keys of the current epoch and of the
	// PublishAheadMS / EpochMS epochs after it, so a sender with a cached set
	// can seal to it for that long without asking the hub again.
	PublishAheadMS = 14 * dayMS

	// DeliveryDeadlineMS is the delivery deadline D: a hub accepts an
	// envelope sealed to a key until that key's not_after plus D, and the
	// sender seals again to a current key after that. Hub and daemon use the
	// same value. Together with the hub's mailbox lifetime it bounds when the
	// last envelope for a key can arrive, which is what lets the recipient
	// delete the key's private half.
	DeliveryDeadlineMS = hourMS

	// MaxKeyValidityMS bounds not_after - not_before of one EncKey. An epoch
	// key spans one epoch; the bound leaves room for a publisher whose epoch
	// boundaries are not exactly on the UTC day, but not for a long-lived
	// key, which would hold the forward-secrecy window open for as long as it
	// is valid.
	MaxKeyValidityMS = 2 * dayMS

	// MaxMessageLifetimeMS bounds exp - ts of one inner message (§3.6 step
	// 5). It is also the hard deletion bound L of an epoch key's private
	// half: by not_after + L every honest hub has dropped every envelope
	// sealed to the key (it accepts one until not_after +
	// DeliveryDeadlineMS and keeps it for at most its mailbox lifetime), so
	// the key can go whatever the hub says. When to delete a private key is
	// the holder's policy; this package does not keep one.
	MaxMessageLifetimeMS = 15 * dayMS
)

const (
	// MaxKeysPerSet is the upper bound of EncKeySet.keys: the previous, the
	// current and PublishAheadMS / EpochMS future epoch keys fit with room to
	// spare.
	MaxKeysPerSet = 32

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
