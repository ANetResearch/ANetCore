// Package identitytest gives tests identities they can rotate in one call.
//
// A real node never keeps its next key. Every key after the hot key an icp commits is derived
// from the identity's recovery seed, which lives outside the data directory, and is handed to
// (*identity.Controller).BuildRotation when it is revealed (KEL C-30, C-31). Tests have no recovery
// seed and do not care where the next key comes from: this package makes a fresh one for each
// rotation, remembers it by the digest the KEL commits to, and builds and adopts each event as if
// the witness had accepted it.
//
// It is for tests only. The keys it remembers are kept in memory for the life of the process.
package identitytest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/ANetResearch/ANetCore/identity"
)

// InceptTS is the icp time of Hub and Agent: the smallest a KEL allows, so that any later time a
// test passes to Rotate or Deactivate is after it.
const InceptTS uint64 = 1

// Witness is the witness hub an agent's rotations name unless told otherwise: the AID of the
// conformance hub identity (identity.SuiteController).
var Witness = identity.SuiteController().AID()

// nextKeys maps hex(SHA-256(public key)) to the private key, for every next key made here.
var nextKeys sync.Map

// Hub returns a new hub identity (toad 0) incepted at InceptTS.
func Hub() (*identity.Controller, error) { return identity.InceptHub(InceptTS) }

// Agent returns a new agent identity (toad 1) incepted at InceptTS. Its first rotation names its
// witness (Witness, unless SwitchWitness names another).
func Agent() (*identity.Controller, error) { return identity.InceptAgent(InceptTS) }

// NewNext makes a next key, remembers it, and returns its digest: the next argument of
// BuildWitnessDesignation and BuildRotation.
func NewNext() []byte {
	_, k, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic("identitytest: " + err.Error())
	}
	d := sha256.Sum256(k.Public().(ed25519.PublicKey))
	nextKeys.Store(hex.EncodeToString(d[:]), k)
	return d[:]
}

// NextKey returns the key c's KEL commits to next, when this package made it, for a test that
// builds an event itself. It is nil while that key is the icp's hot key, which the controller
// holds (BuildRotation and BuildDeactivation take nil for it).
func NextKey(c *identity.Controller) (ed25519.PrivateKey, error) {
	kel := c.Accepted()
	if len(kel) == 1 {
		return nil, nil
	}
	var committed []byte
	for i := len(kel) - 1; i >= 0; i-- {
		if t := kel[i].Event.Type; t == identity.Inception || t == identity.Rotation {
			committed = kel[i].Event.NextDigest
			break
		}
	}
	k, ok := nextKeys.Load(hex.EncodeToString(committed))
	if !ok {
		return nil, errors.New("identitytest: the next key of this identity was not made by identitytest")
	}
	return k.(ed25519.PrivateKey), nil
}

// Rotate makes a planned rotation of c at ts (unix ms, after its last event) and adopts it. An
// agent keeps its witness; its first rotation names Witness.
func Rotate(c *identity.Controller, ts uint64) error { return rotate(c, ts, "", false) }

// RotateEmergency is Rotate with the emergency flag (key 12): the retired key state gets no grace.
func RotateEmergency(c *identity.Controller, ts uint64) error { return rotate(c, ts, "", true) }

// SwitchWitness makes an agent's planned rotation at ts that names witness, and adopts it: the
// first designation of a witness, or a hub switch.
func SwitchWitness(c *identity.Controller, witness string, ts uint64) error {
	return rotate(c, ts, witness, false)
}

// Deactivate builds the dip of c at ts and adopts it, and marks the identity deactivated.
func Deactivate(c *identity.Controller, ts uint64) error {
	revealed, err := NextKey(c)
	if err != nil {
		return err
	}
	ev, err := c.BuildDeactivation(revealed, ts)
	if err != nil {
		return err
	}
	if err := c.Adopt(ev); err != nil {
		return err
	}
	return c.SetState(identity.StateDeactivated)
}

func rotate(c *identity.Controller, ts uint64, witness string, emergency bool) error {
	revealed, err := NextKey(c)
	if err != nil {
		return err
	}
	if c.Toad() == identity.ToadAgent && witness == "" {
		states, err := identity.Replay(c.Accepted())
		if err != nil {
			return err
		}
		if witness = states[len(states)-1].Witness; witness == "" {
			witness = Witness
		}
	}
	var ev identity.SignedEvent
	if c.Toad() == identity.ToadAgent && revealed == nil {
		// an agent's first rotation is its witness designation, which reveals the icp's hot key
		// and is never an emergency (KEL D-13)
		if emergency {
			return errors.New("identitytest: an agent's first rotation designates its witness and is not an emergency")
		}
		ev, err = c.BuildWitnessDesignation(witness, NewNext(), ts)
	} else {
		ev, err = c.BuildRotation(revealed, NewNext(), witness, emergency, ts)
	}
	if err != nil {
		return err
	}
	return c.Adopt(ev)
}
