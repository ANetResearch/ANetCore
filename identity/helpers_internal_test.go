package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

// The tests of this package rotate identities as identity/identitytest does for other packages
// (which this package's own tests cannot import): a fresh next key per rotation, remembered by the
// digest the KEL commits to, and the event adopted at once.

var testNextKeys sync.Map // hex(digest) → ed25519.PrivateKey

// testIncept is a hub identity incepted at ts 1, the smallest a KEL allows.
func testIncept() (*Controller, error) { return InceptHub(1) }

func testNewNext() []byte {
	_, k, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	d := sha256.Sum256(publicOf(k))
	testNextKeys.Store(hex.EncodeToString(d[:]), k)
	return d[:]
}

// testNextKey is the key c's accepted KEL commits to next: nil for the icp's hot key.
func testNextKey(c *Controller) (ed25519.PrivateKey, error) {
	kel := c.Accepted()
	if len(kel) == 1 {
		return nil, nil
	}
	k, ok := testNextKeys.Load(hex.EncodeToString(committedNextDigest(kel)))
	if !ok {
		return nil, errors.New("test: next key not made by testNewNext")
	}
	return k.(ed25519.PrivateKey), nil
}

// testWitness is the witness an agent's test rotations name.
var testWitness = SuiteController().AID()

func testRotateWith(c *Controller, ts uint64, emergency bool) error {
	k, err := testNextKey(c)
	if err != nil {
		return err
	}
	var witness string
	if c.Toad() == ToadAgent {
		witness = testWitness
	}
	var ev SignedEvent
	if c.Toad() == ToadAgent && k == nil {
		// an agent's first rotation is its witness designation (C-31, D-13)
		if emergency {
			return errors.New("test: an agent's first rotation designates its witness and is not an emergency")
		}
		ev, err = c.BuildWitnessDesignation(witness, testNewNext(), ts)
	} else {
		ev, err = c.BuildRotation(k, testNewNext(), witness, emergency, ts)
	}
	if err != nil {
		return err
	}
	return c.Adopt(ev)
}

func testRotate(c *Controller, ts uint64) error { return testRotateWith(c, ts, false) }

func testDeactivate(c *Controller, ts uint64) error {
	k, err := testNextKey(c)
	if err != nil {
		return err
	}
	ev, err := c.BuildDeactivation(k, ts)
	if err != nil {
		return err
	}
	if err := c.Adopt(ev); err != nil {
		return err
	}
	return c.SetState(StateDeactivated)
}
