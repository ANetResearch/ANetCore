package golden

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// ev2Receipt is the evidence v2 receipt of the golden vector EV2-1 (evidence/testdata), which
// golden/py/gen_v016.py writes and evidence/vector_test.go reproduces: a receipt signed by the
// conformance identity for the task the vector describes.
type ev2Receipt struct {
	IX           string
	TaskDoc      []byte // the TaskDoc bytes the requester sent
	Deliverable  []byte
	CompletedDay uint64
	Wire         []byte // ReceiptWire
}

// goldenReceiptV2 reads the EV2-1 receipt, so the completion vectors carry the same bytes the
// independent generator wrote.
func goldenReceiptV2(t *testing.T) *ev2Receipt {
	t.Helper()
	b, err := os.ReadFile("../evidence/testdata/vec-ev2-1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Task struct {
			IX           string `json:"ix"`
			TaskDoc      string `json:"taskdoc"`
			Deliverable  string `json:"deliverable"`
			CompletedDay uint64 `json:"completed_day"`
		} `json:"task"`
		Provider struct {
			AID string `json:"aid"`
		} `json:"provider"`
		Receipt struct {
			Wire string `json:"wire"`
		} `json:"receipt"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.Provider.AID != suiteAID {
		t.Fatalf("the EV2-1 provider is %s, not the conformance identity", v.Provider.AID)
	}
	dec := func(s string) []byte {
		out, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	return &ev2Receipt{IX: v.Task.IX, TaskDoc: dec(v.Task.TaskDoc), Deliverable: dec(v.Task.Deliverable),
		CompletedDay: v.Task.CompletedDay, Wire: dec(v.Receipt.Wire)}
}
