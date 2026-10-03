package delegation_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/delegation"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/tsir"
)

func boundDoc(t testing.TB) *tsir.TaskDoc {
	t.Helper()
	tk := newTask(t, identity.SuiteController(), "ix-1")
	var doc tsir.TaskDoc
	if err := coredet.Unmarshal(tk.taskDoc, &doc); err != nil {
		t.Fatal(err)
	}
	return &doc
}

func TestABoundTaskDocReadsBack(t *testing.T) {
	doc := boundDoc(t)
	b, err := delegation.ReadTaskBinding(doc)
	if err != nil {
		t.Fatalf("a TaskDoc made with Contexts must carry its binding: %v", err)
	}
	if len(b.RequesterCommit) != 32 || len(b.ReviewKey) != 32 || b.Nonce == "" {
		t.Fatalf("binding %+v", b)
	}
	if err := delegation.CheckTaskBinding(doc); err != nil {
		t.Fatal(err)
	}
	// Contexts writes the one form: private, text, one context each.
	ctx, _ := b.Contexts()
	for i, k := range []string{delegation.ContextNonce, delegation.ContextRequesterCommit, delegation.ContextReviewKey} {
		if ctx[i].Key != k || ctx[i].Visibility != "private" || ctx[i].Format != "text" || ctx[i].Src != "" {
			t.Errorf("context %d: %+v", i, ctx[i])
		}
	}
	// A context written without a format (as the v0.2 nonce was) is read as text.
	for i := range doc.Tasks[0].Contexts {
		doc.Tasks[0].Contexts[i].Format = ""
	}
	if err := delegation.CheckTaskBinding(doc); err != nil {
		t.Errorf("format omitted: %v", err)
	}
}

// Every way a TaskDoc can fail to carry the binding is refused (CORE-K7: the provider answers it
// with bad_request).
func TestCheckTaskBindingRefusals(t *testing.T) {
	enc := base64.RawURLEncoding
	edits := map[string]func(d *tsir.TaskDoc){
		"no task":                         func(d *tsir.TaskDoc) { d.Tasks = nil },
		"binding in the second task only": func(d *tsir.TaskDoc) { d.Tasks = append([]tsir.Task{{Intent: d.Tasks[0].Intent}}, d.Tasks[0]) },
		"no nonce":                        func(d *tsir.TaskDoc) { drop(d, delegation.ContextNonce) },
		"no requester_commit":             func(d *tsir.TaskDoc) { drop(d, delegation.ContextRequesterCommit) },
		"no review_key":                   func(d *tsir.TaskDoc) { drop(d, delegation.ContextReviewKey) },
		"nonce twice": func(d *tsir.TaskDoc) {
			d.Tasks[0].Contexts = append(d.Tasks[0].Contexts, tsir.Context{Key: delegation.ContextNonce, Value: "other", Visibility: "private"})
		},
		"nonce open": func(d *tsir.TaskDoc) {
			set(d, delegation.ContextNonce, func(c *tsir.Context) { c.Visibility = "open" })
		},
		"review_key no visibility": func(d *tsir.TaskDoc) {
			set(d, delegation.ContextReviewKey, func(c *tsir.Context) { c.Visibility = "" })
		},
		"nonce as json": func(d *tsir.TaskDoc) { set(d, delegation.ContextNonce, func(c *tsir.Context) { c.Format = "json" }) },
		"nonce by reference": func(d *tsir.TaskDoc) {
			set(d, delegation.ContextNonce, func(c *tsir.Context) { c.Src = "https://example.invalid/n" })
		},
		"empty nonce":       func(d *tsir.TaskDoc) { set(d, delegation.ContextNonce, func(c *tsir.Context) { c.Value = "" }) },
		"nonce with U+0000": func(d *tsir.TaskDoc) { set(d, delegation.ContextNonce, func(c *tsir.Context) { c.Value = "a\x00b" }) },
		"requester_commit padded": func(d *tsir.TaskDoc) {
			set(d, delegation.ContextRequesterCommit, func(c *tsir.Context) { c.Value += "=" })
		},
		"requester_commit 31 bytes": func(d *tsir.TaskDoc) {
			set(d, delegation.ContextRequesterCommit, func(c *tsir.Context) { c.Value = enc.EncodeToString(make([]byte, 31)) })
		},
		"review_key 33 bytes": func(d *tsir.TaskDoc) {
			set(d, delegation.ContextReviewKey, func(c *tsir.Context) { c.Value = enc.EncodeToString(make([]byte, 33)) })
		},
		"review_key in std base64": func(d *tsir.TaskDoc) {
			set(d, delegation.ContextReviewKey, func(c *tsir.Context) {
				c.Value = base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))
			})
		},
		"review_key with a line break": func(d *tsir.TaskDoc) {
			set(d, delegation.ContextReviewKey, func(c *tsir.Context) { c.Value = c.Value[:20] + "\n" + c.Value[20:] })
		},
		"review_key non-zero trailing bits": func(d *tsir.TaskDoc) {
			set(d, delegation.ContextReviewKey, func(c *tsir.Context) { c.Value = c.Value[:42] + "B" })
		},
	}
	for name, edit := range edits {
		doc := boundDoc(t)
		edit(doc)
		if err := delegation.CheckTaskBinding(doc); !errors.Is(err, delegation.ErrTaskBinding) {
			t.Errorf("%s: want ErrTaskBinding, got %v", name, err)
		}
	}
	if err := delegation.CheckTaskBinding(nil); !errors.Is(err, delegation.ErrTaskBinding) {
		t.Errorf("nil: %v", err)
	}
	// Contexts refuses to write what ReadTaskBinding would refuse to read.
	for _, b := range []*delegation.TaskBinding{
		{Nonce: "", RequesterCommit: make([]byte, 32), ReviewKey: make([]byte, 32)},
		{Nonce: "a\x00", RequesterCommit: make([]byte, 32), ReviewKey: make([]byte, 32)},
		{Nonce: "n", RequesterCommit: make([]byte, 31), ReviewKey: make([]byte, 32)},
		{Nonce: "n", RequesterCommit: make([]byte, 32)},
	} {
		if _, err := b.Contexts(); !errors.Is(err, delegation.ErrTaskBinding) {
			t.Errorf("Contexts of %+v: %v", b, err)
		}
	}
}

func drop(d *tsir.TaskDoc, key string) {
	var out []tsir.Context
	for _, c := range d.Tasks[0].Contexts {
		if c.Key != key {
			out = append(out, c)
		}
	}
	d.Tasks[0].Contexts = out
}

func set(d *tsir.TaskDoc, key string, edit func(*tsir.Context)) {
	for i := range d.Tasks[0].Contexts {
		if d.Tasks[0].Contexts[i].Key == key {
			edit(&d.Tasks[0].Contexts[i])
		}
	}
}

// FuzzTaskBinding: whatever a TaskDoc holds, a binding read from it has the one form, and writing
// it back gives contexts that read to the same binding.
func FuzzTaskBinding(f *testing.F) {
	raw, err := coredet.Marshal(*boundDoc(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, b []byte) {
		var doc tsir.TaskDoc
		if coredet.Unmarshal(b, &doc) != nil {
			return
		}
		bd, err := delegation.ReadTaskBinding(&doc)
		if err != nil {
			return
		}
		if bd.Nonce == "" || bytes.IndexByte([]byte(bd.Nonce), 0) >= 0 || len(bd.RequesterCommit) != 32 || len(bd.ReviewKey) != 32 {
			t.Fatalf("read a binding out of form: %+v", bd)
		}
		ctx, err := bd.Contexts()
		if err != nil {
			t.Fatalf("a binding that was read does not write: %v", err)
		}
		again, err := delegation.ReadTaskBinding(&tsir.TaskDoc{Tasks: []tsir.Task{{Contexts: ctx}}})
		if err != nil || again.Nonce != bd.Nonce || !bytes.Equal(again.RequesterCommit, bd.RequesterCommit) ||
			!bytes.Equal(again.ReviewKey, bd.ReviewKey) {
			t.Fatalf("binding does not survive writing: %+v, %v", again, err)
		}
	})
}
