package golden

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/delegation"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/tsir"
)

func taskdoc3Seed(role string) []byte {
	s := sha256.Sum256([]byte("anet-golden/v016/TASKDOC-3/" + role))
	return s[:]
}

// taskdoc3 is the TASKDOC-3 capability call: args with $files (CUX §2.6) and the three private
// contexts of the task binding (core §2.4.3), the requester being the conformance identity.
func taskdoc3(t *testing.T, fileCID string) (*tsir.TaskDoc, *delegation.TaskBinding) {
	t.Helper()
	rc, err := evidence.RequesterCommit(suiteAID, taskdoc3Seed("rsalt"))
	if err != nil {
		t.Fatal(err)
	}
	b := &delegation.TaskBinding{
		Nonce:           base64.RawURLEncoding.EncodeToString(taskdoc3Seed("nonce")[:16]),
		RequesterCommit: rc,
		ReviewKey:       ed25519.NewKeyFromSeed(taskdoc3Seed("review-key")).Public().(ed25519.PublicKey),
	}
	ctx, err := b.Contexts()
	if err != nil {
		t.Fatal(err)
	}
	args := `{"prompt":"describe it","$files":[{"name":"a.txt","mime":"text/plain","size":3,"cid":"` + fileCID + `"}]}`
	goal := "invoke capability image.caption"
	doc := &tsir.TaskDoc{Version: tsir.VersionPair{Major: 1}, Tasks: []tsir.Task{{
		Intent:   tsir.Intent{Summary: goal, Body: goal},
		Requires: []tsir.Require{{ID: "image.caption", Type: "capability", Necessity: "must"}},
		Contexts: append([]tsir.Context{{Key: "args", Value: args, Format: "json"}}, ctx...),
	}}}
	return doc, b
}

// TASKDOC-3: a capability call's TaskDoc — $files in args, the three private contexts — pinned as
// the bytes that travel (DelegateReq key 1) and their CID, the request CID a receipt names; the
// request CID changes with a file's CID; and CheckTaskBinding's refusals. The pinned bytes were
// cross-checked with the independent encoder of golden/py/gen_v016.py.
func TestTASKDOC_3(t *testing.T) {
	const fileCID = "bafkreif2pall7dybz7vecqka3zo24irdwabwdi4wc55jznaq75q7eaavvu" // SumRaw("abc")
	if got, _ := anetcid.SumRaw([]byte("abc")); got != fileCID {
		t.Fatalf("file CID %s", got)
	}
	doc, b := taskdoc3(t, fileCID)
	raw, err := coredet.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	const wantBytes = "a201a101010481a30aa201781f696e766f6b65206361706162696c69747920696d6167652e63617074696f6e03781f696e766f6b65206361706162696c69747920696d6167652e63617074696f6e0b81a3016d696d6167652e63617074696f6e026a6361706162696c69747903646d7573740d84a30164617267730278957b2270726f6d7074223a226465736372696265206974222c222466696c6573223a5b7b226e616d65223a22612e747874222c226d696d65223a22746578742f706c61696e222c2273697a65223a332c22636964223a226261666b726569663270616c6c376479627a37766563716b61337a6f323469726477616277646934776335356a7a6e617137357137656161767675227d5d7d04646a736f6ea4016a616e65742e6e6f6e636502765a394a426e31796175673957714e7255756158385467046474657874056770726976617465a40175616e65742e7265717565737465725f636f6d6d697402782b50356e63463744446f2d50356a64436273646b757055335f514e455f56647058346647305033486a2d5a51046474657874056770726976617465a4016f616e65742e7265766965775f6b657902782b6c4853613249386a48676c57753255746c434a62676e7769484665596b46576f5961455a76562d4d4f3759046474657874056770726976617465"
	if got := hex.EncodeToString(raw); got != wantBytes {
		t.Fatalf("TaskDoc bytes\n got  %s\n want %s", got, wantBytes)
	}
	const wantRequestCID = "bafyreibnzwosmwjbarbxfu7pjcmkgyocrxu36ykptakszvtatlgxtwvl6i"
	if got := anetcid.MustSum(raw); got != wantRequestCID {
		t.Errorf("request CID\n got  %s\n want %s", got, wantRequestCID)
	}
	read, err := delegation.ReadTaskBinding(doc)
	if err != nil {
		t.Fatalf("the binding must read back: %v", err)
	}
	if read.Nonce != b.Nonce || hex.EncodeToString(read.RequesterCommit) != hex.EncodeToString(b.RequesterCommit) {
		t.Fatalf("binding read back as %+v", read)
	}
	// The request CID covers the files: another file, another request.
	other, _ := taskdoc3(t, "bafkreidoesnotmatchanything")
	otherRaw, _ := coredet.Marshal(other)
	if anetcid.MustSum(otherRaw) == wantRequestCID {
		t.Fatal("the request CID does not change with a file's CID")
	}
	// CheckTaskBinding's refusals (CORE-K7: bad_request at step 9).
	for name, edit := range map[string]func(c []tsir.Context) []tsir.Context{
		"no anet.nonce":            func(c []tsir.Context) []tsir.Context { return dropKey(c, delegation.ContextNonce) },
		"no anet.requester_commit": func(c []tsir.Context) []tsir.Context { return dropKey(c, delegation.ContextRequesterCommit) },
		"no anet.review_key":       func(c []tsir.Context) []tsir.Context { return dropKey(c, delegation.ContextReviewKey) },
		"anet.nonce not private": func(c []tsir.Context) []tsir.Context {
			return setKey(c, delegation.ContextNonce, func(x *tsir.Context) { x.Visibility = "open" })
		},
		"anet.nonce with U+0000": func(c []tsir.Context) []tsir.Context {
			return setKey(c, delegation.ContextNonce, func(x *tsir.Context) { x.Value = "a\x00b" })
		},
		"review_key padded": func(c []tsir.Context) []tsir.Context {
			return setKey(c, delegation.ContextReviewKey, func(x *tsir.Context) { x.Value += "=" })
		},
		"requester_commit 31 bytes": func(c []tsir.Context) []tsir.Context {
			return setKey(c, delegation.ContextRequesterCommit, func(x *tsir.Context) { x.Value = strings.Repeat("A", 41) + "A" })
		},
	} {
		d, _ := taskdoc3(t, fileCID)
		d.Tasks[0].Contexts = edit(d.Tasks[0].Contexts)
		if err := delegation.CheckTaskBinding(d); !errors.Is(err, delegation.ErrTaskBinding) {
			t.Errorf("%s: want ErrTaskBinding, got %v", name, err)
		}
	}
}

func dropKey(c []tsir.Context, key string) []tsir.Context {
	var out []tsir.Context
	for _, x := range c {
		if x.Key != key {
			out = append(out, x)
		}
	}
	return out
}

func setKey(c []tsir.Context, key string, edit func(*tsir.Context)) []tsir.Context {
	for i := range c {
		if c[i].Key == key {
			edit(&c[i])
		}
	}
	return c
}
