package a2acard

import (
	"reflect"
	"strings"
	"testing"
)

func TestDefaultSkillTags(t *testing.T) {
	cases := map[string][]string{
		"echo":            {"echo"},
		"translate.zh-en": {"translate", "zh", "en"},
		"Image/Resize_v2": {"image", "resize", "v2"},
		"a.a.A":           {"a"},
		"翻译.text":         {"翻译", "text"},
		"--":              {"--"},
		"":                {"anet"},
	}
	for id, want := range cases {
		if got := DefaultSkillTags(id); !reflect.DeepEqual(got, want) {
			t.Errorf("DefaultSkillTags(%q) = %q, want %q", id, got, want)
		}
	}
	long := strings.Repeat("x.", 40) + "end"
	var parts []string
	for i := 0; i < 40; i++ {
		parts = append(parts, "t"+dec(uint64(i)))
	}
	if got := DefaultSkillTags(strings.Join(parts, ".")); len(got) != MaxTagsPerSkill {
		t.Errorf("%d tags, want at most %d", len(got), MaxTagsPerSkill)
	}
	if got := DefaultSkillTags(long); !reflect.DeepEqual(got, []string{"x", "end"}) {
		t.Errorf("DefaultSkillTags(%q) = %q", long, got)
	}
}

// A skill with nothing but an id becomes a publishable skill: AgentSkill name, description
// and tags are REQUIRED, and the publish form holds no empty string (A2A-DESIGN §10.2).
func TestSkillWithDefaults(t *testing.T) {
	for _, id := range []string{"echo", "translate.zh-en", ""} {
		s := Skill{ID: id}.WithDefaults()
		if s.Name == "" || s.Description == "" || len(s.Tags) == 0 {
			t.Fatalf("Skill{ID:%q}.WithDefaults() = %+v", id, s)
		}
		for _, tag := range s.Tags {
			if tag == "" {
				t.Fatalf("empty tag in %+v", s)
			}
		}
	}
	if d := DefaultSkillDescription("echo"); !strings.Contains(d, "echo") {
		t.Fatalf("DefaultSkillDescription(echo) = %q", d)
	}

	// Given values are kept; empty tags are dropped and replaced only if none remain.
	s := Skill{ID: "echo", Name: "Echo", Description: "Returns the input.", Tags: []string{"", "text"}}.WithDefaults()
	want := Skill{ID: "echo", Name: "Echo", Description: "Returns the input.", Tags: []string{"text"}}
	if !reflect.DeepEqual(s, want) {
		t.Fatalf("WithDefaults = %+v, want %+v", s, want)
	}
	if s := (Skill{ID: "echo", Tags: []string{""}}).WithDefaults(); !reflect.DeepEqual(s.Tags, []string{"echo"}) {
		t.Fatalf("tags = %q", s.Tags)
	}
}

func TestExtensionDecl(t *testing.T) {
	const x402 = "https://github.com/google-agentic-commerce/a2a-x402/blob/main/spec/v0.2"
	// A2A-DESIGN §8.7: the proxy card's x402 declaration is not required, so it has no
	// "required" member at all.
	got := ExtensionDecl(x402, "", false, map[string]any{"signer": "anet-daemon", "clientPayload": false})
	want := map[string]any{"uri": x402, "params": map[string]any{"signer": "anet-daemon", "clientPayload": false}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtensionDecl = %v, want %v", got, want)
	}
	if got := ExtensionDecl(x402, "Paid skills.", true, nil); !reflect.DeepEqual(got, map[string]any{"uri": x402, "description": "Paid skills.", "required": true}) {
		t.Fatalf("ExtensionDecl = %v", got)
	}
	if got := ExtensionDecl(x402, "", false, map[string]any{}); !reflect.DeepEqual(got, map[string]any{"uri": x402}) {
		t.Fatalf("ExtensionDecl = %v", got)
	}
	// uri is a plain proto3 string too: an empty one is omitted, not written as "".
	if got := ExtensionDecl("", "No uri.", false, nil); !reflect.DeepEqual(got, map[string]any{"description": "No uri."}) {
		t.Fatalf("ExtensionDecl = %v", got)
	}
}

// A network card assembled from the builder helpers is in publish form, signs, and verifies
// under the proto-stripped form.
func TestBuilderHelpersMakePublishForm(t *testing.T) {
	c := incept(t)
	card := baseCard(c.AID())
	var skills []any
	for _, s := range []Skill{{ID: "echo"}, {ID: "translate.zh-en", Name: "Translate"}} {
		s = s.WithDefaults()
		tags := make([]any, len(s.Tags))
		for i, tag := range s.Tags {
			tags[i] = tag
		}
		skills = append(skills, map[string]any{"id": s.ID, "name": s.Name, "description": s.Description, "tags": tags})
	}
	card["skills"] = skills
	caps := card["capabilities"].(map[string]any)
	caps["extensions"] = append(extensions(card),
		ExtensionDecl("https://github.com/google-agentic-commerce/a2a-x402/blob/main/spec/v0.2", "", false, nil),
		ExtensionDecl("https://agentnetwork.org.cn/a2a/ext/anet-evidence/v1", "", false, nil),
	)
	if err := CheckPublishForm(marshal(t, card)); err != nil {
		t.Fatal(err)
	}
	v, err := Verify(signCard(t, card, c), newResolver(c).resolve, t0)
	if err != nil {
		t.Fatal(err)
	}
	if v.CanonicalForm != FormProtoStripped || len(v.Skills) != 2 || v.Skills[0].Description != DefaultSkillDescription("echo") {
		t.Fatalf("Verified = %+v", v)
	}
}
