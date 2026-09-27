package a2acard

import (
	"strings"
	"unicode"
)

// Helpers for card builders (the daemon's network card, A2A-DESIGN §10.1-§10.2; the local
// interface's proxy card, §11.3). Each returns values that are already in publish form, so a
// card assembled from them passes Sign's check without further normalization.

// DefaultSkillDescription is the description a card builder publishes for a capability whose
// provider supplies none (A2A-DESIGN §10.2: the provider does not implement Described, or
// returns an empty description). AgentSkill.description is REQUIRED in a2a.proto and an empty
// string is not in publish form, so a skill never goes out with "". The text says plainly that
// no description was given rather than inventing one.
func DefaultSkillDescription(capID string) string {
	if capID == "" {
		return "anet capability (the provider gave no description)"
	}
	return "anet capability " + capID + " (the provider gave no description)"
}

// DefaultSkillName is the name published for a capability whose provider supplies none: the
// capability id itself, which is non-empty for every published capability.
func DefaultSkillName(capID string) string {
	if capID == "" {
		return "capability"
	}
	return capID
}

// DefaultSkillTags derives tags from a capability id when its provider supplies none
// (A2A-DESIGN §10.2): the id split at every character that is not a letter or digit,
// lower-cased, without duplicates, at most MaxTagsPerSkill. "translate.zh-en" gives
// ["translate", "zh", "en"]. AgentSkill.tags is REQUIRED and must have at least one element,
// so an id with no letters or digits gives the id itself, and an empty id gives ["anet"].
func DefaultSkillTags(capID string) []string {
	var tags []string
	seen := map[string]bool{}
	for _, t := range strings.FieldsFunc(capID, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		t = strings.ToLower(t)
		if seen[t] {
			continue
		}
		seen[t] = true
		tags = append(tags, t)
		if len(tags) == MaxTagsPerSkill {
			break
		}
	}
	switch {
	case len(tags) > 0:
		return tags
	case capID != "":
		return []string{capID}
	default:
		return []string{"anet"}
	}
}

// WithDefaults returns s with an empty Name, Description or Tags replaced by the defaults
// derived from s.ID. Empty tags inside a non-empty Tags are dropped, and if none remain the
// derived tags are used.
func (s Skill) WithDefaults() Skill {
	if s.Name == "" {
		s.Name = DefaultSkillName(s.ID)
	}
	if s.Description == "" {
		s.Description = DefaultSkillDescription(s.ID)
	}
	var tags []string
	for _, t := range s.Tags {
		if t != "" {
			tags = append(tags, t)
		}
	}
	if len(tags) == 0 {
		tags = DefaultSkillTags(s.ID)
	}
	s.Tags = tags
	return s
}

// ExtensionDecl returns an AgentExtension declaration for capabilities.extensions in publish
// form: "uri" and "description" only when non-empty (both are plain proto3 strings, and every
// real declaration has a uri); "required" only when true, since required is a plain proto3
// bool whose false is omitted (A2A §8.4.1; A2A-DESIGN §8.7, where the a2a-x402 declaration on
// a proxy card is not required and so carries no "required" member); "params" only when
// non-empty. The params values themselves must also be free of null, "", [] and {} (see
// CheckPublishForm); Sign reports any that are not.
func ExtensionDecl(uri, description string, required bool, params map[string]any) map[string]any {
	ext := map[string]any{}
	if uri != "" {
		ext["uri"] = uri
	}
	if description != "" {
		ext["description"] = description
	}
	if required {
		ext["required"] = true
	}
	if len(params) > 0 {
		ext["params"] = params
	}
	return ext
}
