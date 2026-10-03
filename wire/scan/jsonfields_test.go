package scan_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/wire"
	"github.com/ANetResearch/ANetCore/wire/scan"
)

type identityStatus struct {
	AID               string          `json:"aid"`
	Name              string          `json:"name"`
	State             string          `json:"state"`
	Reason            string          `json:"reason"`
	Message           string          `json:"message"`
	Next              string          `json:"next,omitempty"`
	KeySeq            uint64          `json:"key_seq"`
	Commitment        []byte          `json:"commitment"`
	LastRotation      *struct{}       `json:"last_rotation"`
	Witness           json.RawMessage `json:"witness"`
	Notice            map[string]any  `json:"notice"`
	Pending           *struct{}       `json:"pending"`
	OldWitnessUnacked []struct {
		URL     string `json:"url"`
		Since   string `json:"since"`
		NextTry string `json:"next_try"`
	} `json:"old_witness_unacked"`
	Recovery struct {
		State   string `json:"state"`
		Message string `json:"message,omitempty"`
		Next    string `json:"next,omitempty"`
	} `json:"recovery"`
}

func TestJSONFieldsMatchesTheRegisteredShape(t *testing.T) {
	r := wire.MustLoad()
	route := r.ControlRoute("/identity/status")
	if diff := scan.JSONFields(reflect.TypeFor[identityStatus](), route.Response); len(diff) != 0 {
		t.Fatalf("a conforming struct differs:\n%s", strings.Join(diff, "\n"))
	}
	type extra struct {
		identityStatus
		Ksn uint64 `json:"ksn"`
	}
	if diff := scan.JSONFields(reflect.TypeFor[extra](), route.Response); len(diff) != 1 || !strings.Contains(diff[0], "ksn") {
		t.Fatalf("an unregistered member must be reported: %v", diff)
	}
	type wrongType struct {
		identityStatus
		KeySeq string `json:"key_seq"`
	}
	if diff := scan.JSONFields(reflect.TypeFor[wrongType](), route.Response); len(diff) != 1 || !strings.Contains(diff[0], "key_seq") {
		t.Fatalf("a mistyped member must be reported: %v", diff)
	}
	type noRecoveryState struct {
		identityStatus
		Recovery struct {
			Message string `json:"message"`
		} `json:"recovery"`
	}
	if diff := scan.JSONFields(reflect.TypeFor[noRecoveryState](), route.Response); len(diff) == 0 || !strings.Contains(strings.Join(diff, " "), "recovery.state") {
		t.Fatalf("a missing nested member must be reported: %v", diff)
	}
}

func TestJSONFieldsPartialBodies(t *testing.T) {
	r := wire.MustLoad()
	ep := r.Endpoint("GET", "/hub/identity")
	type hubIdentity struct {
		AID        string `json:"aid"`
		Wire       string `json:"wire"`
		DirMaxBits uint   `json:"dir_max_bits"`
	}
	if diff := scan.JSONFields(reflect.TypeFor[hubIdentity](), ep.Response); len(diff) != 1 || !strings.Contains(diff[0], "wire is registered as uint") {
		t.Fatalf("partial body: %v", diff)
	}
	reg := scan.Alt(r.Endpoint("POST", "/register").Response, "check_only")
	type checkOnly struct {
		Status string `json:"status"`
	}
	if diff := scan.JSONFields(reflect.TypeFor[checkOnly](), reg); len(diff) != 0 {
		t.Fatalf("check_only answer: %v", diff)
	}
	if diff := scan.JSONFields(reflect.TypeFor[checkOnly](), r.Endpoint("POST", "/register").Response); len(diff) != 1 {
		t.Fatalf("a body with alternatives needs one picked: %v", diff)
	}
}
