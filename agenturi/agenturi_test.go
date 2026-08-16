package agenturi

import "testing"

// AU-P / AU-C / AU-W / AU-Q ACCEPT vectors (agent-uri-spec §6): input → canonical.
// Only the spec's critical-path rows reproducible without the full Unicode kit are here;
// AU-C-07 (generic fullwidth UTS-46) is value:conformance-kit in the spec and omitted.
func TestCanonicalAccept(t *testing.T) {
	cases := []struct{ id, in, want string }{
		{"AU-P-01", "agent://bridge-ops.example/ns=structural/svc=vibration-analysis/inst=sensor-07", "agent://bridge-ops.example/ns=structural/svc=vibration-analysis/inst=sensor-07"},
		{"AU-P-02", "agent://bridge-ops.example/svc=vibration-analysis", "agent://bridge-ops.example/svc=vibration-analysis"},
		{"AU-P-03", "agent://bridge-ops.example", "agent://bridge-ops.example"},
		{"AU-P-04", "agent://org/inst=sensor-07", "agent://org/inst=sensor-07"},
		{"AU-P-05", "agent://a", "agent://a"},
		{"AU-R-02", "agent://copa", "agent://copa"}, // all-Latin accept arm (Cyrillic twin REJECTs, §6 R-02)
		{"AU-P-06", "agent://org/ns=名前/svc=translate", "agent://org/ns=名前/svc=translate"},
		{"AU-P-07", "agent://my_org/svc=~tmp", "agent://my_org/svc=~tmp"},
		{"AU-W-01", "agent://*/structural-health?domain=bridge", "agent://*/structural-health?domain=bridge"},
		{"AU-W-02", "agent://*/translation", "agent://*/translation"},
		{"AU-W-10", "agent://*/bad.expr", "agent://*/bad.expr"},
		{"AU-W-11", "agent://*/translate%2bsummarize", "agent://*/translate%2Bsummarize"},
		{"AU-C-01", "AGENT://Bridge-Ops.Example/SVC=Vibration-Analysis", "agent://bridge-ops.example/svc=vibration-analysis"},
		{"AU-C-02", "agent://cafe%CC%81.example", "agent://café.example"},
		{"AU-C-03", "agent://caf%C3%A9.example", "agent://café.example"},
		{"AU-C-04", "agent://org/svc=a%2fb", "agent://org/svc=a%2Fb"},
		{"AU-C-05", "agent://%41cme", "agent://acme"},
		{"AU-C-06", "agent://stra%C3%9Fe.example", "agent://strasse.example"},
		{"AU-C-09", "agent://org/Ns=Alpha", "agent://org/ns=alpha"},
		{"AU-C-10", "agent://Org123/ns=NS_456/svc=Svc-789", "agent://org123/ns=ns_456/svc=svc-789"},
		{"AU-C-11", "agent://org/svc=a%20b", "agent://org/svc=a%20b"},
		{"AU-C-12", "agent://op%E2%80%8Dtic", "agent://optic"},
		{"AU-Q-01", "agent://*/structural-health?lang=en&domain=bridge", "agent://*/structural-health?domain=bridge&lang=en"},
		{"AU-Q-02", "agent://*/cap?b=2&a=1&b=1", "agent://*/cap?a=1&b=1&b=2"},
		{"AU-Q-03", "agent://*/cap?b=1&A=2", "agent://*/cap?A=2&b=1"},
		{"AU-Q-04", "agent://*/cap?flag=", "agent://*/cap?flag="},
		{"AU-Q-07", "agent://*/cap?note=a%26b", "agent://*/cap?note=a%26b"},
		{"AU-Q-08", "agent://org/svc=x?b=2&a=1", "agent://org/svc=x?a=1&b=2"},
	}
	for _, c := range cases {
		got, err := Canonical(c.in)
		if err != nil {
			t.Errorf("%s: Canonical(%q) error %v", c.id, c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: Canonical(%q)\n got  %q\n want %q", c.id, c.in, got, c.want)
		}
		// AU-C-08 idempotence over every ACCEPT vector.
		again, err := Canonical(got)
		if err != nil || again != got {
			t.Errorf("%s: not idempotent: canonical(%q)=%q err=%v", c.id, got, again, err)
		}
	}
}

// AU-L / AU-W / AU-Q / AU-R REJECT vectors (agent-uri-spec §6): input → reason.
func TestParseReject(t *testing.T) {
	cases := []struct{ id, in, reason string }{
		{"AU-L-01", "agent://org/a/b/c/d", "UNMARKED_SEGMENT"},
		{"AU-L-02", "agent://org/structural/vibration", "UNMARKED_SEGMENT"},
		{"AU-L-03", "agent://org/svc=x/ns=y", "POSITION_ORDER"},
		{"AU-L-04", "agent://org/ns=a/ns=b", "DUPLICATE_MARKER"},
		{"AU-L-05", "agent://myorg/myns/myservice", "UNMARKED_SEGMENT"},
		{"AU-L-06", "agent://org/ns/svc/peer123", "UNMARKED_SEGMENT"},
		{"AU-L-07", "agent://ns/chatroom/", "EMPTY_LABEL"}, // trailing '/' = empty final segment (§6.2)
		{"AU-L-08", "agent://org/ns=", "EMPTY_LABEL"},
		{"AU-L-09", "agent://", "EMPTY_AUTHORITY"},
		{"AU-L-10", "agent://a/b/c/d/e/f", "UNMARKED_SEGMENT"},
		{"AU-L-11", "agent://org/ns=n/svc=s#section1", "FRAGMENT_PRESENT"},
		{"AU-L-13", "agent://Org123/NS_456/Svc-789", "UNMARKED_SEGMENT"},
		{"AU-L-14", "agent://org/svc=a b", "ILLEGAL_CHAR"},
		{"AU-W-03", "agent://*", "WILDCARD_FORM"},
		{"AU-W-04", "agent://*/", "EMPTY_LABEL"},
		{"AU-W-05", "agent://*.example/cap", "WILDCARD_IN_LABEL"},
		{"AU-W-06", "agent://*/a/b", "WILDCARD_FORM"},
		{"AU-W-07", "agent://org/*", "WILDCARD_IN_LABEL"},
		{"AU-W-08", "agent://ab*cd/svc=x", "WILDCARD_IN_LABEL"},
		{"AU-W-09", "agent://*/translate+summarize", "ILLEGAL_CHAR"},
		{"AU-W-12", "agent://*/svc=translate", "ILLEGAL_CHAR"},
		{"AU-Q-05", "agent://*/cap?flag", "QUERY_SYNTAX"},
		{"AU-Q-06", "agent://*/cap?", "QUERY_SYNTAX"},
		{"AU-L-12", "lob://service", "SCHEME_MISMATCH"},
		{"AU-L-12b", "http://example.com", "SCHEME_MISMATCH"},
		{"AU-R-01", "agent://p%D0%B0ypal.example", "MIXED_SCRIPT"},
		{"AU-R-03", "agent://exa%E2%80%A8mple", "DISALLOWED_CODEPOINT"},
	}
	for _, c := range cases {
		_, err := Parse(c.in)
		if err == nil {
			t.Errorf("%s: Parse(%q) = nil error, want %s", c.id, c.in, c.reason)
			continue
		}
		pe, ok := err.(*Error)
		if !ok || pe.Reason != c.reason {
			t.Errorf("%s: Parse(%q) reason = %v, want %s", c.id, c.in, err, c.reason)
		}
	}
}

// AU-F fold-collision pairs + two-form discrimination (§6.5, §6.8).
func TestFoldCollisionAndForms(t *testing.T) {
	pairs := [][2]string{
		{"agent://Bridge-Ops.example/svc=X", "agent://bridge-ops.EXAMPLE/SVC=x"}, // AU-F-01
		{"agent://cafe%CC%81.example", "agent://caf%C3%A9.example"},              // AU-F-02
		{"agent://stra%C3%9Fe.example", "agent://strasse.example"},               // AU-F-03
	}
	for i, p := range pairs {
		eq, err := Equals(p[0], p[1])
		if err != nil || !eq {
			t.Errorf("AU-F-%02d: Equals(%q,%q)=%v err=%v, want true", i+1, p[0], p[1], eq, err)
		}
	}
	// §6.8: capability query vs concrete locator form guards.
	if _, err := RequireConcreteLocator("agent://*/structural-health?domain=bridge"); err == nil {
		t.Error("require_concrete_locator over wildcard: want WRONG_FORM")
	}
	if _, err := ValidateCapabilityQuery("agent://bridge-ops.example"); err == nil {
		t.Error("validate_capability_query over concrete: want WRONG_FORM")
	}
}
