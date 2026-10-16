package payment

import "testing"

func TestParseAmountCanonicalLedgerRange(t *testing.T) {
	for s, want := range map[string]uint64{"0": 0, "7": 7, "9223372036854775807": 1<<63 - 1} {
		if n, err := ParseAmount(s); err != nil || n != want {
			t.Errorf("ParseAmount(%q) = %d, %v", s, n, err)
		}
	}
	for _, s := range []string{"", "007", "00", "-1", "+7", "0x7", "1_0", " 7", "9223372036854775808", "18446744073709551615", "18446744073709551616"} {
		if n, err := ParseAmount(s); err == nil {
			t.Errorf("ParseAmount(%q) = %d, want an error", s, n)
		}
	}
}
