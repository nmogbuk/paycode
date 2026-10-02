package totp

import (
	"testing"
	"time"
)

// RFC 6238 appendix B uses the ASCII secret "12345678901234567890"; these are
// the SHA-1 vectors cut to six digits.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestCodesMatchRFC6238(t *testing.T) {
	cases := map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	}
	for unix, want := range cases {
		got, err := Code(rfcSecret, time.Unix(unix, 0))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("Code at %d = %s, want %s", unix, got, want)
		}
	}
}

func TestValidateAcceptsOneStepOfDriftEitherSide(t *testing.T) {
	now := time.Unix(1111111111, 0)
	current, _ := Code(rfcSecret, now)
	before, _ := Code(rfcSecret, now.Add(-30*time.Second))
	after, _ := Code(rfcSecret, now.Add(30*time.Second))
	tooOld, _ := Code(rfcSecret, now.Add(-90*time.Second))

	for name, code := range map[string]string{"current": current, "previous step": before, "next step": after} {
		if !Validate(rfcSecret, code, now) {
			t.Errorf("%s code %s refused", name, code)
		}
	}
	if Validate(rfcSecret, tooOld, now) && tooOld != current && tooOld != before && tooOld != after {
		t.Errorf("code from three steps ago %s accepted", tooOld)
	}
	for _, bad := range []string{"", "abcdef", "-1", "1000000", " " + current, current + " ", "0" + current, "+" + current, current[1:]} {
		if Validate(rfcSecret, bad, now) {
			t.Errorf("%q accepted", bad)
		}
	}
	if Validate("", current, now) {
		t.Error("empty secret accepted")
	}
}

func TestMatchNamesTheStepACodeBelongsTo(t *testing.T) {
	now := time.Unix(1111111111, 0)
	counter := counterAt(now)
	for offset, at := range map[int64]time.Time{-1: now.Add(-30 * time.Second), 0: now, 1: now.Add(30 * time.Second)} {
		code, _ := Code(rfcSecret, at)
		step, ok := Match(rfcSecret, code, now)
		if !ok || step != uint64(int64(counter)+offset) {
			t.Errorf("offset %d: step %d, %v; want %d", offset, step, ok, int64(counter)+offset)
		}
	}
	// 1234567890 gives a code with a leading zero, which must be matched as
	// written.
	at := time.Unix(1234567890, 0)
	if _, ok := Match(rfcSecret, "005924", at); !ok {
		t.Error("a code with a leading zero was refused")
	}
	if _, ok := Match(rfcSecret, "5924", at); ok {
		t.Error("a code without its leading zeros was accepted")
	}
}

func TestGeneratedSecretsAreLongAndUsable(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 32 {
		t.Fatalf("secret length = %d", len(secret))
	}
	now := time.Now()
	code, err := Code(secret, now)
	if err != nil || !Validate(secret, code, now) {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestSecondsUntilExpiry(t *testing.T) {
	if got := SecondsUntilExpiry(time.Unix(60, 0)); got != 30 {
		t.Errorf("at a step boundary = %d", got)
	}
	if got := SecondsUntilExpiry(time.Unix(89, 0)); got != 1 {
		t.Errorf("one second before the boundary = %d", got)
	}
}
