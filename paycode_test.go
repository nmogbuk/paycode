package paycode

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nmogbuk/paycode/totp"
)

type fakeStore struct {
	failures  int
	recorded  []Attempt
	markedTo  *uint64
	uses      []Attempt
	failErr   error
	markErr   error
	countErr  error
	useErr    error
	nextUseID string
}

func (f *fakeStore) RecentFailures(_ context.Context, _ string, _ time.Time) (int, error) {
	return f.failures, f.countErr
}

func (f *fakeStore) RecordFailure(_ context.Context, a Attempt) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.recorded = append(f.recorded, a)
	return nil
}

func (f *fakeStore) MarkStepUsed(_ context.Context, _ string, step uint64) error {
	if f.markErr != nil {
		return f.markErr
	}
	s := step
	f.markedTo = &s
	return nil
}

func (f *fakeStore) RecordUse(_ context.Context, a Attempt) (string, error) {
	if f.useErr != nil {
		return "", f.useErr
	}
	f.uses = append(f.uses, a)
	if f.nextUseID == "" {
		return "use-1", nil
	}
	return f.nextUseID, nil
}

var at = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func newPayer(t *testing.T) (Payer, string, uint64) {
	t.Helper()
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.Code(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	step, ok := totp.Match(secret, code, at)
	if !ok {
		t.Fatal("generated code does not match")
	}
	return Payer{ID: "payer-1", Secret: secret}, code, step
}

func checker(s Store) *Checker {
	return New(s, WithClock(func() time.Time { return at }))
}

func TestRightCodeIsAccepted(t *testing.T) {
	p, code, step := newPayer(t)
	s := &fakeStore{}
	id, err := checker(s).Use(context.Background(), p, code, Movement{AgentID: "agent-1", Kind: "CREDIT", Amount: 1500})
	if err != nil {
		t.Fatalf("want accepted, got %v", err)
	}
	if id != "use-1" {
		t.Fatalf("want the store's id, got %q", id)
	}
	if s.markedTo == nil || *s.markedTo != step {
		t.Fatalf("want step %d marked used, got %v", step, s.markedTo)
	}
	if len(s.uses) != 1 || s.uses[0].Amount != 1500 {
		t.Fatalf("want the movement recorded, got %+v", s.uses)
	}
	if s.uses[0].ExpiresAt != at.Add(DefaultCodeLife) {
		t.Fatalf("want expiry one code life out, got %v", s.uses[0].ExpiresAt)
	}
}

func TestWrongCodeIsRecordedAndMustCommit(t *testing.T) {
	p, _, _ := newPayer(t)
	s := &fakeStore{}
	_, err := checker(s).Use(context.Background(), p, "000000", Movement{AgentID: "agent-1"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
	var rec Recorded
	if !errors.As(err, &rec) {
		t.Fatal("a wrong code must be wrapped in Recorded so the caller commits the attempt")
	}
	if len(s.recorded) != 1 {
		t.Fatalf("want the attempt recorded, got %d", len(s.recorded))
	}
	if s.markedTo != nil {
		t.Fatal("a wrong code must not mark a step used")
	}
}

func TestLockoutAtMaxFailures(t *testing.T) {
	p, code, _ := newPayer(t)
	s := &fakeStore{failures: DefaultMaxFailures}
	_, err := checker(s).Use(context.Background(), p, code, Movement{})
	if !errors.Is(err, ErrLockedOut) {
		t.Fatalf("want ErrLockedOut, got %v", err)
	}
	if len(s.uses) != 0 || s.markedTo != nil {
		t.Fatal("a locked-out payer must not have a code spent")
	}
	var rec Recorded
	if errors.As(err, &rec) {
		t.Fatal("a lockout writes nothing, so it must not be Recorded")
	}
}

func TestBelowMaxFailuresStillWorks(t *testing.T) {
	p, code, _ := newPayer(t)
	s := &fakeStore{failures: DefaultMaxFailures - 1}
	if _, err := checker(s).Use(context.Background(), p, code, Movement{}); err != nil {
		t.Fatalf("want accepted below the limit, got %v", err)
	}
}

func TestReplayIsRefusedAndNotCounted(t *testing.T) {
	p, code, step := newPayer(t)
	p.LastStep = &step
	s := &fakeStore{}
	_, err := checker(s).Use(context.Background(), p, code, Movement{})
	if !errors.Is(err, ErrReplayed) {
		t.Fatalf("want ErrReplayed, got %v", err)
	}
	if len(s.recorded) != 0 {
		t.Fatal("a replay must not be counted as a wrong code")
	}
	var rec Recorded
	if errors.As(err, &rec) {
		t.Fatal("a replay writes nothing, so it must not be Recorded")
	}
}

func TestEarlierStepIsRefused(t *testing.T) {
	p, code, step := newPayer(t)
	later := step + 5
	p.LastStep = &later
	s := &fakeStore{}
	if _, err := checker(s).Use(context.Background(), p, code, Movement{}); !errors.Is(err, ErrReplayed) {
		t.Fatalf("want a code from an earlier step refused, got %v", err)
	}
}

func TestNoSecret(t *testing.T) {
	s := &fakeStore{}
	_, err := checker(s).Use(context.Background(), Payer{ID: "payer-1"}, "123456", Movement{})
	if !errors.Is(err, ErrNoSecret) {
		t.Fatalf("want ErrNoSecret, got %v", err)
	}
}

func TestMalformedCodesAreRejected(t *testing.T) {
	p, code, _ := newPayer(t)
	for name, mangle := range map[string]func(string) string{
		"five digits":    func(c string) string { return c[1:] },
		"seventh digit":  func(c string) string { return "0" + c },
		"leading space":  func(c string) string { return " " + c },
		"trailing space": func(c string) string { return c + " " },
		"plus sign":      func(c string) string { return "+" + c },
	} {
		t.Run(name, func(t *testing.T) {
			s := &fakeStore{}
			_, err := checker(s).Use(context.Background(), p, mangle(code), Movement{})
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestLongCodeIsTruncatedBeforeStoring(t *testing.T) {
	p, _, _ := newPayer(t)
	long := ""
	for i := 0; i < 400; i++ {
		long += "9"
	}
	s := &fakeStore{}
	if _, err := checker(s).Use(context.Background(), p, long, Movement{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
	if len(s.recorded) != 1 || len(s.recorded[0].Code) != maxStoredCode {
		t.Fatalf("want the stored code truncated to %d, got %d", maxStoredCode, len(s.recorded[0].Code))
	}
}

func TestStoreErrorsPropagate(t *testing.T) {
	p, code, _ := newPayer(t)
	boom := errors.New("boom")
	for name, s := range map[string]*fakeStore{
		"counting": {countErr: boom},
		"marking":  {markErr: boom},
		"use":      {useErr: boom},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := checker(s).Use(context.Background(), p, code, Movement{}); !errors.Is(err, boom) {
				t.Fatalf("want the store error wrapped, got %v", err)
			}
		})
	}
}

func TestDriftWindowIsAccepted(t *testing.T) {
	p, _, _ := newPayer(t)
	prev, err := totp.Code(p.Secret, at.Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeStore{}
	if _, err := checker(s).Use(context.Background(), p, prev, Movement{}); err != nil {
		t.Fatalf("want the previous step accepted as drift, got %v", err)
	}
}
