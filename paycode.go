// Package paycode checks the six-digit code on a payer's phone that a field
// agent types in when cash changes hands. The code is the proof that the payer
// was present and agreed to the amount.
//
// The three rules that make six digits safe:
//
//  1. A code is accepted once. Acceptance marks the TOTP *step* used, so
//     replaying that code, or any code from an earlier step, is refused. The
//     step is what is remembered, not the string.
//  2. Wrong codes are counted. Three in ten minutes locks the payer's code for
//     the rest of the window. Without this a six-digit code is guessable.
//  3. A replay is not a wrong code. It cannot succeed, so counting it would
//     only lock out an agent whose app sent the same request twice.
//
// Persistence is yours: implement Store. The reference behaviour a Store must
// provide is described on each method.
package paycode

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/nmogbuk/paycode/totp"
)

// Refusals. Each is returned unwrapped so callers can match with errors.Is.
var (
	// ErrLockedOut means too many wrong codes within the lockout window.
	ErrLockedOut = errors.New("paycode: too many wrong codes, locked out")
	// ErrReplayed means the code was right but its step was already used.
	ErrReplayed = errors.New("paycode: code already used")
	// ErrInvalid means the code is not right for this payer now.
	ErrInvalid = errors.New("paycode: code is not valid")
	// ErrNoSecret means the payer has no code configured yet.
	ErrNoSecret = errors.New("paycode: payer has no code configured")
)

// Recorded wraps a refusal that wrote something to the Store. A caller running
// Use inside a transaction MUST commit when it sees this, because the failed
// attempt that was recorded is what the lockout counts. Rolling back erases
// the evidence and the lockout never triggers.
type Recorded struct{ Err error }

func (r Recorded) Error() string { return r.Err.Error() }
func (r Recorded) Unwrap() error { return r.Err }

// Payer is whose code is being checked.
//
// Read the row FOR UPDATE in the same transaction as the Use call. Two
// concurrent requests must not both spend one code, and the lock is what
// prevents it.
type Payer struct {
	ID     string
	Secret string
	// LastStep is the most recent TOTP step accepted for this payer, or nil if
	// none has been. Persisted by Store.MarkStepUsed.
	LastStep *uint64
}

// Movement is what the code authorises. Kind and Amount are opaque here and
// stored as given.
type Movement struct {
	AgentID string
	Kind    string
	Amount  float64
}

// Attempt is one use of a code, successful or not.
type Attempt struct {
	PayerID   string
	AgentID   string
	Code      string
	Kind      string
	Amount    float64
	At        time.Time
	ExpiresAt time.Time
}

// Store is the persistence Use needs.
type Store interface {
	// RecentFailures counts attempts for payerID recorded at or after since
	// that were not accepted.
	RecentFailures(ctx context.Context, payerID string, since time.Time) (int, error)
	// RecordFailure stores a rejected attempt. Its Code is already truncated.
	RecordFailure(ctx context.Context, a Attempt) error
	// MarkStepUsed persists step as the latest accepted step for payerID.
	MarkStepUsed(ctx context.Context, payerID string, step uint64) error
	// RecordUse stores an accepted attempt and returns its identifier.
	RecordUse(ctx context.Context, a Attempt) (string, error)
}

// Defaults.
const (
	DefaultLockout     = 10 * time.Minute
	DefaultMaxFailures = 3
	DefaultCodeLife    = 60 * time.Second
	// maxStoredCode bounds what is kept from a rejected attempt, so whatever an
	// agent typed can be stored without an unbounded write.
	maxStoredCode = 255
)

// Checker checks codes against a Store. The zero value is not usable; use New.
type Checker struct {
	store       Store
	lockout     time.Duration
	maxFailures int
	codeLife    time.Duration
	now         func() time.Time
}

// Option configures a Checker.
type Option func(*Checker)

// WithLockout sets how long wrong codes are counted for, and how long a locked
// payer waits. Default 10 minutes.
func WithLockout(d time.Duration) Option { return func(c *Checker) { c.lockout = d } }

// WithMaxFailures sets how many wrong codes within the lockout window trigger
// a lockout. Default 3.
func WithMaxFailures(n int) Option { return func(c *Checker) { c.maxFailures = n } }

// WithCodeLife sets how long an accepted code is recorded as valid for.
// Default 60 seconds, which is the code's own step plus the drift step after it.
func WithCodeLife(d time.Duration) Option { return func(c *Checker) { c.codeLife = d } }

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option { return func(c *Checker) { c.now = now } }

// New returns a Checker backed by store.
func New(store Store, opts ...Option) *Checker {
	c := &Checker{
		store:       store,
		lockout:     DefaultLockout,
		maxFailures: DefaultMaxFailures,
		codeLife:    DefaultCodeLife,
		now:         time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Use checks code for p and, if it is right, records the movement it
// authorises and returns that record's identifier.
//
// Errors:
//
//	ErrNoSecret             the payer has no code yet
//	ErrLockedOut            too many wrong codes recently; nothing was written
//	Recorded{ErrInvalid}    wrong code; the attempt WAS written, so commit
//	ErrReplayed             right code, step already spent; nothing was written
func (c *Checker) Use(ctx context.Context, p Payer, code string, m Movement) (string, error) {
	now := c.now()

	failed, err := c.store.RecentFailures(ctx, p.ID, now.Add(-c.lockout))
	if err != nil {
		return "", fmt.Errorf("counting recent failures: %w", err)
	}
	if failed >= c.maxFailures {
		return "", ErrLockedOut
	}

	if p.Secret == "" {
		return "", ErrNoSecret
	}

	step, ok := totp.Match(p.Secret, code, now)
	if !ok {
		a := Attempt{
			PayerID: p.ID,
			AgentID: m.AgentID,
			Code:    truncate(code, maxStoredCode),
			Kind:    m.Kind,
			At:      now,
		}
		if err := c.store.RecordFailure(ctx, a); err != nil {
			return "", fmt.Errorf("recording a failed attempt: %w", err)
		}
		return "", Recorded{ErrInvalid}
	}

	// A replay is refused but not counted: it cannot succeed, so counting it
	// would only lock out an agent whose app retried.
	if p.LastStep != nil && step <= *p.LastStep {
		return "", ErrReplayed
	}

	if err := c.store.MarkStepUsed(ctx, p.ID, step); err != nil {
		return "", fmt.Errorf("marking the step used: %w", err)
	}

	id, err := c.store.RecordUse(ctx, Attempt{
		PayerID:   p.ID,
		AgentID:   m.AgentID,
		Code:      code,
		Kind:      m.Kind,
		Amount:    m.Amount,
		At:        now,
		ExpiresAt: now.Add(c.codeLife),
	})
	if err != nil {
		return "", fmt.Errorf("recording the use: %w", err)
	}
	return id, nil
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
