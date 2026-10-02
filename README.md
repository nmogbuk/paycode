# paycode

Proof that a payer was present and agreed to an amount, for cash collected in
the field.

The payer's phone shows a six-digit code. The agent types it in when the cash
changes hands. If the code is right, the movement is recorded; if it is wrong,
the attempt is recorded too, because that is what makes six digits safe.

Built for daily savings collection in Nigeria. The same shape fits agent
banking, cash on delivery, field service sign-off, meter reading, and anywhere
else money or a service changes hands in person and both parties need to be
provably there.

## Why six digits is enough

It is not, on its own. Six digits is a million guesses, and an attacker with
unlimited attempts walks straight through. Three rules close that:

**A code is accepted once, by step and not by string.** Acceptance records the
TOTP *step* the code belonged to. Replaying the same code, or presenting one
from an earlier step, is refused. Remembering the string would be defeated by
the next window; remembering the step is not. RFC 6238 §5.2 asks for exactly
this and most implementations skip it.

**Wrong codes are counted and lock the payer out.** Three within ten minutes
locks their code for the rest of the window. A million guesses at three per ten
minutes is not an attack, it is a hobby.

**A replay is refused but never counted.** It cannot succeed, so counting it
would only lock out an agent whose app sent the same request twice on a bad
connection. In the field that is a weekly occurrence, not an edge case.

## Use

```go
checker := paycode.New(store)

id, err := checker.Use(ctx, payer, code, paycode.Movement{
    AgentID: agentID,
    Kind:    "CREDIT",
    Amount:  1500,
})

switch {
case err == nil:
    // accepted; id identifies the recorded movement
case errors.Is(err, paycode.ErrLockedOut):
case errors.Is(err, paycode.ErrReplayed):
case errors.Is(err, paycode.ErrInvalid):
case errors.Is(err, paycode.ErrNoSecret):
}
```

## Two things you must get right in the caller

**Lock the payer row for the duration.** Read it `FOR UPDATE` in the same
transaction as the `Use` call. Two requests must not both spend one code, and
the row lock is what stops them.

**Commit on `Recorded`.** A wrong code returns `Recorded{ErrInvalid}`, and the
wrapper means the Store already wrote the failed attempt. That attempt is what
the lockout counts. Roll the transaction back and you erase the evidence, and
the lockout never triggers no matter how many times someone guesses.

```go
var rec paycode.Recorded
if errors.As(err, &rec) {
    tx.Commit() // the refusal stands, but the attempt must persist
}
```

Refusals that write nothing (`ErrLockedOut`, `ErrReplayed`, `ErrNoSecret`) are
returned unwrapped, so `errors.As` tells the two cases apart.

## Persistence is yours

Implement `Store`: count recent failures, record a failure, mark a step used,
record a use. Four methods, no assumptions about your schema or your database.

## Configuration

```go
paycode.New(store,
    paycode.WithLockout(10*time.Minute),
    paycode.WithMaxFailures(3),
    paycode.WithCodeLife(60*time.Second),
)
```

## totp

`paycode/totp` is the RFC 6238 implementation underneath: HMAC-SHA1,
30-second steps, six digits, one step of drift either side. The same
parameters Google Authenticator uses, so an existing secret store keeps working.

`Match` returns the step a code belongs to, which is what makes single-use
enforcement possible. It also insists on exactly six ASCII digits, so a code
has one spelling and cannot be re-presented spelt differently with a space or
a leading plus.

## Install

```
go get github.com/nmogbuk/paycode
```

Go 1.24 or newer. No dependencies outside the standard library.

## Tests

```
go test ./...
```

## Licence

MIT.
