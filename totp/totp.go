// Package totp generates and checks the six-digit codes a payer's app shows and
// their agent types in.
//
// Codes are RFC 6238 TOTP with HMAC-SHA1, 30-second steps and six digits, the
// same parameters Google Authenticator uses, so an existing secret store keeps
// producing the same codes. A code from the step before or after the
// current one is also accepted, which absorbs up to about 30 seconds of clock
// drift between the two phones.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	step   = 30 * time.Second
	digits = 6
	// drift is how many steps either side of the current one are accepted.
	drift = 1
)

var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a new base32 secret of 160 bits, 32 characters.
func GenerateSecret() (string, error) {
	key := make([]byte, 20)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generating TOTP secret: %w", err)
	}
	return encoding.EncodeToString(key), nil
}

func decode(secret string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.TrimRight(strings.ReplaceAll(secret, " ", ""), "="))
	key, err := encoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("TOTP secret is not base32: %w", err)
	}
	return key, nil
}

func codeAt(key []byte, counter uint64) int {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return int(value % 1_000_000)
}

func counterAt(at time.Time) uint64 { return uint64(at.Unix() / int64(step/time.Second)) }

// Code returns the code for secret at the given time, zero-padded to six digits.
func Code(secret string, at time.Time) (string, error) {
	key, err := decode(secret)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", digits, codeAt(key, counterAt(at))), nil
}

// Match returns the step code belongs to when it is right for secret at the
// given time, or one step either side of it. A code is exactly six ASCII
// digits: a sign, a space or a seventh digit is refused, so each code has one
// spelling and cannot be presented again spelt differently.
//
// Callers that must not accept a code twice remember the step and refuse any
// code whose step is not later, as RFC 6238 section 5.2 requires.
func Match(secret, code string, at time.Time) (step uint64, ok bool) {
	if len(code) != digits || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, false
	}
	key, err := decode(secret)
	if err != nil || secret == "" {
		return 0, false
	}
	counter := counterAt(at)
	for i := -drift; i <= drift; i++ {
		c := uint64(int64(counter) + int64(i))
		if hmac.Equal([]byte(fmt.Sprintf("%0*d", digits, codeAt(key, c))), []byte(code)) {
			return c, true
		}
	}
	return 0, false
}

// Validate reports whether code is right for secret at the given time, or one
// step either side of it.
func Validate(secret, code string, at time.Time) bool {
	_, ok := Match(secret, code, at)
	return ok
}

// SecondsUntilExpiry is how long the current code has left, 1 to 30.
func SecondsUntilExpiry(at time.Time) int64 {
	window := step.Milliseconds()
	return (window - at.UnixMilli()%window) / 1000
}
