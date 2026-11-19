// Package totp makes and checks the six-digit codes of RFC 6238 with SHA-1
// and 30-second steps, the form every authenticator app reads.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

const step = 30

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a fresh 160-bit secret.
func NewSecret() ([]byte, error) {
	s := make([]byte, 20)
	_, err := rand.Read(s)
	return s, err
}

// Encode returns secret in the base32 form apps let people type in.
func Encode(secret []byte) string { return b32.EncodeToString(secret) }

// URI is what the QR code holds for an authenticator app.
func URI(issuer, account string, secret []byte) string {
	q := url.Values{"secret": {Encode(secret)}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Code returns the code for the step that holds t.
func Code(secret []byte, t time.Time) string { return at(secret, t.Unix()/step) }

// Check accepts code for the step of now or the one on either side, as long
// as that step is later than last. It returns the step it matched, which the
// caller keeps as the next last so no code counts twice.
func Check(secret []byte, code string, now time.Time, last int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	cur := now.Unix() / step
	for s := cur - 1; s <= cur+1; s++ {
		if s > last && subtle.ConstantTimeCompare([]byte(at(secret, s)), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}

func at(secret []byte, counter int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}
