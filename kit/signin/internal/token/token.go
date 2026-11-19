// Package token makes the random values behind API tokens, sessions and
// codes, and the API token format "<prefix>_<id><secret><check>": a public id
// of 16 bytes and a secret of 32 bytes in fixed-width base62, then a CRC32 of
// everything before it. The checksum lets a guard drop a mistyped or made-up
// token without a store read, and secret scanners match the prefix.
package token

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"hash/crc32"
	"math/big"
	"regexp"
	"strings"
)

const (
	alphabet  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	idChars   = 22
	secChars  = 43
	sumChars  = 6
	bodyChars = idChars + secChars + sumChars
)

var prefixRE = regexp.MustCompile(`^[a-z]{2,8}$`)

// ValidPrefix reports whether p may start a token: two to eight lower-case
// letters.
func ValidPrefix(p string) bool { return prefixRE.MatchString(p) }

// Token is a new API token. Value is shown once, ID is kept in the clear and
// Secret only as a MAC.
type Token struct {
	ID, Secret, Value string
}

// New makes a token under prefix.
func New(prefix string) (Token, error) {
	if !ValidPrefix(prefix) {
		return Token{}, errors.New("token: prefix must be 2 to 8 lower-case letters")
	}
	id := base62(randomBytes(16), idChars)
	secret := base62(randomBytes(32), secChars)
	head := prefix + "_" + id + secret
	return Token{ID: id, Secret: secret, Value: head + checksum(head)}, nil
}

// Parse splits value into id and secret when it has the shape of a token
// under prefix and its checksum holds.
func Parse(prefix, value string) (id, secret string, ok bool) {
	body, found := strings.CutPrefix(value, prefix+"_")
	if !found || len(body) != bodyChars {
		return "", "", false
	}
	for i := 0; i < len(body); i++ {
		if strings.IndexByte(alphabet, body[i]) < 0 {
			return "", "", false
		}
	}
	head := value[:len(value)-sumChars]
	if checksum(head) != value[len(value)-sumChars:] {
		return "", "", false
	}
	return body[:idChars], body[idChars : idChars+secChars], true
}

// Random returns n random bytes in unpadded base64url.
func Random(n int) string { return base64.RawURLEncoding.EncodeToString(randomBytes(n)) }

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func checksum(s string) string {
	return base62(big.NewInt(int64(crc32.ChecksumIEEE([]byte(s)))).Bytes(), sumChars)
}

func base62(b []byte, width int) string {
	n := new(big.Int).SetBytes(b)
	out := make([]byte, width)
	base := big.NewInt(62)
	mod := new(big.Int)
	for i := width - 1; i >= 0; i-- {
		n.DivMod(n, base, mod)
		out[i] = alphabet[mod.Int64()]
	}
	return string(out)
}
