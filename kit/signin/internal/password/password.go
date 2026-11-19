// Package password hashes the MAC of a password with Argon2id in the encoded
// form "$argon2id$v=19$m=...,t=...,p=...$salt$hash".
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// The parameters OWASP names for Argon2id with 19 MiB.
const (
	memory  = 19 * 1024
	passes  = 2
	lanes   = 1
	saltLen = 16
	keyLen  = 32
)

// A hash read from a store may ask for at most this much, so a written row
// cannot make every sign-in allocate gigabytes.
const (
	maxMemory = 64 * 1024
	maxPasses = 4
	maxLanes  = 4
)

var (
	errFormat = errors.New("password: not an argon2id hash")
	errLimit  = errors.New("password: argon2id parameters above the limit")
)

// Hash returns the encoded Argon2id hash of input under a fresh salt.
func Hash(input []byte) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey(input, salt, passes, memory, lanes, keyLen)
	return encode(memory, passes, lanes, salt, key), nil
}

// Check reports whether input matches hash. It fails on a hash it cannot
// read or whose parameters are above the limit.
func Check(hash string, input []byte) (bool, error) {
	p, err := parse(hash)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey(input, p.salt, p.passes, p.memory, p.lanes, uint32(len(p.key)))
	return subtle.ConstantTimeCompare(got, p.key) == 1, nil
}

// Current reports whether hash uses the parameters Hash writes today, so a
// sign-in can write a hash with older ones anew.
func Current(hash string) bool {
	p, err := parse(hash)
	return err == nil && p.memory == memory && p.passes == passes && p.lanes == lanes && len(p.key) == keyLen
}

type params struct {
	memory, passes uint32
	lanes          uint8
	salt, key      []byte
}

func parse(hash string) (params, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return params{}, errFormat
	}
	var p params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.passes, &p.lanes); err != nil {
		return params{}, errFormat
	}
	if p.memory > maxMemory || p.passes > maxPasses || p.lanes > maxLanes || p.memory == 0 || p.passes == 0 || p.lanes == 0 {
		return params{}, errLimit
	}
	var err error
	if p.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(p.salt) < 8 {
		return params{}, errFormat
	}
	if p.key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(p.key) < 16 || len(p.key) > 64 {
		return params{}, errFormat
	}
	return p, nil
}

func encode(m, t uint32, p uint8, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", m, t, p,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}
