package signin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// Sealer is the app's own key. Seal and Open encrypt with authentication,
// MAC is a keyed hash. Every call names a domain, and a value sealed or
// MACed under one domain never counts under another. The package puts the
// kind and the id into the domain, so a sealed secret cannot be moved to
// another account either.
type Sealer interface {
	Seal(domain string, plain []byte) ([]byte, error)
	Open(domain string, sealed []byte) ([]byte, error)
	MAC(domain string, data []byte) []byte
}

const sealVersion = 1

var errSealed = errors.New("signin: sealed value does not open")

// NewSealer returns a Sealer on a key of at least 32 bytes, for an app that
// has no seal of its own: AES-256-GCM with the domain as associated data,
// and HMAC-SHA256 over the length of the domain, the domain and the data.
func NewSealer(key []byte) (Sealer, error) {
	if len(key) < 32 {
		return nil, errors.New("signin: the sealer needs a key of at least 32 bytes")
	}
	block, err := aes.NewCipher(derive(key, "seal"))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &keySealer{gcm: gcm, mac: derive(key, "mac")}, nil
}

type keySealer struct {
	gcm cipher.AEAD
	mac []byte
}

func derive(key []byte, label string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("signin/sealer/" + label))
	return m.Sum(nil)
}

func (s *keySealer) Seal(domain string, plain []byte) ([]byte, error) {
	out := make([]byte, 1+s.gcm.NonceSize(), 1+s.gcm.NonceSize()+len(plain)+s.gcm.Overhead())
	out[0] = sealVersion
	rand.Read(out[1:])
	return s.gcm.Seal(out, out[1:], plain, []byte(domain)), nil
}

func (s *keySealer) Open(domain string, sealed []byte) ([]byte, error) {
	n := s.gcm.NonceSize()
	if len(sealed) < 1+n+s.gcm.Overhead() || sealed[0] != sealVersion {
		return nil, errSealed
	}
	plain, err := s.gcm.Open(nil, sealed[1:1+n], sealed[1+n:], []byte(domain))
	if err != nil {
		return nil, errSealed
	}
	return plain, nil
}

func (s *keySealer) MAC(domain string, data []byte) []byte {
	m := hmac.New(sha256.New, s.mac)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(domain)))
	m.Write(n[:])
	m.Write([]byte(domain))
	m.Write(data)
	return m.Sum(nil)
}
