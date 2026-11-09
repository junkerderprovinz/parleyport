package relay

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// ErrSealed is returned when a frame cannot be opened, whether the key was
// wrong or the frame truncated or tampered with. The cases share one error so
// an attacker learns nothing about which guess was closer.
var ErrSealed = errors.New("relay: frame could not be opened")

// nonceLen is AES-GCM's standard nonce size. Nonces are random rather than
// counted, because both ends seal on their own and a counter would have to
// survive reconnects.
const nonceLen = 12

func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("relay: frame key is %d bytes, want 32", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal encrypts plaintext under key as nonce and ciphertext, bound to aad, the
// frame's clear routing fields, so a relay that delivers it elsewhere or
// replays one answer as another makes the tag fail on open.
func seal(key []byte, aad string, plaintext []byte) ([]byte, error) {
	gcm, err := aead(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("relay: no randomness for a frame nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, []byte(aad)), nil
}

// open reverses seal and returns ErrSealed for every failure.
func open(key []byte, aad string, sealed []byte) ([]byte, error) {
	gcm, err := aead(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < nonceLen {
		return nil, ErrSealed
	}
	plaintext, err := gcm.Open(nil, sealed[:nonceLen], sealed[nonceLen:], []byte(aad))
	if err != nil {
		return nil, ErrSealed
	}
	return plaintext, nil
}
