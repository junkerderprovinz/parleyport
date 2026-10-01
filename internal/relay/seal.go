package relay

// Sealing proxy frames so the relay that carries them cannot read them. The
// relay routes on the target and the request id; the path, body and bearer
// token are sealed under DeriveFrameKey, which the relay does not hold.
//
// AES-256-GCM is authenticated, in the standard library and hardware
// accelerated everywhere this ships. The 12-byte nonce is random and prefixed
// to the ciphertext: both ends seal independently, a counter would have to
// survive reconnects, and the birthday bound is far beyond this channel's
// traffic.

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

// nonceLen is AES-GCM's standard nonce size.
const nonceLen = 12

// aead builds the cipher for one key and rejects a key of the wrong length
// instead of producing frames nothing can open.
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

// seal encrypts plaintext under key and binds it to aad, the frame's clear
// routing fields. A relay that delivers the frame to another instance or
// replays one request's answer as another's makes the tag fail on open.
func seal(key []byte, aad string, plaintext []byte) ([]byte, error) {
	gcm, err := aead(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("relay: no randomness for a frame nonce: %w", err)
	}
	// Seal appends to its first argument, giving nonce||ciphertext in one
	// allocation.
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
