package relay

import (
	"encoding/hex"
	"strings"
	"testing"
)

// If the relay key equalled the secret, the relay operator could reconstruct
// anyone's phrase.
func TestDeriveKeyIsNotTheSecret(t *testing.T) {
	secret := []byte("0123456789abcdef")
	key := DeriveKey(secret)
	if strings.Contains(key, hex.EncodeToString(secret)) {
		t.Fatal("the derived key contains the secret verbatim")
	}
	if key == string(secret) {
		t.Fatal("the derived key equals the secret")
	}
}

// Two instances given the same phrase have to land in the same group on every
// machine and every run.
func TestDeriveKeyIsDeterministic(t *testing.T) {
	secret := []byte("0123456789abcdef")
	first := DeriveKey(secret)
	for i := 0; i < 100; i++ {
		if again := DeriveKey(secret); again != first {
			t.Fatalf("DeriveKey is not deterministic: %q then %q", first, again)
		}
	}
}

func TestDeriveKeyDiffersPerSecret(t *testing.T) {
	a := DeriveKey([]byte("0123456789abcdef"))
	b := DeriveKey([]byte("0123456789abcdeg")) // one byte apart
	if a == b {
		t.Fatal("two different secrets derived the same relay key")
	}
}

// The relay refuses keys below minKeyLength.
func TestDeriveKeyClearsTheRelayMinimum(t *testing.T) {
	key := DeriveKey([]byte("0123456789abcdef"))
	if len(key) < minKeyLength {
		t.Fatalf("derived key is %d characters, relay requires at least %d", len(key), minKeyLength)
	}
	if len(key) != 64 {
		t.Fatalf("derived key is %d characters, expected 64 (hex of SHA-256)", len(key))
	}
	if _, err := hex.DecodeString(key); err != nil {
		t.Fatalf("derived key is not valid hex: %v", err)
	}
}

// Pinned values catch a change to keyDomain or the hash, which would stay
// self-consistent while orphaning every existing phrase; a phrase is not
// stored anywhere to be re-derived. The phone's port
// (mobile/src/api/seedphrase.ts) is checked against the same vectors.
func TestDeriveKeyMatchesItsPinnedVectors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		secret []byte
		want   string
	}{
		{
			name:   "the all-zero secret",
			secret: make([]byte, 16),
			want:   "293fa85653adb9e7195717c1a6f34e3f433f0a610cd247bb9ff73b8642e7fc15",
		},
		{
			// Every byte different, so a dropped or reordered part of the
			// secret shows up instead of cancelling out.
			name:   "a walk over the byte range",
			secret: []byte{0x00, 0x07, 0x0e, 0x15, 0x1c, 0x23, 0x2a, 0x31, 0x38, 0x3f, 0x46, 0x4d, 0x54, 0x5b, 0x62, 0x69},
			want:   "57d28da6bdc93397c9a3a8355b9c3e322a7e134b9985ae7e76c3667d240b5b52",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeriveKey(tc.secret); got != tc.want {
				t.Fatalf("DeriveKey = %s, want %s; a changed derivation breaks every existing phrase", got, tc.want)
			}
		})
	}
}
