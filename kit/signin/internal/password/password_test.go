package password_test

import (
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/signin/internal/password"
)

func TestHashChecks(t *testing.T) {
	h, err := password.Hash([]byte("input"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash %q is not in the encoded argon2id form", h)
	}
	ok, err := password.Check(h, []byte("input"))
	if err != nil || !ok {
		t.Fatalf("Check(right) = %v, %v", ok, err)
	}
	ok, err = password.Check(h, []byte("other"))
	if err != nil || ok {
		t.Fatalf("Check(wrong) = %v, %v", ok, err)
	}
}

func TestHashSaltsEveryCall(t *testing.T) {
	a, _ := password.Hash([]byte("input"))
	b, _ := password.Hash([]byte("input"))
	if a == b {
		t.Fatal("two hashes of the same input are equal")
	}
}

func TestCheckRefusesParametersAboveTheLimit(t *testing.T) {
	tests := []struct {
		name string
		hash string
	}{
		{"too much memory", "$argon2id$v=19$m=1048576,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"},
		{"too many passes", "$argon2id$v=19$m=19456,t=40,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"},
		{"too many lanes", "$argon2id$v=19$m=19456,t=2,p=64$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"},
		{"other version", "$argon2id$v=16$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"},
		{"argon2i", "$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"},
		{"no salt", "$argon2id$v=19$m=19456,t=2,p=1$$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"},
		{"garbage", "bcrypt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := password.Check(tt.hash, []byte("input"))
			if err == nil || ok {
				t.Fatalf("Check = %v, %v, want an error", ok, err)
			}
		})
	}
}

func TestCurrentTellsTheKitsParametersFromOthers(t *testing.T) {
	h, _ := password.Hash([]byte("input"))
	if !password.Current(h) {
		t.Fatal("a fresh hash is not current")
	}
	weaker := strings.Replace(h, "t=2", "t=1", 1)
	if password.Current(weaker) {
		t.Fatal("a hash with other parameters counts as current")
	}
}
