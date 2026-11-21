package signin_test

import (
	"bytes"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/signin"
)

func testKey() []byte { return bytes.Repeat([]byte{7}, 32) }

func TestNewSealerOpensWhatItSealed(t *testing.T) {
	s, err := signin.NewSealer(testKey())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal("alpha/signin/totp/v1|1", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("secret")) {
		t.Fatal("the sealed value holds the plain text")
	}
	plain, err := s.Open("alpha/signin/totp/v1|1", sealed)
	if err != nil || string(plain) != "secret" {
		t.Fatalf("Open = %q, %v", plain, err)
	}
}

func TestNewSealerBindsTheDomain(t *testing.T) {
	s, _ := signin.NewSealer(testKey())
	sealed, _ := s.Seal("alpha/signin/totp/v1|1", []byte("secret"))
	if _, err := s.Open("alpha/signin/totp/v1|2", sealed); err == nil {
		t.Fatal("a value sealed for one account opens for another")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := s.Open("alpha/signin/totp/v1|1", sealed); err == nil {
		t.Fatal("a changed value opens")
	}
	other, _ := signin.NewSealer(bytes.Repeat([]byte{8}, 32))
	sealed2, _ := s.Seal("d", []byte("x"))
	if _, err := other.Open("d", sealed2); err == nil {
		t.Fatal("a value opens under another key")
	}
}

func TestNewSealerMACsPerDomain(t *testing.T) {
	s, _ := signin.NewSealer(testKey())
	a := s.MAC("alpha/x", []byte("data"))
	if len(a) != 32 || !bytes.Equal(a, s.MAC("alpha/x", []byte("data"))) {
		t.Fatal("MAC is not a stable 32-byte value")
	}
	if bytes.Equal(a, s.MAC("alpha/y", []byte("data"))) {
		t.Fatal("two domains give the same MAC")
	}
	// The domain and the data are kept apart, so moving bytes from one to
	// the other changes the MAC.
	if bytes.Equal(s.MAC("ab", []byte("c")), s.MAC("a", []byte("bc"))) {
		t.Fatal("domain and data run together")
	}
}

func TestNewSealerRefusesAShortKey(t *testing.T) {
	if _, err := signin.NewSealer(make([]byte, 16)); err == nil {
		t.Fatal("a 16-byte key accepted")
	}
}

func TestAnotherSealKeyStopsTheStart(t *testing.T) {
	a := newApp(t)
	a.owner()
	other, _ := signin.NewSealer(bytes.Repeat([]byte{8}, 32))
	a.cfg.Seal = other
	if _, err := signin.Open(a.cfg); err == nil {
		t.Fatal("Open went on with another seal key")
	}
}
