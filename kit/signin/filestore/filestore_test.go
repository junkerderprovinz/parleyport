package filestore_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/filestore"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

func sealer(t testing.TB, b byte) signin.Sealer {
	t.Helper()
	s, err := signin.NewSealer(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStoreContract(t *testing.T) {
	signintest.Store(t, func(t testing.TB) func() signin.Store {
		path := filepath.Join(t.TempDir(), "signin.json")
		seal := sealer(t, 1)
		return func() signin.Store {
			s, err := filestore.Open(path, seal)
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
	})
}

func TestTheFileHoldsNoPlainData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signin.json")
	s, err := filestore.Open(path, sealer(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(context.Background(), signin.Doc{Kind: "account", ID: "owner", Data: []byte(`{"name":"visible"}`)}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("visible")) || bytes.Contains(raw, []byte("owner")) {
		t.Fatal("the file shows what it holds")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", info.Mode().Perm())
		}
	}
}

func TestOpenFailsOnAFileItCannotOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signin.json")
	s, _ := filestore.Open(path, sealer(t, 1))
	if err := s.Apply(context.Background(), signin.Doc{Kind: "k", ID: "1", Data: []byte(`1`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := filestore.Open(path, sealer(t, 2)); err == nil {
		t.Fatal("a file sealed under another key opened as an empty store")
	}
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := filestore.Open(path, sealer(t, 1)); err == nil {
		t.Fatal("a broken file opened as an empty store")
	}
}

func TestOpenRefusesAFileAboveTheLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signin.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(17 << 20); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := filestore.Open(path, sealer(t, 1)); err == nil {
		t.Fatal("a 17 MiB file opened")
	}
}
