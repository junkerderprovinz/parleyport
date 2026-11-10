package fortress

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/group"
)

func TestAMembershipJoinedInADirectoryOpensFromIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fortress")
	m := Membership{App: "alpha", Device: "cellar", Relay: "off", Uses: []string{"files.drop"}}
	if err := Join(dir, testSecret, m); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := Domain.Keys(testSecret)
	if cfg.App.ID != "alpha" || cfg.Self.Name != "cellar" || cfg.Self.Deployment != "plugin" || cfg.Relay != group.RelayOff ||
		cfg.LAN != nil || !slices.Equal(cfg.Uses, m.Uses) || len(cfg.Secret) != 0 ||
		cfg.Keys.Group != want.Group || !bytes.Equal(cfg.Keys.Frame, want.Frame) || !bytes.Equal(cfg.Keys.PeerAuth, want.PeerAuth) {
		t.Errorf("Load = %+v", cfg)
	}
	again, err := Load(dir)
	if err != nil || again.Identity.ID() != cfg.Identity.ID() {
		t.Errorf("a second Load is %s, %v, want the same member %s", again.Identity.ID(), err, cfg.Identity.ID())
	}
	f, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Store.Save([]byte("{}")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err != nil {
		t.Errorf("the fortress keeps its state elsewhere than next to the membership: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "fortress.json")) //nolint:gosec // G304: a directory of the test
	if err != nil || bytes.Contains(raw, []byte(hex.EncodeToString(testSecret))) || bytes.Contains(raw, testSecret) {
		t.Errorf("the membership keeps the secret: %s %v", raw, err)
	}
}

func TestAMembershipNamesItsRelayAndNetwork(t *testing.T) {
	for _, c := range []struct {
		relay string
		mode  group.RelayMode
		url   string
	}{
		{"", group.RelayProject, ""},
		{"off", group.RelayOff, ""},
		{"https://relay.example", group.RelayOwn, "https://relay.example"},
	} {
		dir := t.TempDir()
		if err := Join(dir, testSecret, Membership{App: "alpha", Device: "cellar", Relay: c.relay, LAN: true}); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Relay != c.mode || cfg.RelayURL != c.url || cfg.LAN == nil {
			t.Errorf("relay %q loads as %q %q, LAN %v", c.relay, cfg.Relay, cfg.RelayURL, cfg.LAN)
		}
		_ = cfg.LAN.Close()
	}
}

func TestLoadingWhereNobodyJoinedSaysSo(t *testing.T) {
	if _, err := Load(t.TempDir()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Load of an empty directory: %v, want fs.ErrNotExist", err)
	}
}

func TestADamagedMembershipDoesNotLoad(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fortress.json"), []byte(`{"app":"alpha","seed":"zz"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Load of a damaged membership: %v", err)
	}
}

func TestJoinRefusesAnAppItCannotOpen(t *testing.T) {
	dir := t.TempDir()
	if err := Join(dir, testSecret, Membership{App: "Not An App", Device: "cellar"}); err == nil {
		t.Error("Join took an app id that Open refuses")
	}
	if _, err := os.Stat(filepath.Join(dir, "fortress.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused Join left a membership behind: %v", err)
	}
}
