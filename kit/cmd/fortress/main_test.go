package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/junkerderprovinz/parleyport/kit/fortress"
	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/phrase"
	"github.com/junkerderprovinz/parleyport/kit/relay"
	"github.com/junkerderprovinz/parleyport/kit/status"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

var secret = []byte("0123456789abcdef")

type memStore struct {
	mu   sync.Mutex
	data []byte
}

func (s *memStore) Load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.data), nil
}

func (s *memStore) Save(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = bytes.Clone(b)
	return nil
}

type source struct{}

func (source) Report(context.Context, string) (status.Report, error) {
	return status.Report{
		App:   status.App{ID: "alpha", Name: "Alpha", Version: "2.0.0"},
		State: status.StateOK,
		Work:  []status.Task{{ID: "run-1", Kind: status.KindBackup, Title: "Everything", BlocksRestart: true}},
	}, nil
}

func (source) Log(context.Context, status.LogQuery) (status.LogPage, error) {
	return status.LogPage{}, nil
}

// app is an instance of the app "alpha" in the fortress, which offers the
// action "files.drop" and records who ran it.
type app struct {
	f  *fortress.Fortress
	id string

	mu    sync.Mutex
	drops []string
}

func openApp(t *testing.T, url string) *app {
	t.Helper()
	seed := sha256.Sum256([]byte("alpha-1"))
	id, err := member.FromSeed(member.KindInstance, seed[:])
	if err != nil {
		t.Fatal(err)
	}
	a := &app{id: id.ID()}
	f, err := fortress.Open(fortress.Config{
		App:      fortress.App{ID: "alpha", Name: "Alpha", Version: "2.0.0"},
		Secret:   secret,
		Identity: id,
		Self:     group.Self{Name: "tower", Deployment: "container"},
		Relay:    group.RelayOwn,
		RelayURL: url,
		Store:    &memStore{},
		Status:   source{},
		Actions: []fortress.Action{{Name: "files.drop", Run: func(_ context.Context, from fortress.Caller, body []byte) ([]byte, error) {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.drops = append(a.drops, from.App+":"+string(body))
			return []byte(`{"ok":true}`), nil
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	a.f = f
	return a
}

func (a *app) dropped() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.drops)
}

func relayServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(relay.New())
	t.Cleanup(srv.CloseClientConnections)
	t.Cleanup(srv.Close)
	return srv.URL
}

// cli runs the command with args and words on standard input.
func cli(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestAPluginJoinsReadsAndActs(t *testing.T) {
	url := relayServer(t)
	a := openApp(t, url)
	dir := t.TempDir()
	words, err := phrase.Encode(secret)
	if err != nil {
		t.Fatal(err)
	}

	if code, _, stderr := cli(t, words+"\n", "join", "-dir", dir, "-app", "watcher", "-name", "tower", "-relay", url, "-uses", "files.drop"); code != 0 {
		t.Fatalf("join: %d %s", code, stderr)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, configFile))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("the file with the secret is %v %v, want 0600", info.Mode(), err)
		}
	}

	// The plugin shows up at the app, which approves it, and the plugin
	// approves the app.
	code, out, stderr := cli(t, "", "members", "-dir", dir, "-json", "-wait", "3s")
	if code != 0 {
		t.Fatalf("members: %d %s", code, stderr)
	}
	var listed []memberOut
	if err := json.Unmarshal([]byte(out), &listed); err != nil || len(listed) != 1 || listed[0].ID != a.id {
		t.Fatalf("members lists %s %v, want alpha-1", out, err)
	}
	var plugin string
	waitFor(t, "the plugin to ask the app", func() bool {
		for _, m := range a.f.Members() {
			if m.State == group.StatePending {
				plugin = m.ID
			}
		}
		return plugin != ""
	})
	if err := a.f.Approve(plugin); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := cli(t, "", "approve", "-dir", dir, "-wait", "10s", a.id); code != 0 {
		t.Fatalf("approve: %d %s", code, stderr)
	}

	code, out, stderr = cli(t, "", "status", "-dir", dir, "-json", "-wait", "10s")
	if code != 0 {
		t.Fatalf("status: %d %s", code, stderr)
	}
	var reports []statusOut
	if err := json.Unmarshal([]byte(out), &reports); err != nil || len(reports) != 1 || reports[0].Report == nil ||
		len(reports[0].Report.Work) != 1 || !reports[0].Report.Work[0].BlocksRestart || reports[0].App.ID != "alpha" {
		t.Fatalf("status gives %s %v", out, err)
	}

	code, out, stderr = cli(t, "", "act", "-dir", dir, "-wait", "10s", "alpha", "files.drop", `"report.pdf"`)
	if code != 0 || strings.TrimSpace(out) != `{"ok":true}` {
		t.Fatalf("act: %d %q %s", code, out, stderr)
	}
	if got := a.dropped(); !slices.Equal(got, []string{`watcher:"report.pdf"`}) {
		t.Errorf("the app ran %v", got)
	}

	if err := a.f.SetPermission("watcher", "alpha", "files.drop", false); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = cli(t, "", "act", "-dir", dir, "-wait", "10s", a.id, "files.drop", `"again"`)
	if code != 1 || !strings.Contains(stderr, "switched off") {
		t.Errorf("act with the permission off: %d %s", code, stderr)
	}
}

func TestUsage(t *testing.T) {
	dir := t.TempDir()
	for name, args := range map[string][]string{
		"nothing":          nil,
		"an unknown verb":  {"dance"},
		"no dir":           {"members"},
		"act without all":  {"act", "-dir", dir, "alpha"},
		"join without app": {"join", "-dir", dir, "-name", "tower"},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, _ := cli(t, "", args...); code != 2 {
				t.Errorf("exit %d, want 2", code)
			}
		})
	}
	if code, _, stderr := cli(t, "not twelve words\n", "join", "-dir", dir, "-app", "watcher", "-name", "tower"); code != 1 || stderr == "" {
		t.Errorf("join with a broken phrase: %d %q", code, stderr)
	}
	if code, _, stderr := cli(t, "", "members", "-dir", dir); code != 1 || !strings.Contains(stderr, "join") {
		t.Errorf("members before joining: %d %q", code, stderr)
	}
}
