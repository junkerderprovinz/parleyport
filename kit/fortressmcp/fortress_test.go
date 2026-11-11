package fortressmcp_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/fortress"
	"github.com/junkerderprovinz/parleyport/kit/fortressmcp"
	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
	"github.com/junkerderprovinz/parleyport/kit/status"
)

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

type report struct{ app string }

func (r report) Report(context.Context, string) (status.Report, error) {
	return status.Report{App: status.App{ID: r.app, Name: r.app, Version: "1.0.0"}, State: status.StateOK}, nil
}

func (r report) Log(context.Context, status.LogQuery) (status.LogPage, error) {
	return status.LogPage{Entries: []status.LogEntry{{ID: "1", At: time.Now().UTC(), Level: status.SeverityInfo, Code: "ran", Text: r.app + " ran"}}, Next: "1"}, nil
}

func join(t *testing.T, relayURL, app, device string, actions []fortress.Action, uses []string) *fortress.Fortress {
	t.Helper()
	seed := sha256.Sum256([]byte(device))
	id, err := member.FromSeed(member.KindInstance, seed[:])
	if err != nil {
		t.Fatal(err)
	}
	f, err := fortress.Open(fortress.Config{
		App:      fortress.App{ID: app, Name: app, Version: "1.0.0"},
		Secret:   []byte("0123456789abcdef"),
		Identity: id,
		Self:     group.Self{Name: device, Deployment: "container"},
		Relay:    group.RelayOwn,
		RelayURL: relayURL,
		Store:    &memStore{},
		Status:   report{app: app},
		Actions:  actions,
		Uses:     uses,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestAToolRunsAtAnotherAppThroughTheFortress(t *testing.T) {
	srv := httptest.NewServer(relay.New())
	t.Cleanup(srv.Close)
	t.Cleanup(srv.CloseClientConnections)
	files := join(t, srv.URL, "files", "Tower", []fortress.Action{fortressmcp.Offer(target(), []string{"drop"}, enter)}, nil)
	notes := join(t, srv.URL, "notes", "Desk", nil, []string{fortressmcp.ActAction})
	deadline := time.Now().Add(15 * time.Second)
	for {
		ms := notes.Members()
		if len(ms) == 1 && ms[0].App.ID == "files" && slices.Contains(ms[0].Actions, fortressmcp.ActAction) && ms[0].Online() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("notes never saw files offer its tools: %+v", ms)
		}
		time.Sleep(20 * time.Millisecond)
	}
	h := connect(t, notes, true)

	var got struct{ Dropped, For string }
	decode(t, h.call(t, "files_drop", map[string]any{"path": "notes.txt"}), &got)
	if got.Dropped != "notes.txt" || got.For != "notes@Desk" {
		t.Errorf("files_drop answered %+v", got)
	}
	var st struct {
		Members []struct {
			App    string
			Report struct{ State string }
		}
	}
	decode(t, h.call(t, "fortress_status", nil), &st)
	if len(st.Members) != 1 || st.Members[0].App != "files" || st.Members[0].Report.State != "ok" {
		t.Errorf("fortress_status reads %+v", st)
	}

	if err := files.SetPermission("notes", "files", fortressmcp.ActAction, false); err != nil {
		t.Fatal(err)
	}
	if code := errorCode(t, h.call(t, "files_drop", map[string]any{"path": "a"})); code != "permission_off" {
		t.Errorf("a call with the permission off at files: %q, want permission_off", code)
	}
}
