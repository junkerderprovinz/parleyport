package fortress

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// viewer is a member that only reads, such as a tile, on the relay.
type viewer struct {
	id     member.Identity
	client *relay.Client
}

func openViewer(t *testing.T, url string) *viewer {
	t.Helper()
	id, err := member.FromSeed(member.KindViewer, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	c, err := relay.NewClient(relay.ClientOptions{
		URL:      url,
		Key:      Domain.GroupKey(testSecret),
		FrameKey: Domain.FrameKey(testSecret),
		Signing:  Domain.Signing(),
		Self:     relay.Announce{Name: "tile", Deployment: string(member.KindViewer), Client: true, Member: id.ID()},
		Identity: &id,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Start()
	t.Cleanup(func() { _ = c.Close() })
	return &viewer{id: id, client: c}
}

func (v *viewer) call(t *testing.T, target, method, path string, body []byte) (int, []byte) {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, status, err := v.client.Proxy(c, target, method, path, body)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return status, out
}

func TestAViewerOnlyReads(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	v := openViewer(t, url)
	waitFor(t, "the viewer on the relay", func() bool { return v.client.Connected() && len(v.client.Siblings()) > 0 })

	v.call(t, a.id, http.MethodGet, aboutPath, nil)
	if m, _ := memberOf(a.f, v.id.ID()); m.Kind != member.KindViewer || m.State != group.StateApproved {
		t.Errorf("alpha lists the viewer as %+v, want a member", m)
	}

	if status, _ := v.call(t, a.id, http.MethodGet, "/api/fortress/v1/status", nil); status != http.StatusOK {
		t.Errorf("the viewer reads the status: %d", status)
	}
	if status, _ := v.call(t, a.id, http.MethodGet, permissionsPath, nil); status != http.StatusOK {
		t.Errorf("the viewer reads the permissions: %d", status)
	}
	if status, body := v.call(t, a.id, http.MethodPost, actPrefix+"files.drop", []byte(`"x"`)); status != http.StatusForbidden || len(a.drops()) > 0 {
		t.Errorf("the viewer acts: %d %s, ran %v", status, body, a.drops())
	}
	sw := []byte(`{"from":"alpha","to":"alpha","action":"files.drop","on":false,"at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","by":"` + v.id.ID() + `"}`)
	if status, _ := v.call(t, a.id, http.MethodPost, permissionsPath, sw); status != http.StatusForbidden {
		t.Errorf("the viewer switches a permission: %d", status)
	}
	if !on(a.f.Permissions(), "alpha", "alpha", "files.drop") {
		t.Error("a viewer switched a permission off")
	}
	for _, p := range a.f.Permissions() {
		if p.From == "" || p.To == "" {
			t.Errorf("the viewer shows up in a permission: %+v", p)
		}
	}
}
