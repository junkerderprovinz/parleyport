package fortress

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/status"
)

func TestMembersReadEachOthersStatusAndLog(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "bravo", "bravo-1")
	a, b := n[0], n[1]
	meet(t, a, b)
	if err := b.f.SetPermission("alpha", "bravo", "files.drop", false); err != nil {
		t.Fatal(err)
	}

	report, err := a.f.Status(ctx(t), b.id, "de")
	if err != nil {
		t.Fatal(err)
	}
	if report.App.ID != "bravo" || report.Instance.Name != "bravo-1" || report.State != status.StateWarning ||
		len(report.NeedsYou) != 1 || report.NeedsYou[0].Text != "Die Kopie ist alt." {
		t.Errorf("alpha reads bravo's status as %+v", report)
	}
	page, err := a.f.Log(ctx(t), b.id, status.LogQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 1 || page.Entries[0].Text != "bravo ran" || page.Next != "1" {
		t.Errorf("alpha reads bravo's log as %+v", page)
	}
}

func TestAMemberWithoutAStatusSaysSo(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := &node{name: "bravo-1", app: "bravo", id: identity(t, "bravo-1").ID(), store: &memStore{}, pairStore: &memStore{}}
	cfg := config(t, b, setup{relay: url})
	cfg.Status = nil
	f, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	b.f = f
	waitFor(t, "both on the relay", func() bool { return len(a.f.Members()) == 1 && len(b.f.Members()) == 1 })
	meet(t, a, b)
	if _, err := a.f.Status(ctx(t), b.id, ""); refusalCode(err) != "not_found" {
		t.Errorf("reading the status of an app without one: %v, want not_found", err)
	}
}

func TestAnActionRunsAtAnotherApp(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "bravo", "bravo-1")
	a, b := n[0], n[1]
	meet(t, a, b)

	out, err := a.f.Act(ctx(t), b.id, "files.drop", []byte(`"report.pdf"`))
	if err != nil || string(out) != `{"ok":true}` {
		t.Fatalf("alpha drops a file at bravo: %s %v", out, err)
	}
	if got := b.drops(); !slices.Equal(got, []string{`alpha:"report.pdf"`}) {
		t.Errorf("bravo ran %v, want the drop from alpha", got)
	}
}

func TestAnActionTheAppDoesNotOfferIsRefused(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "bravo", "bravo-1")
	a, b := n[0], n[1]
	meet(t, a, b)
	if _, err := a.f.Act(ctx(t), b.id, "jobs.run", nil); !errors.Is(err, ErrNoSuchAction) {
		t.Errorf("an action bravo does not offer: %v, want ErrNoSuchAction", err)
	}
}

func TestAnActionPassesOnTheAppsRefusal(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "bravo", "bravo-1")
	a, b := n[0], n[1]
	meet(t, a, b)
	if _, err := a.f.Act(ctx(t), b.id, "files.drop", []byte(`"full"`)); refusalCode(err) != "disk_full" {
		t.Errorf("a drop on a full disk: %v, want disk_full", err)
	}
}

func TestASwitchedOffPermissionRefusesTheAction(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "bravo", "bravo-1", "charlie", "charlie-1")
	a, b, c := n[0], n[1], n[2]
	meet(t, a, b)
	meet(t, a, c)
	meet(t, b, c)

	// The owner switches it off in a third app; bravo, where the drop would
	// run, hears of it.
	if err := c.f.SetPermission("alpha", "bravo", "files.drop", false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bravo to hear the switch", func() bool { return !on(b.f.Permissions(), "alpha", "bravo", "files.drop") })
	if _, err := a.f.Act(ctx(t), b.id, "files.drop", []byte(`"x"`)); !errors.Is(err, ErrPermissionOff) {
		t.Errorf("alpha drops at bravo: %v, want ErrPermissionOff", err)
	}
	if _, err := c.f.Act(ctx(t), b.id, "files.drop", []byte(`"y"`)); err != nil {
		t.Errorf("charlie's own permission is still on: %v", err)
	}
	if got := b.drops(); !slices.Equal(got, []string{`charlie:"y"`}) {
		t.Errorf("bravo ran %v, want charlie's drop alone", got)
	}

	if err := a.f.SetPermission("alpha", "bravo", "files.drop", true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bravo to hear it is on again", func() bool { return on(b.f.Permissions(), "alpha", "bravo", "files.drop") })
	if _, err := a.f.Act(ctx(t), b.id, "files.drop", []byte(`"z"`)); err != nil {
		t.Errorf("alpha drops after the switch is on again: %v", err)
	}
}

func TestManyActionsAtOnce(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "bravo", "bravo-1")
	a, b := n[0], n[1]
	meet(t, a, b)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := a.f.Act(ctx(t), b.id, "files.drop", []byte(`"x"`)); err != nil {
				t.Error(err)
			}
		})
		wg.Go(func() { _ = b.f.SetPermission("charlie", "bravo", "files.drop", false) })
		wg.Go(func() { _ = a.f.Members(); _ = a.f.Permissions() })
	}
	wg.Wait()
	if got := len(b.drops()); got != 8 {
		t.Errorf("bravo ran %d drops, want 8", got)
	}
}

func TestAnActionsRefusalKeepsItsStatus(t *testing.T) {
	url := relayServer(t)
	lookup := Action{Name: "containers.find", Run: func(_ context.Context, _ Caller, body []byte) ([]byte, error) {
		if string(body) == `"gone"` {
			return nil, &Refusal{Status: http.StatusNotFound, Code: "unknown_container"}
		}
		return nil, &Refusal{Code: "busy"}
	}}
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url, actions: []Action{lookup}})
	waitFor(t, "both on the relay", func() bool { return len(a.f.Members()) == 1 && len(b.f.Members()) == 1 })
	meet(t, a, b)

	for body, want := range map[string]Refusal{
		`"gone"`: {Status: http.StatusNotFound, Code: "unknown_container"},
		`"x"`:    {Status: http.StatusConflict, Code: "busy"},
	} {
		_, err := a.f.Act(ctx(t), b.id, lookup.Name, []byte(body))
		var got *Refusal
		if !errors.As(err, &got) || *got != want {
			t.Errorf("the action refusing %s arrives as %v, want %+v", body, err, want)
		}
	}
}
