package fortress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/group"
)

// restoring is an app that takes its backup back: it keeps one only after
// reading the whole of it, and refuses with refuse if that is set.
type restoring struct {
	refuse string

	asked  atomic.Int32
	mu     sync.Mutex
	kept   [][]byte
	from   []Caller
	failed []error
}

func (r *restoring) take(_ context.Context, from Caller, backup io.Reader, n int64) error {
	r.asked.Add(1)
	if r.refuse != "" {
		return &Refusal{Code: r.refuse}
	}
	got, err := io.ReadAll(backup)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.failed = append(r.failed, err)
		return err
	}
	if int64(len(got)) != n {
		r.failed = append(r.failed, errors.New("length differs"))
		return errors.New("length differs")
	}
	r.kept = append(r.kept, got)
	r.from = append(r.from, from)
	return nil
}

func (r *restoring) state() (kept [][]byte, failed []error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.kept, r.failed
}

func handBack(t *testing.T, from, to *node, data []byte) error {
	t.Helper()
	return from.f.Import(ctx(t), to.id, bytes.NewReader(data), int64(len(data)))
}

func importPermission(f *Fortress, from, to string) (Permission, bool) {
	for _, p := range f.Permissions() {
		if p.From == from && p.To == to && p.Action == ImportAction {
			return p, true
		}
	}
	return Permission{}, false
}

func TestABackupIsHandedBackOnTheNetworkOnceSwitchedOn(t *testing.T) {
	r := &restoring{}
	a, b := onOneNetwork(t, setup{uses: []string{ImportAction}}, setup{importer: r.take}, unchanged)
	data := backupOf(9<<20 + 777)

	if err := handBack(t, a, b, data); !errors.Is(err, ErrPermissionOff) {
		t.Fatalf("an import nobody switched on: %v, want ErrPermissionOff", err)
	}
	if n := r.asked.Load(); n != 0 {
		t.Errorf("bravo's app was asked %d times without the permission", n)
	}
	waitFor(t, "bravo to know alpha's uses", func() bool { _, ok := importPermission(b.f, "alpha", "bravo"); return ok })
	if p, _ := importPermission(b.f, "alpha", "bravo"); p.On {
		t.Errorf("the import permission starts as %+v, want off", p)
	}

	if err := b.f.SetPermission("alpha", "bravo", ImportAction, true); err != nil {
		t.Fatal(err)
	}
	if err := handBack(t, a, b, data); err != nil {
		t.Fatalf("alpha hands bravo its backup: %v", err)
	}
	kept, _ := r.state()
	if len(kept) != 1 || !bytes.Equal(kept[0], data) {
		t.Fatalf("bravo kept %d backups", len(kept))
	}
	if from := r.from[0]; from.ID != a.id || from.App != "alpha" || from.Device != "alpha-1" {
		t.Errorf("the import ran for %+v", from)
	}
}

func TestAnImportGoesOnlyOnTheNetwork(t *testing.T) {
	url := relayServer(t)
	r := &restoring{}
	a := open(t, "alpha", "alpha-1", setup{relay: url, uses: []string{ImportAction}})
	b := open(t, "bravo", "bravo-1", setup{relay: url, noListener: true, importer: r.take})
	waitFor(t, "both on the relay", func() bool { return len(a.f.Members()) == 1 && len(b.f.Members()) == 1 })
	meet(t, a, b)
	if err := b.f.SetPermission("alpha", "bravo", ImportAction, true); err != nil {
		t.Fatal(err)
	}
	if err := handBack(t, a, b, backupOf(1000)); !errors.Is(err, group.ErrNotDirect) {
		t.Errorf("an import through the relay: %v, want group.ErrNotDirect", err)
	}
	if n := r.asked.Load(); n != 0 {
		t.Errorf("bravo's app was asked %d times through the relay", n)
	}
}

// damagingImport is a proxy in front of a member that hands on every call but
// passes the body of an upload through damage.
func damagingImport(t *testing.T, damage func([]byte) []byte) func(string) string {
	return func(target string) string {
		u, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		proxy := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			r := pr.Out
			if r.Header.Get("Content-Type") != "application/x-kit-upload" {
				return
			}
			raw, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			raw = damage(raw)
			r.Body = io.NopCloser(bytes.NewReader(raw))
			r.ContentLength = int64(len(raw))
			r.TransferEncoding = nil
			r.Header.Set("Content-Length", strconv.Itoa(len(raw)))
		}}
		srv := httptest.NewServer(proxy)
		t.Cleanup(srv.Close)
		return srv.URL
	}
}

func TestADamagedImportFailsBeforeTheAppTakesIt(t *testing.T) {
	for name, damage := range map[string]func([]byte) []byte{
		"a flipped bit": func(b []byte) []byte {
			b[len(b)/2] ^= 0x01
			return b
		},
		"cut short": func(b []byte) []byte { return b[:len(b)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			r := &restoring{}
			a, b := onOneNetwork(t, setup{uses: []string{ImportAction}}, setup{importer: r.take}, damagingImport(t, damage))
			if err := b.f.SetPermission("alpha", "bravo", ImportAction, true); err != nil {
				t.Fatal(err)
			}
			if err := handBack(t, a, b, backupOf(1<<20)); !errors.Is(err, group.ErrStreamBroken) {
				t.Errorf("a damaged import: %v, want group.ErrStreamBroken", err)
			}
			kept, failed := r.state()
			if len(kept) != 0 || len(failed) != 1 || !errors.Is(failed[0], group.ErrStreamBroken) {
				t.Errorf("bravo kept %d, failed with %v", len(kept), failed)
			}
		})
	}
}

func TestAnImportRefusalComesBackWithTheAppsCode(t *testing.T) {
	r := &restoring{refuse: "version_too_new"}
	a, b := onOneNetwork(t, setup{uses: []string{ImportAction}}, setup{importer: r.take}, unchanged)
	if err := b.f.SetPermission("alpha", "bravo", ImportAction, true); err != nil {
		t.Fatal(err)
	}
	if err := handBack(t, a, b, backupOf(9<<20)); refusalCode(err) != "version_too_new" {
		t.Errorf("a refused import: %v, want version_too_new", err)
	}
}

func TestAnAppWithoutImportTakesNone(t *testing.T) {
	a, b := onOneNetwork(t, setup{uses: []string{ImportAction}}, setup{}, unchanged)
	if err := handBack(t, a, b, []byte("x")); !errors.Is(err, ErrNoSuchAction) {
		t.Errorf("an import to an app that takes none: %v, want ErrNoSuchAction", err)
	}
	if _, err := a.f.Act(ctx(t), b.id, ImportAction, nil); !errors.Is(err, ErrNoSuchAction) {
		t.Errorf("backup.import as an ordinary action: %v, want ErrNoSuchAction", err)
	}
	cfg := config(t, &node{name: "charlie-1", app: "charlie", store: &memStore{}, pairStore: &memStore{}}, setup{noPair: true})
	cfg.Actions = append(cfg.Actions, Action{Name: ImportAction, Run: func(context.Context, Caller, []byte) ([]byte, error) { return nil, nil }})
	if f, err := Open(cfg); err == nil {
		_ = f.Close()
		t.Error("backup.import was taken as an ordinary action")
	}
}
