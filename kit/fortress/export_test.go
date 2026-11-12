package fortress

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/lan"
)

// tagged is p as a member of the test fortress announces it now, tagged the
// way the group checks it.
func tagged(p lan.Peer) lan.Peer {
	p.Sent = time.Now().Unix()
	mac := hmac.New(sha256.New, Domain.Keys(testSecret).PeerAuth)
	mac.Write([]byte("announce\x00" + p.ID + "\x00" + p.URL + "\x00" + p.Name + "\x00" + p.Deployment + "\x00" + p.Address + "\x00" + strconv.FormatInt(p.Sent, 10)))
	p.Tag = hex.EncodeToString(mac.Sum(nil))
	return p
}

// onOneNetwork opens alpha-1 and bravo-1 as two instances on one network,
// each handed the other's announce. Alpha reaches bravo at via(bravo's
// address).
func onOneNetwork(t *testing.T, sa, sb setup, via func(string) string) (a, b *node) {
	t.Helper()
	la, lb := lan.New(lan.Config{}), lan.New(lan.Config{})
	t.Cleanup(func() { _ = la.Close(); _ = lb.Close() })
	sa.lan, sb.lan, sa.noPair, sb.noPair = la, lb, true, true
	a = open(t, "alpha", "alpha-1", sa)
	b = open(t, "bravo", "bravo-1", sb)
	la.Observe(tagged(lan.Peer{ID: b.id, Name: b.name, URL: via(b.srv.URL), Deployment: "container"}))
	lb.Observe(tagged(lan.Peer{ID: a.id, Name: a.name, URL: a.srv.URL, Deployment: "container"}))
	meet(t, a, b)
	return a, b
}

func unchanged(u string) string { return u }

// backupOf is the n bytes the test app exports.
func backupOf(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.NewChaCha8([32]byte{7}).Read(b)
	return b
}

// exporting is an app that exports a backup of size bytes and counts how
// often it did.
func exporting(size int, count *atomic.Int32) func(context.Context, Caller) (io.ReadCloser, int64, error) {
	return func(context.Context, Caller) (io.ReadCloser, int64, error) {
		count.Add(1)
		return io.NopCloser(bytes.NewReader(backupOf(size))), int64(size), nil
	}
}

func export(t *testing.T, from, to *node) ([]byte, error) {
	t.Helper()
	body, err := from.f.Export(ctx(t), to.id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()
	return io.ReadAll(body)
}

func TestABackupLargerThanARelayFrameArrivesWholeOnTheNetwork(t *testing.T) {
	const size = 9<<20 + 4321
	var count atomic.Int32
	a, b := onOneNetwork(t, setup{uses: []string{ExportAction}}, setup{export: exporting(size, &count)}, unchanged)
	got, err := export(t, a, b)
	if err != nil || !bytes.Equal(got, backupOf(size)) {
		t.Fatalf("alpha exports bravo's backup: %d of %d bytes, %v", len(got), size, err)
	}
	if m, _ := memberOf(a.f, b.id); !slices.Contains(m.Actions, ExportAction) {
		t.Errorf("bravo offers %v, without %s", m.Actions, ExportAction)
	}
}

func TestABackupIsNotExportedThroughTheRelay(t *testing.T) {
	url := relayServer(t)
	var count atomic.Int32
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url, noListener: true, export: exporting(10, &count)})
	waitFor(t, "both on the relay", func() bool { return len(a.f.Members()) == 1 && len(b.f.Members()) == 1 })
	meet(t, a, b)
	if _, err := export(t, a, b); !errors.Is(err, group.ErrNotDirect) {
		t.Errorf("an export through the relay: %v, want group.ErrNotDirect", err)
	}
	if n := count.Load(); n != 0 {
		t.Errorf("bravo exported %d times for a call through the relay", n)
	}
}

func TestABackupIsNotExportedWithoutThePermission(t *testing.T) {
	var count atomic.Int32
	a, b := onOneNetwork(t, setup{uses: []string{ExportAction}}, setup{export: exporting(10, &count)}, unchanged)
	if err := b.f.SetPermission("alpha", "bravo", ExportAction, false); err != nil {
		t.Fatal(err)
	}
	if _, err := export(t, a, b); !errors.Is(err, ErrPermissionOff) {
		t.Errorf("an export with the permission off: %v, want ErrPermissionOff", err)
	}
	if n := count.Load(); n != 0 {
		t.Errorf("bravo exported %d times with the permission off", n)
	}
	if err := b.f.SetPermission("alpha", "bravo", ExportAction, true); err != nil {
		t.Fatal(err)
	}
	if got, err := export(t, a, b); err != nil || len(got) != 10 {
		t.Errorf("an export with the permission back on: %d bytes, %v", len(got), err)
	}
}

func TestAnAppWithoutAnExportSaysSo(t *testing.T) {
	a, b := onOneNetwork(t, setup{uses: []string{ExportAction}}, setup{}, unchanged)
	if _, err := export(t, a, b); !errors.Is(err, ErrNoSuchAction) {
		t.Errorf("an export from an app without one: %v, want ErrNoSuchAction", err)
	}
}

func TestAnExportPassesOnTheAppsRefusal(t *testing.T) {
	refuse := func(context.Context, Caller) (io.ReadCloser, int64, error) {
		return nil, 0, &Refusal{Code: "backup_running"}
	}
	a, b := onOneNetwork(t, setup{uses: []string{ExportAction}}, setup{export: refuse}, unchanged)
	if _, err := export(t, a, b); refusalCode(err) != "backup_running" {
		t.Errorf("a refused export: %v, want backup_running", err)
	}
}

func TestAnExportSeesWhoAsked(t *testing.T) {
	var asked atomic.Value
	who := func(_ context.Context, from Caller) (io.ReadCloser, int64, error) {
		asked.Store(from)
		return io.NopCloser(bytes.NewReader(nil)), 0, nil
	}
	a, b := onOneNetwork(t, setup{uses: []string{ExportAction}}, setup{export: who}, unchanged)
	if _, err := export(t, a, b); err != nil {
		t.Fatal(err)
	}
	if c, _ := asked.Load().(Caller); c != (Caller{ID: a.id, App: "alpha", Device: "alpha-1"}) {
		t.Errorf("bravo exported for %+v, want alpha-1", c)
	}
}

// tampering is a proxy in front of a member that passes every export through
// damage on its way.
func tampering(t *testing.T, damage func([]byte) []byte) func(string) string {
	return func(target string) string {
		u, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		proxy := httputil.NewSingleHostReverseProxy(u)
		proxy.ModifyResponse = func(r *http.Response) error {
			if r.Header.Get("Content-Type") == "application/json" {
				return nil
			}
			raw, err := io.ReadAll(r.Body)
			_ = r.Body.Close()
			if err != nil {
				return err
			}
			r.Body = io.NopCloser(bytes.NewReader(damage(raw)))
			r.ContentLength = -1
			r.Header.Del("Content-Length")
			return nil
		}
		srv := httptest.NewServer(proxy)
		t.Cleanup(srv.Close)
		return srv.URL
	}
}

func TestADamagedOrCutExportFails(t *testing.T) {
	const size = 2 << 20
	for name, damage := range map[string]func([]byte) []byte{
		"a flipped bit":        func(b []byte) []byte { b[len(b)/2] ^= 0x04; return b },
		"cut in the middle":    func(b []byte) []byte { return b[:len(b)/2] },
		"cut by its last byte": func(b []byte) []byte { return b[:len(b)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			var count atomic.Int32
			a, b := onOneNetwork(t, setup{uses: []string{ExportAction}}, setup{export: exporting(size, &count)}, tampering(t, damage))
			got, err := export(t, a, b)
			if !errors.Is(err, group.ErrStreamBroken) {
				t.Errorf("a damaged export: %d bytes, %v, want group.ErrStreamBroken", len(got), err)
			}
		})
	}
}

func TestAnExportShorterThanItSaidFails(t *testing.T) {
	short := func(context.Context, Caller) (io.ReadCloser, int64, error) {
		return io.NopCloser(bytes.NewReader(backupOf(1000))), 2000, nil
	}
	a, b := onOneNetwork(t, setup{uses: []string{ExportAction}}, setup{export: short}, unchanged)
	if _, err := export(t, a, b); !errors.Is(err, group.ErrStreamBroken) {
		t.Errorf("an export shorter than it said: %v, want group.ErrStreamBroken", err)
	}
}

func TestBackupExportCannotBeAnOrdinaryAction(t *testing.T) {
	n := &node{name: "alpha-1", app: "alpha", id: identity(t, "alpha-1").ID(), store: &memStore{}, pairStore: &memStore{}}
	cfg := config(t, n, setup{})
	cfg.Actions = append(cfg.Actions, Action{Name: ExportAction, Run: func(context.Context, Caller, []byte) ([]byte, error) { return nil, nil }})
	if _, err := Open(cfg); err == nil {
		t.Error("Open took backup.export as an ordinary action")
	}
}

// big answers with as many bytes as its body says.
var big = Action{Name: "files.big", Run: func(_ context.Context, _ Caller, body []byte) ([]byte, error) {
	n, err := strconv.Atoi(string(body))
	return bytes.Repeat([]byte("x"), n), err
}}

func TestAnAnswerMayBeAsLargeAsTheAppAllows(t *testing.T) {
	act := func(t *testing.T, a, b *node, n int) error {
		t.Helper()
		out, err := a.f.Act(ctx(t), b.id, "files.big", []byte(strconv.Itoa(n)))
		if err == nil && len(out) != n {
			t.Errorf("an answer of %d bytes came as %d", n, len(out))
		}
		return err
	}
	t.Run("directly", func(t *testing.T) {
		a, b := onOneNetwork(t, setup{maxAnswer: 6 << 20, uses: []string{big.Name}}, setup{actions: []Action{big}, maxAnswer: 6 << 20}, unchanged)
		if err := act(t, a, b, 6<<20); err != nil {
			t.Errorf("an answer of 6 MiB on the network: %v", err)
		}
		if err := act(t, a, b, 6<<20+1); refusalCode(err) != "answerTooLarge" {
			t.Errorf("an answer past 6 MiB on the network: %v, want answerTooLarge", err)
		}
	})
	t.Run("through the relay", func(t *testing.T) {
		url := relayServer(t)
		a := open(t, "alpha", "alpha-1", setup{relay: url, noListener: true, uses: []string{big.Name}})
		b := open(t, "bravo", "bravo-1", setup{relay: url, noListener: true, actions: []Action{big}, maxRelay: 6 << 20})
		waitFor(t, "both on the relay", func() bool { return len(a.f.Members()) == 1 && len(b.f.Members()) == 1 })
		meet(t, a, b)
		if err := act(t, a, b, 6<<20); err != nil {
			t.Errorf("an answer of 6 MiB through the relay: %v", err)
		}
		if err := act(t, a, b, 6<<20+1); refusalCode(err) != "answerTooLarge" {
			t.Errorf("an answer past 6 MiB through the relay: %v, want answerTooLarge", err)
		}
	})
}

func TestABackupAskedForAsAnActionIsRefusedForWhatItIs(t *testing.T) {
	var count atomic.Int32
	a, b := onOneNetwork(t, setup{}, setup{export: exporting(10, &count)}, unchanged)
	if _, err := a.f.Act(ctx(t), b.id, ExportAction, nil); !errors.Is(err, ErrNotUsed) {
		t.Errorf("an app that does not use backup.export asks for it: %v, want ErrNotUsed", err)
	}
	c, d := onOneNetwork(t, setup{uses: []string{ExportAction}}, setup{export: exporting(10, &count)}, unchanged)
	if _, err := c.f.Act(ctx(t), d.id, ExportAction, nil); refusalCode(err) != "stream_only" {
		t.Errorf("backup.export asked for as an action: %v, want stream_only", err)
	}
	if n := count.Load(); n != 0 {
		t.Errorf("bravo exported %d times for an ordinary call", n)
	}
}
