package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/notify"
)

// hook is a webhook receiver that keeps what it got.
type hook struct {
	*httptest.Server
	status int

	mu   sync.Mutex
	got  []string
	auth []string
}

func newHook(t *testing.T, status int) *hook {
	t.Helper()
	h := &hook{status: status}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.got = append(h.got, string(body))
		h.auth = append(h.auth, r.Header.Get("Authorization"))
		h.mu.Unlock()
		w.WriteHeader(h.status)
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *hook) received() ([]string, []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.got...), append([]string(nil), h.auth...)
}

func webhook(id, url, on string) notify.Channel {
	return notify.Channel{ID: id, Kind: notify.KindWebhook, Enabled: true, On: notify.On(on), Attempts: 1,
		Webhook: &notify.Webhook{URL: url, Method: "POST", Headers: map[string]string{"Authorization": "Bearer s3cret"},
			Body: `{"title":"%%title%%","severity":"%%severity%%","from":"%%source%%"}`}}
}

func saved(t *testing.T, channels ...notify.Channel) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notify.json")
	raw, err := json.Marshal(channels)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func cli(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestSendDeliversAFailureToEveryChannelThatTakesIt(t *testing.T) {
	loud, quiet := newHook(t, 200), newHook(t, 200)
	path := saved(t, webhook("loud", loud.URL, "failure"), webhook("quiet", quiet.URL, "never"))

	code, out, stderr := cli(t, `{"kind":"disk.full","severity":"failure","title":"Disk full on tower","body":"Only 2 GB left."}`,
		"send", "-channels", path, "-source", "Watcher")
	if code != 0 {
		t.Fatalf("send: %d %s %s", code, out, stderr)
	}
	var results []result
	if err := json.Unmarshal([]byte(out), &results); err != nil || len(results) != 1 || !results[0].OK || results[0].Channel != "loud" {
		t.Fatalf("send printed %s %v", out, err)
	}
	got, _ := loud.received()
	if len(got) != 1 || got[0] != `{"title":"Disk full on tower","severity":"failure","from":"Watcher"}` {
		t.Errorf("the channel got %q", got)
	}
	if got, _ := quiet.received(); len(got) != 0 {
		t.Errorf("a channel switched to never got %q", got)
	}
}

func TestSendSkipsGoodNewsOnAFailureChannel(t *testing.T) {
	h := newHook(t, 200)
	path := saved(t, webhook("a", h.URL, "failure"))
	code, out, _ := cli(t, `{"kind":"disk.ok","severity":"success","title":"space again"}`, "send", "-channels", path)
	if code != 0 || strings.TrimSpace(out) != "[]" {
		t.Fatalf("send: %d %s", code, out)
	}
	if got, _ := h.received(); len(got) != 0 {
		t.Errorf("the channel got %q", got)
	}
}

func TestSendWithoutChannelsSendsNothing(t *testing.T) {
	code, out, stderr := cli(t, `{"severity":"failure","title":"x"}`, "send", "-channels", filepath.Join(t.TempDir(), "none.json"))
	if code != 0 || strings.TrimSpace(out) != "[]" {
		t.Fatalf("send: %d %s %s", code, out, stderr)
	}
}

func TestAFailedChannelExitsWithOneAndKeepsItsSecretsOut(t *testing.T) {
	h := newHook(t, 500)
	path := saved(t, webhook("a", h.URL+"/hook?token=s3cret", "always"))
	code, out, _ := cli(t, `{"severity":"failure","title":"x"}`, "send", "-channels", path)
	if code != 1 {
		t.Fatalf("send exits %d, want 1: %s", code, out)
	}
	var results []result
	if err := json.Unmarshal([]byte(out), &results); err != nil || len(results) != 1 || results[0].OK || results[0].Code != notify.CodeServer {
		t.Fatalf("send printed %s %v", out, err)
	}
	if strings.Contains(out, "s3cret") {
		t.Errorf("the result shows the secret: %s", out)
	}
}

func TestShowMasksTheSecretsAndSaveKeepsThem(t *testing.T) {
	h := newHook(t, 200)
	path := saved(t, webhook("a", h.URL, "failure"))

	code, out, stderr := cli(t, "", "show", "-channels", path)
	if code != 0 || strings.Contains(out, "s3cret") || !strings.Contains(out, notify.RedactedValue) {
		t.Fatalf("show: %d %s %s", code, out, stderr)
	}
	// The page sends the list back as show gave it, with a new name.
	edited := strings.Replace(out, `"enabled":true`, `"name":"Phone","enabled":true`, 1)
	code, out, stderr = cli(t, edited, "save", "-channels", path)
	if code != 0 || strings.Contains(out, "s3cret") || !strings.Contains(out, `"Phone"`) {
		t.Fatalf("save: %d %s %s", code, out, stderr)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own file
	if err != nil || !strings.Contains(string(raw), "Bearer s3cret") || !strings.Contains(string(raw), `"Phone"`) {
		t.Errorf("the file holds %s %v", raw, err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("the file is %v %v, want 0600", info.Mode().Perm(), err)
		}
	}
}

func TestSaveRefusesAnInvalidListAndKeepsTheOldOne(t *testing.T) {
	path := saved(t, webhook("a", "http://192.168.1.10/hook", "failure"))
	before, _ := os.ReadFile(path) //nolint:gosec // G304: the test's own file
	code, out, _ := cli(t, `[{"id":"b","kind":"ntfy","enabled":true}]`, "save", "-channels", path)
	if code != 1 {
		t.Fatalf("save exits %d, want 1: %s", code, out)
	}
	var answer struct{ Problems notify.Problems }
	if err := json.Unmarshal([]byte(out), &answer); err != nil || len(answer.Problems) == 0 || answer.Problems[0].Channel != "b" {
		t.Fatalf("save printed %s %v", out, err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) { //nolint:gosec // G304: the test's own file
		t.Errorf("the file changed to %s", after)
	}
}

func TestTestSendsADraftWithTheSavedSecret(t *testing.T) {
	h := newHook(t, 200)
	path := saved(t, webhook("a", h.URL, "never"))
	_, shown, _ := cli(t, "", "show", "-channels", path)
	var list []notify.Channel
	if err := json.Unmarshal([]byte(shown), &list); err != nil || len(list) != 1 {
		t.Fatal(shown, err)
	}
	draft, _ := json.Marshal(map[string]any{"channel": list[0], "event": map[string]string{"title": "Test", "severity": "info"}})

	code, out, stderr := cli(t, string(draft), "test", "-channels", path, "-source", "Watcher")
	if code != 0 {
		t.Fatalf("test: %d %s %s", code, out, stderr)
	}
	var r result
	if err := json.Unmarshal([]byte(out), &r); err != nil || !r.OK {
		t.Fatalf("test printed %s %v", out, err)
	}
	got, auth := h.received()
	if len(got) != 1 || len(auth) != 1 || auth[0] != "Bearer s3cret" {
		t.Errorf("the draft reached the hook as %q with %q, want the saved token", got, auth)
	}
}

func TestUsage(t *testing.T) {
	for name, args := range map[string][]string{
		"nothing":         nil,
		"an unknown verb": {"dance", "-channels", "x"},
		"no channels":     {"send"},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, _ := cli(t, "", args...); code != 2 {
				t.Errorf("exit %d, want 2", code)
			}
		})
	}
	if code, _, stderr := cli(t, "not json", "send", "-channels", filepath.Join(t.TempDir(), "n.json")); code != 1 || stderr == "" {
		t.Errorf("send with a broken event: %d %q", code, stderr)
	}
}
