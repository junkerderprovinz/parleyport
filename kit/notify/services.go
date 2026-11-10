package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

func (d *Dispatcher) webhook(ctx context.Context, w *Webhook, e Event) error {
	vars := e.vars(d.source)
	method := strings.ToUpper(strings.TrimSpace(w.Method))
	if method == "" {
		method = http.MethodPost
	}
	addr := expand(strings.TrimSpace(w.URL), slotURL, vars)
	var body string
	if method != http.MethodGet {
		body = expand(w.Body, bodySlot(w.Headers), vars)
	}
	embed := body == "" && method != http.MethodGet && discordToken(addr) != ""
	if embed {
		body = d.discordBody(e)
	}
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, addr, reader)
	if err != nil {
		return failf(CodeInvalid, "build the request: %v", err)
	}
	for name, value := range w.Headers {
		// An empty value is a header waiting for its secret, and a bare
		// Authorization would read as a wrong token.
		if v := stripControl(expand(value, slotHeader, vars)); v != "" {
			req.Header.Set(strings.TrimSpace(name), v)
		}
	}
	if embed {
		req.Header.Set("Content-Type", "application/json")
	}
	return d.do(req, nil)
}

func (d *Dispatcher) discord(ctx context.Context, addr string, e Event) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, strings.NewReader(d.discordBody(e)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return d.do(req, nil)
}

func (d *Dispatcher) gotify(ctx context.Context, g *Gotify, e Event) error {
	u, err := url.Parse(strings.TrimSpace(g.URL))
	if err != nil {
		return err
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(u.Path, "/message") {
		u.Path += "/message"
	}
	priority := deref(g.PrioritySuccess, DefaultGotifySuccess)
	if e.Severity.failed() {
		priority = deref(g.PriorityFailure, DefaultGotifyFailure)
	}
	payload := map[string]any{"title": e.Title, "message": e.Body, "priority": priority}
	if e.Link != "" {
		payload["extras"] = map[string]any{"client::notification": map[string]any{"click": map[string]string{"url": e.Link}}}
	}
	body, err := jsonBody(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if g.Token != "" {
		req.Header.Set("X-Gotify-Key", g.Token)
	}
	return d.do(req, nil)
}

func (d *Dispatcher) ntfy(ctx context.Context, n *Ntfy, e Event) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(n.URL), strings.NewReader(e.Body))
	if err != nil {
		return err
	}
	if e.Title != "" {
		// ntfy reads RFC 2047 for a header outside ASCII.
		req.Header.Set("Title", mime.QEncoding.Encode("utf-8", stripControl(e.Title)))
	}
	switch e.Severity {
	case SeverityCritical:
		req.Header.Set("Priority", "urgent")
		req.Header.Set("Tags", "rotating_light")
	case SeverityFailure:
		req.Header.Set("Priority", "high")
		req.Header.Set("Tags", "warning")
	}
	if e.Link != "" {
		req.Header.Set("Click", e.Link)
	}
	if n.Token != "" {
		req.Header.Set("Authorization", "Bearer "+n.Token)
	}
	return d.do(req, nil)
}

func (d *Dispatcher) matrix(ctx context.Context, m *Matrix, e Event) error {
	hs := strings.TrimRight(strings.TrimSpace(m.Homeserver), "/")
	room := strings.TrimSpace(m.Room)
	if strings.HasPrefix(room, "#") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, hs+"/_matrix/client/v3/directory/room/"+url.PathEscape(room), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+m.Token)
		var found struct {
			RoomID string `json:"room_id"`
		}
		if err := d.do(req, &found); err != nil {
			return err
		}
		if found.RoomID == "" {
			return failf(CodeNotFound, "the alias names no room")
		}
		room = found.RoomID
	}
	payload := map[string]string{"msgtype": "m.text", "body": lines(e.Title, e.Body, e.Link)}
	if e.HTML != "" {
		payload["format"] = "org.matrix.custom.html"
		payload["formatted_body"] = e.HTML
	}
	body, err := jsonBody(payload)
	if err != nil {
		return err
	}
	// Matrix drops a message whose transaction id it has seen, so every
	// message gets a new one.
	txn := fmt.Sprintf("%d.%d", time.Now().UnixNano(), d.txn.Add(1))
	endpoint := hs + "/_matrix/client/v3/rooms/" + url.PathEscape(room) + "/send/m.room.message/" + txn
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.Token)
	return d.do(req, nil)
}

func (d *Dispatcher) apprise(ctx context.Context, a *Apprise, e Event) error {
	typ := "info"
	switch e.Severity {
	case SeveritySuccess:
		typ = "success"
	case SeverityWarning:
		typ = "warning"
	case SeverityFailure, SeverityCritical:
		typ = "failure"
	}
	payload := map[string]string{"title": e.Title, "body": lines(e.Body, e.Link), "type": typ}
	if a.Tags != "" {
		payload["tag"] = a.Tags
	}
	if len(a.URLs) > 0 {
		payload["urls"] = strings.Join(a.URLs, " ")
	}
	return d.postJSON(ctx, strings.TrimSpace(a.URL), payload)
}

// checkURL is the check a key pings: its own, or the channel's.
func checkURL(h *Healthchecks, key string) string {
	if u := h.ByKey[key]; u != "" {
		return u
	}
	return h.URL
}

// checkURLs is every distinct check of a channel.
func checkURLs(h *Healthchecks) []string {
	var out []string
	seen := map[string]bool{}
	for _, u := range append([]string{h.URL}, mapValues(h.ByKey)...) {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// ping reports a phase to a check. A body, which the check keeps in its log,
// turns the GET into a POST.
func (d *Dispatcher) ping(ctx context.Context, check string, p Ping, body string) error {
	u := strings.TrimRight(strings.TrimSpace(check), "/")
	switch p {
	case PingStart, PingFail, PingLog:
		u += "/" + string(p)
	}
	method, reader := http.MethodGet, io.Reader(nil)
	if body != "" {
		method, reader = http.MethodPost, strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return err
	}
	return d.do(req, nil)
}

// unraidText takes out what Unraid's push agents mangle: they pass the
// text through echo -e and into JSON they build by hand.
var unraidText = strings.NewReplacer(`\`, "", `"`, "")

// unraidGate keeps Unraid notifications a second apart across the process,
// since the notify script names its file after the second and a second
// message within it replaces the first while the script still succeeds.
var unraidGate = &gate{slot: make(chan struct{}, 1), spacing: time.Second}

type gate struct {
	slot    chan struct{}
	spacing time.Duration
	last    time.Time
}

func (g *gate) run(ctx context.Context, f func() error) error {
	select {
	case g.slot <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-g.slot }()
	if wait := time.Until(g.last.Add(g.spacing)); wait > 0 && !sleep(ctx, wait) {
		return ctx.Err()
	}
	err := f()
	g.last = time.Now()
	return err
}

func (d *Dispatcher) unraid(ctx context.Context, e Event) error {
	var args []string
	if d.source != "" {
		args = append(args, "-e", unraidText.Replace(d.source))
	}
	args = append(args, "-s", unraidText.Replace(e.Title), "-d", unraidText.Replace(e.Body), "-i", e.Severity.importance())
	if e.Link != "" {
		args = append(args, "-l", unraidText.Replace(e.Link))
	}
	err := unraidGate.run(ctx, func() error { return d.runner.Run(ctx, UnraidNotifyScript, args...) })
	if err != nil {
		if ctx.Err() != nil {
			return failf(CodeTimeout, "unraid notify: %v", err)
		}
		return failf(CodeScript, "unraid notify: %v", err)
	}
	return nil
}

type localRunner struct{}

func (localRunner) Run(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		if said := strings.TrimSpace(string(out[:min(len(out), maxSaid)])); said != "" {
			return fmt.Errorf("%w: %s", err, said)
		}
	}
	return err
}

func jsonBody(v any) (io.Reader, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}

func deref(p *int, fallback int) int {
	if p == nil {
		return fallback
	}
	return *p
}
