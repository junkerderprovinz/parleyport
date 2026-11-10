package statustest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/status"
)

const testToken = "Bearer example-app-test"

func authenticate(r *http.Request) { r.Header.Set("Authorization", testToken) }

func authorize(r *http.Request) error {
	if r.Header.Get("Authorization") != testToken {
		return status.ErrUnauthenticated
	}
	return nil
}

// source is an app that keeps the contract until one of its switches is set.
type source struct {
	needs         int
	unstableIDs   bool
	untranslated  bool
	entries       int
	disorder      bool
	ignoreCursor  bool
	ignoreLimit   bool
	forgetsCursor bool
	icon          string
	calls         int
}

func newSource() *source { return &source{needs: 2, entries: 3, icon: svgIcon(`<circle r="4"/>`)} }

// svgIcon wraps body in an SVG and returns it as a data URI without checking it.
func svgIcon(body string) string {
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8">` + body + `</svg>`
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg))
}

func (s *source) text(lang, en, de string) string {
	if lang == "de" && !s.untranslated {
		return de
	}
	return en
}

func (s *source) Report(_ context.Context, lang string) (status.Report, error) {
	s.calls++
	at := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	r := status.Report{
		App:      status.App{ID: "example-app", Name: "Example", Version: "1.0.0", Color: "#2e7d32", Icon: s.icon},
		Instance: status.Instance{ID: "a1", Name: "Tower"},
		State:    status.StateOK,
		Work:     []status.Task{{ID: "run-1", Kind: status.KindBackup, Title: "All", StartedAt: at}},
	}
	for i := range s.needs {
		id := "need-" + strconv.Itoa(i)
		if s.unstableIDs {
			id += "-" + strconv.Itoa(s.calls)
		}
		r.NeedsYou = append(r.NeedsYou, status.Need{
			ID: id, Severity: status.SeverityWarn, Code: "copy.stale",
			Text: s.text(lang, "The copy is old.", "Die Kopie ist alt."),
		})
	}
	return r, nil
}

func (s *source) Log(_ context.Context, q status.LogQuery) (status.LogPage, error) {
	after, _ := strconv.Atoi(q.After)
	if s.ignoreCursor {
		after = 0
	}
	page := status.LogPage{Entries: []status.LogEntry{}, Next: q.After}
	for i := after + 1; i <= s.entries; i++ {
		if len(page.Entries) == q.Limit && !s.ignoreLimit {
			break
		}
		at := time.Date(2026, 11, 9, 10, i, 0, 0, time.UTC)
		if s.disorder {
			at = at.Add(-time.Duration(2*i) * time.Minute)
		}
		page.Entries = append(page.Entries, status.LogEntry{
			ID: strconv.Itoa(i), At: at, Level: status.SeverityInfo, Code: "run.done",
			Text: s.text(q.Lang, "The run is done.", "Der Lauf ist fertig."),
		})
		page.Next = strconv.Itoa(i)
	}
	if len(page.Entries) == 0 && s.forgetsCursor {
		page.Next = ""
	}
	return page, nil
}

// rewrite changes the JSON a handler answers on path.
func rewrite(h http.Handler, path string, change func(map[string]any)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if r.URL.Path != path || rec.Code != http.StatusOK {
			copyResponse(w, rec)
			return
		}
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			panic(err)
		}
		change(m)
		body, err := json.Marshal(m)
		if err != nil {
			panic(err)
		}
		rec.Body = bytes.NewBuffer(body)
		copyResponse(w, rec)
	})
}

func copyResponse(w http.ResponseWriter, rec *httptest.ResponseRecorder) {
	for k, v := range rec.Header() {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

func TestCheck_AcceptsAHandlerThatKeepsTheContract(t *testing.T) {
	h := status.Handler(newSource(), authorize)
	if got := check(h, Options{Authenticate: authenticate}); len(got) != 0 {
		t.Errorf("deviations for a conforming handler:\n%s", strings.Join(got, "\n"))
	}
}

func TestCheck_FindsEveryDeviation(t *testing.T) {
	good := func(change func(*source)) http.Handler {
		s := newSource()
		if change != nil {
			change(s)
		}
		return status.Handler(s, authorize)
	}
	tests := []struct {
		name string
		h    http.Handler
		want string
	}{
		{
			name: "open to anyone",
			h:    status.Handler(newSource(), func(*http.Request) error { return nil }),
			want: "GET /api/fortress/v1/status without credentials: status 200, want 401",
		},
		{
			name: "any token goes",
			h: status.Handler(newSource(), func(r *http.Request) error {
				if r.Header.Get("Authorization") == "" {
					return status.ErrUnauthenticated
				}
				return nil
			}),
			want: "GET /api/fortress/v1/log with an unknown token: status 200, want 401",
		},
		{
			name: "takes a post",
			h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					r.Method = http.MethodGet
				}
				good(nil).ServeHTTP(w, r)
			}),
			want: "POST /api/fortress/v1/status: status 200, want 405",
		},
		{
			name: "outside the schema",
			h:    rewrite(good(nil), status.StatusPath, func(m map[string]any) { m["state"] = "attention" }),
			want: "report does not match the schema",
		},
		{
			name: "not json",
			h:    withHeader(good(nil), "Content-Type", "text/plain"),
			want: "report Content-Type is text/plain, want application/json",
		},
		{
			name: "counts that do not add up",
			h:    rewrite(good(nil), status.StatusPath, func(m map[string]any) { m["counts"].(map[string]any)["work"] = 4 }),
			want: "counts.work is 4, but work lists 1",
		},
		{
			name: "a field that looks like a secret",
			h:    rewrite(good(nil), status.StatusPath, func(m map[string]any) { m["app"].(map[string]any)["apiToken"] = "x" }),
			want: `report has a field named "apiToken"`,
		},
		{
			name: "an icon that runs a script",
			h:    good(func(s *source) { s.icon = svgIcon(`<script>alert(1)</script>`) }),
			want: "app.icon: ",
		},
		{
			name: "an icon that loads a picture from elsewhere",
			h:    good(func(s *source) { s.icon = svgIcon(`<image href="https://example.org/x.png"/>`) }),
			want: "app.icon: ",
		},
		{
			name: "an icon that is not an SVG",
			h:    rewrite(good(nil), status.StatusPath, func(m map[string]any) { m["app"].(map[string]any)["icon"] = "/icon.png" }),
			want: "at '/app/icon': '/icon.png' does not match pattern",
		},
		{
			name: "a color that is not hex",
			h:    rewrite(good(nil), status.StatusPath, func(m map[string]any) { m["app"].(map[string]any)["color"] = "green" }),
			want: "at '/app/color': 'green' does not match pattern",
		},
		{
			name: "too large",
			h:    status.Handler(&bigSource{source: newSource()}, authorize),
			want: "bytes, want at most 65536",
		},
		{
			name: "nothing that needs the user",
			h:    good(func(s *source) { s.needs = 0 }),
			want: "needsYou is empty",
		},
		{
			name: "ids that change",
			h:    good(func(s *source) { s.unstableIDs = true }),
			want: "needsYou ids changed between two reports",
		},
		{
			name: "the same id twice",
			h: rewrite(good(nil), status.StatusPath, func(m map[string]any) {
				needs := m["needsYou"].([]any)
				needs[1].(map[string]any)["id"] = needs[0].(map[string]any)["id"]
			}),
			want: `needsYou lists the id "need-0" twice`,
		},
		{
			name: "one language only",
			h:    good(func(s *source) { s.untranslated = true }),
			want: "lang=de returns the same needsYou texts as lang=en",
		},
		{
			name: "header ignored",
			h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Header.Del("Accept-Language")
				good(nil).ServeHTTP(w, r)
			}),
			want: "Accept-Language: de returns other needsYou texts than lang=de",
		},
		{
			name: "log out of order",
			h:    good(func(s *source) { s.disorder = true }),
			want: "log entry 2 is older than the entry before it",
		},
		{
			name: "log cursor ignored",
			h:    good(func(s *source) { s.ignoreCursor = true }),
			want: `log returned entry "1" twice`,
		},
		{
			name: "log limit ignored",
			h:    good(func(s *source) { s.ignoreLimit = true }),
			want: "log with limit=1 returned 3 entries",
		},
		{
			name: "log forgets the cursor at the end",
			h:    good(func(s *source) { s.forgetsCursor = true }),
			want: `log after "3" with nothing newer returns next "", want "3"`,
		},
		{
			name: "log too short to page",
			h:    good(func(s *source) { s.entries = 1 }),
			want: "log has 1 entries",
		},
		{
			name: "log takes a zero limit",
			h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("limit") == "0" {
					r.URL.RawQuery = ""
				}
				good(nil).ServeHTTP(w, r)
			}),
			want: "GET /api/fortress/v1/log?limit=0: status 200, want 400",
		},
		{
			name: "log in one language only",
			h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == status.LogPath {
					q := r.URL.Query()
					q.Del("lang")
					r.URL.RawQuery = q.Encode()
				}
				good(nil).ServeHTTP(w, r)
			}),
			want: "lang=de returns the same log texts as lang=en",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := check(tt.h, Options{Authenticate: authenticate})
			for _, d := range got {
				if strings.Contains(d, tt.want) {
					return
				}
			}
			t.Errorf("no deviation contains %q, got:\n%s", tt.want, strings.Join(got, "\n"))
		})
	}
}

// withHeader sets a response header on everything h answers.
func withHeader(h http.Handler, key, value string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		rec.Header().Set(key, value)
		copyResponse(w, rec)
	})
}

// bigSource pads every report past the size limit.
type bigSource struct{ *source }

func (s *bigSource) Report(ctx context.Context, lang string) (status.Report, error) {
	r, err := s.source.Report(ctx, lang)
	for i := range 40 {
		r.NeedsYou = append(r.NeedsYou, status.Need{
			ID: fmt.Sprint("pad-", i), Severity: status.SeverityInfo, Code: "pad",
			Text: strings.Repeat(s.text(lang, "x", "y"), 2000),
		})
	}
	return r, err
}

// recorder stands in for a test to see what Run reports.
type recorder struct {
	testing.TB
	errors []string
}

func (r *recorder) Helper() {}

func (r *recorder) Error(args ...any) { r.errors = append(r.errors, fmt.Sprint(args...)) }

func TestRun_FailsTheTestOncePerDeviation(t *testing.T) {
	broken := func() http.Handler {
		s := newSource()
		s.needs, s.entries = 0, 0
		return status.Handler(s, authorize)
	}
	want := strings.Join(check(broken(), Options{Authenticate: authenticate}), "\n")
	if want == "" {
		t.Fatal("the broken handler shows no deviation")
	}
	rec := &recorder{TB: t}
	Run(rec, broken(), Options{Authenticate: authenticate})
	if got := strings.Join(rec.errors, "\n"); got != want {
		t.Errorf("Run reported:\n%s\nwant:\n%s", got, want)
	}
}
