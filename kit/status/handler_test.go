package status_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/status"
)

// fakeSource answers with fixed data and remembers what it was asked.
type fakeSource struct {
	report    status.Report
	page      status.LogPage
	err       error
	gotLang   string
	gotQuery  status.LogQuery
	reportHit bool
	logHit    bool
}

func (s *fakeSource) Report(_ context.Context, lang string) (status.Report, error) {
	s.reportHit = true
	s.gotLang = lang
	return s.report, s.err
}

func (s *fakeSource) Log(_ context.Context, q status.LogQuery) (status.LogPage, error) {
	s.logHit = true
	s.gotQuery = q
	return s.page, s.err
}

func allow(*http.Request) error { return nil }

func serve(t *testing.T, h http.Handler, method, target string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	for k, v := range header {
		r.Header[k] = v
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body %q is not JSON: %v", w.Body.String(), err)
	}
	return body.Error
}

func TestHandler_Authorization(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
		wantBody string
	}{
		{"no credentials", status.ErrUnauthenticated, http.StatusUnauthorized, "unauthenticated"},
		{"wrapped no credentials", fmt.Errorf("token unknown: %w", status.ErrUnauthenticated), http.StatusUnauthorized, "unauthenticated"},
		{"credentials without the right", status.ErrForbidden, http.StatusForbidden, "forbidden"},
		{"check that breaks", errors.New("token store down"), http.StatusInternalServerError, "internal"},
	}
	for _, tt := range tests {
		for _, path := range []string{status.StatusPath, status.LogPath} {
			t.Run(tt.name+" on "+path, func(t *testing.T) {
				src := &fakeSource{}
				h := status.Handler(src, func(*http.Request) error { return tt.err })
				w := serve(t, h, http.MethodGet, path, nil)
				if w.Code != tt.wantCode {
					t.Fatalf("code = %d, want %d", w.Code, tt.wantCode)
				}
				if got := errorCode(t, w); got != tt.wantBody {
					t.Errorf("error = %q, want %q", got, tt.wantBody)
				}
				if src.reportHit || src.logHit {
					t.Error("source was asked although the request was refused")
				}
				if strings.Contains(w.Body.String(), "token store") {
					t.Errorf("body %q leaks the check's error", w.Body.String())
				}
			})
		}
	}
}

func TestHandler_UnauthenticatedNamesTheScheme(t *testing.T) {
	h := status.Handler(&fakeSource{}, func(*http.Request) error { return status.ErrUnauthenticated })
	w := serve(t, h, http.MethodGet, status.StatusPath, nil)
	if got := w.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want Bearer", got)
	}
}

func TestHandler_Routing(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		wantCode int
		wantBody string
	}{
		{"unknown path", http.MethodGet, "/api/fortress/v1/other", http.StatusNotFound, "not_found"},
		{"status with a trailing slash", http.MethodGet, status.StatusPath + "/", http.StatusNotFound, "not_found"},
		{"post to status", http.MethodPost, status.StatusPath, http.StatusMethodNotAllowed, "method_not_allowed"},
		{"delete on log", http.MethodDelete, status.LogPath, http.StatusMethodNotAllowed, "method_not_allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := serve(t, status.Handler(&fakeSource{}, allow), tt.method, tt.path, nil)
			if w.Code != tt.wantCode {
				t.Fatalf("code = %d, want %d", w.Code, tt.wantCode)
			}
			if got := errorCode(t, w); got != tt.wantBody {
				t.Errorf("error = %q, want %q", got, tt.wantBody)
			}
			if tt.wantCode == http.StatusMethodNotAllowed && w.Header().Get("Allow") != http.MethodGet {
				t.Errorf("Allow = %q, want GET", w.Header().Get("Allow"))
			}
		})
	}
}

func TestHandler_SourceFailure(t *testing.T) {
	for _, path := range []string{status.StatusPath, status.LogPath} {
		t.Run(path, func(t *testing.T) {
			src := &fakeSource{err: errors.New("database is locked at /data/app.db")}
			w := serve(t, status.Handler(src, allow), http.MethodGet, path, nil)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("code = %d, want 500", w.Code)
			}
			if got := errorCode(t, w); got != "internal" {
				t.Errorf("error = %q, want internal", got)
			}
			if strings.Contains(w.Body.String(), "/data") {
				t.Errorf("body %q leaks the source's error", w.Body.String())
			}
		})
	}
}

func TestHandler_Report(t *testing.T) {
	sampled := time.Date(2026, 11, 9, 10, 5, 0, 0, time.UTC)
	src := &fakeSource{report: status.Report{
		App:      status.App{ID: "example-app", Name: "Example", Version: "1.2.3"},
		Instance: status.Instance{ID: "3f9c", Name: "Tower"},
		State:    status.StateOK,
		NeedsYou: []status.Need{
			{ID: "a", Severity: status.SeverityInfo, Code: "update.available", Text: "An update is ready."},
			{ID: "b", Severity: status.SeverityWarn, Code: "copy.stale", Text: "The copy is old."},
		},
		Work:      []status.Task{{ID: "run-1", Kind: status.KindBackup, Title: "All", StartedAt: sampled}},
		SampledAt: sampled,
	}}
	w := serve(t, status.Handler(src, allow), http.MethodGet, status.StatusPath, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200, body %s", w.Code, w.Body)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	var got status.Report
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Contract != status.Contract {
		t.Errorf("contract = %d, want %d", got.Contract, status.Contract)
	}
	if got.Counts != (status.Counts{NeedsYou: 2, Work: 1}) {
		t.Errorf("counts = %+v, want 2 needs and 1 task", got.Counts)
	}
	if got.State != status.StateWarning {
		t.Errorf("state = %q, want warning because a need is a warning", got.State)
	}
	if !got.SampledAt.Equal(sampled) {
		t.Errorf("sampledAt = %v, want the source's %v", got.SampledAt, sampled)
	}
}

func TestHandler_ReportStateFollowsTheWorstNeed(t *testing.T) {
	tests := []struct {
		name  string
		state status.State
		needs []status.Severity
		want  status.State
	}{
		{"info leaves ok alone", status.StateOK, []status.Severity{status.SeverityInfo}, status.StateOK},
		{"warn lifts ok to warning", status.StateOK, []status.Severity{status.SeverityWarn}, status.StateWarning},
		{"error lifts ok to failed", status.StateOK, []status.Severity{status.SeverityInfo, status.SeverityError}, status.StateFailed},
		{"warn keeps overdue", status.StateOverdue, []status.Severity{status.SeverityWarn}, status.StateOverdue},
		{"no state and no needs reads as off", "", nil, status.StateOff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := status.Report{State: tt.state}
			for i, sev := range tt.needs {
				r.NeedsYou = append(r.NeedsYou, status.Need{ID: fmt.Sprint(i), Severity: sev})
			}
			w := serve(t, status.Handler(&fakeSource{report: r}, allow), http.MethodGet, status.StatusPath, nil)
			var got status.Report
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.State != tt.want {
				t.Errorf("state = %q, want %q", got.State, tt.want)
			}
		})
	}
}

func TestHandler_ReportFillsTheGaps(t *testing.T) {
	before := time.Now()
	w := serve(t, status.Handler(&fakeSource{}, allow), http.MethodGet, status.StatusPath, nil)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, list := range []string{"needsYou", "work", "next", "capabilities"} {
		if got := string(raw[list]); got != "[]" {
			t.Errorf("%s = %s, want []", list, got)
		}
	}
	var got status.Report
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.SampledAt.Before(before.Add(-time.Second)) {
		t.Errorf("sampledAt = %v, want about now", got.SampledAt)
	}
}

func TestHandler_Language(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		accept string
		want   string
	}{
		{"query", "?lang=de", "", "de"},
		{"query beats header", "?lang=fr", "de", "fr"},
		{"header", "", "de-AT", "de-AT"},
		{"highest weight in the header", "", "en;q=0.5, de;q=0.9, fr;q=0.1", "de"},
		{"first of equal weights", "", "pt-BR, de", "pt-BR"},
		{"wildcard and refused tags are skipped", "", "*, en;q=0, de;q=0.3", "de"},
		{"nothing asked", "", "", ""},
		{"malformed query falls back to the header", "?lang=../../etc", "de", "de"},
		{"malformed header", "", "<script>", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var header http.Header
			if tt.accept != "" {
				header = http.Header{"Accept-Language": {tt.accept}}
			}
			src := &fakeSource{}
			h := status.Handler(src, allow)
			serve(t, h, http.MethodGet, status.StatusPath+tt.query, header)
			if src.gotLang != tt.want {
				t.Errorf("report lang = %q, want %q", src.gotLang, tt.want)
			}
			serve(t, h, http.MethodGet, status.LogPath+tt.query, header)
			if src.gotQuery.Lang != tt.want {
				t.Errorf("log lang = %q, want %q", src.gotQuery.Lang, tt.want)
			}
		})
	}
}

func TestHandler_LogQuery(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		wantAfter string
		wantLimit int
	}{
		{"defaults", "", "", status.DefaultLogLimit},
		{"cursor and limit", "?after=c42&limit=10", "c42", 10},
		{"limit above the cap", "?limit=5000", "", status.MaxLogLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := &fakeSource{}
			w := serve(t, status.Handler(src, allow), http.MethodGet, status.LogPath+tt.query, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("code = %d, want 200", w.Code)
			}
			if src.gotQuery.After != tt.wantAfter || src.gotQuery.Limit != tt.wantLimit {
				t.Errorf("query = %+v, want after %q and limit %d", src.gotQuery, tt.wantAfter, tt.wantLimit)
			}
		})
	}
}

func TestHandler_LogRejectsABadLimit(t *testing.T) {
	for _, limit := range []string{"0", "-3", "ten", "1.5"} {
		t.Run(limit, func(t *testing.T) {
			src := &fakeSource{}
			w := serve(t, status.Handler(src, allow), http.MethodGet, status.LogPath+"?limit="+limit, nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("code = %d, want 400", w.Code)
			}
			if got := errorCode(t, w); got != "bad_limit" {
				t.Errorf("error = %q, want bad_limit", got)
			}
			if src.logHit {
				t.Error("source was asked for a bad limit")
			}
		})
	}
}

func TestHandler_LogPage(t *testing.T) {
	at := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	src := &fakeSource{page: status.LogPage{
		Entries: []status.LogEntry{{ID: "7", At: at, Level: status.SeverityInfo, Code: "run.done", Text: "Done."}},
		Next:    "7",
	}}
	w := serve(t, status.Handler(src, allow), http.MethodGet, status.LogPath, nil)
	var got status.LogPage
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || got.Entries[0].ID != "7" || got.Next != "7" {
		t.Errorf("page = %+v, want the source's page", got)
	}
}

func TestHandler_EmptyLogPageListsNoEntries(t *testing.T) {
	src := &fakeSource{page: status.LogPage{Next: "c9"}}
	w := serve(t, status.Handler(src, allow), http.MethodGet, status.LogPath+"?after=c9", nil)
	if got := strings.TrimSpace(w.Body.String()); got != `{"entries":[],"next":"c9"}` {
		t.Errorf("body = %s, want an empty list and the cursor", got)
	}
}
