package status

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrUnauthenticated tells Handler that a request carries no credentials
	// it accepts. Handler answers 401.
	ErrUnauthenticated = errors.New("status: unauthenticated")
	// ErrForbidden tells Handler that the caller is known but may not read
	// the status. Handler answers 403.
	ErrForbidden = errors.New("status: forbidden")
)

const (
	// DefaultLogLimit is how many log entries a request without a limit gets.
	DefaultLogLimit = 50
	// MaxLogLimit is the most log entries one request gets; a larger limit is
	// cut down to it.
	MaxLogLimit = 200
)

// Source is the app behind Handler. Lang is a language tag such as "de" or
// "pt-BR", or empty when the caller asked for none; texts come back in that
// language or the app's default.
type Source interface {
	Report(ctx context.Context, lang string) (Report, error)
	Log(ctx context.Context, q LogQuery) (LogPage, error)
}

// Handler serves GET on StatusPath and LogPath from src. Every request passes
// authorize first, which returns nil to let it through, an error wrapping
// ErrUnauthenticated or ErrForbidden to refuse it, or any other error when it
// cannot decide.
//
// Errors are JSON of the form {"error":"<code>"} with a matching status:
// not_found, method_not_allowed, unauthenticated, forbidden, bad_limit and
// internal. Errors from authorize or src are logged with slog and never sent.
func Handler(src Source, authorize func(*http.Request) error) http.Handler {
	return &handler{src: src, authorize: authorize}
}

type handler struct {
	src       Source
	authorize func(*http.Request) error
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != StatusPath && r.URL.Path != LogPath {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if err := h.authorize(r); err != nil {
		switch {
		case errors.Is(err, ErrUnauthenticated):
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthenticated")
		case errors.Is(err, ErrForbidden):
			writeError(w, http.StatusForbidden, "forbidden")
		default:
			fail(w, r, err)
		}
		return
	}
	if r.URL.Path == StatusPath {
		h.serveReport(w, r)
	} else {
		h.serveLog(w, r)
	}
}

func (h *handler) serveReport(w http.ResponseWriter, r *http.Request) {
	report, err := h.src.Report(r.Context(), language(r))
	if err != nil {
		fail(w, r, err)
		return
	}
	report.finish(time.Now())
	writeJSON(w, r, report)
}

func (h *handler) serveLog(w http.ResponseWriter, r *http.Request) {
	q := LogQuery{After: r.URL.Query().Get("after"), Limit: DefaultLogLimit, Lang: language(r)}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "bad_limit")
			return
		}
		q.Limit = min(n, MaxLogLimit)
	}
	page, err := h.src.Log(r.Context(), q)
	if err != nil {
		fail(w, r, err)
		return
	}
	if page.Entries == nil {
		page.Entries = []LogEntry{}
	}
	writeJSON(w, r, page)
}

// finish sets what the handler owns and replaces nil lists, which readers in
// other languages would otherwise see as null.
func (rep *Report) finish(now time.Time) {
	rep.Contract = Contract
	rep.Counts = Counts{NeedsYou: len(rep.NeedsYou), Work: len(rep.Work)}
	states := []State{rep.State}
	for _, n := range rep.NeedsYou {
		states = append(states, n.Severity.state())
	}
	rep.State = Worst(states...)
	if rep.SampledAt.IsZero() {
		rep.SampledAt = now.UTC()
	}
	if rep.NeedsYou == nil {
		rep.NeedsYou = []Need{}
	}
	if rep.Work == nil {
		rep.Work = []Task{}
	}
	if rep.Next == nil {
		rep.Next = []Scheduled{}
	}
	if rep.Capabilities == nil {
		rep.Capabilities = []string{}
	}
}

var languageTag = regexp.MustCompile(`^[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$`)

// language reads the lang parameter, or else the tag the Accept-Language
// header weighs highest. Anything that is not a well-formed tag is ignored.
func language(r *http.Request) string {
	if l := r.URL.Query().Get("lang"); languageTag.MatchString(l) {
		return l
	}
	best, bestQ := "", 0.0
	for part := range strings.SplitSeq(r.Header.Get("Accept-Language"), ",") {
		tag, params, _ := strings.Cut(part, ";")
		tag = strings.TrimSpace(tag)
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			q = f
		}
		if q > bestQ && languageTag.MatchString(tag) {
			best, bestQ = tag, q
		}
	}
	return best
}

func writeJSON(w http.ResponseWriter, r *http.Request, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(body, '\n'))
}

func fail(w http.ResponseWriter, r *http.Request, err error) {
	slog.ErrorContext(r.Context(), "status request failed", "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal")
}

func writeError(w http.ResponseWriter, code int, errCode string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"error":"` + errCode + `"}` + "\n"))
}
