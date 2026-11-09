// Package statustest checks a handler against the status contract, so every
// app can prove in its own tests that it answers what readers expect. An app
// builds its real API handler on test data and hands it to Run:
//
//	func TestStatusContract(t *testing.T) {
//		statustest.Run(t, newTestAPI(t), statustest.Options{Authenticate: signIn})
//	}
package statustest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/junkerderprovinz/parleyport/kit/status"
)

// maxReportBytes is the largest report the contract allows.
const maxReportBytes = 64 << 10

// maxLogPages stops paging through a log whose cursor never reaches the end.
const maxLogPages = 1000

// Options tells Run how to reach the handler.
type Options struct {
	// Authenticate adds credentials the handler accepts to a request.
	Authenticate func(r *http.Request)
}

// Run checks h against the status contract and reports every deviation as an
// error on t. The handler must serve test data with at least one item in
// needsYou and two log entries, all with texts in English and German, so the
// ids, the cursor and the languages can be compared. A report may be at most
// 64 KiB.
func Run(t testing.TB, h http.Handler, opt Options) {
	t.Helper()
	for _, d := range check(h, opt) {
		t.Error(d)
	}
}

func check(h http.Handler, opt Options) []string {
	c := &checker{h: h, opt: opt}
	c.checkAccess()
	c.checkReport()
	c.checkLog()
	return c.issues
}

type checker struct {
	h      http.Handler
	opt    Options
	issues []string
}

func (c *checker) addf(format string, args ...any) {
	c.issues = append(c.issues, fmt.Sprintf(format, args...))
}

func (c *checker) do(method, path string, query url.Values, header http.Header, authed bool) *httptest.ResponseRecorder {
	target := path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	r := httptest.NewRequest(method, target, nil)
	for k, v := range header {
		r.Header[k] = v
	}
	if authed {
		c.opt.Authenticate(r)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	return w
}

func (c *checker) checkAccess() {
	for _, path := range []string{status.StatusPath, status.LogPath} {
		if w := c.do(http.MethodGet, path, nil, nil, false); w.Code != http.StatusUnauthorized {
			c.addf("GET %s without credentials: status %d, want 401", path, w.Code)
		}
		foreign := http.Header{"Authorization": {"Bearer statustest-unknown-token"}}
		if w := c.do(http.MethodGet, path, nil, foreign, false); w.Code != http.StatusUnauthorized {
			c.addf("GET %s with an unknown token: status %d, want 401", path, w.Code)
		}
	}
	if w := c.do(http.MethodPost, status.StatusPath, nil, nil, true); w.Code != http.StatusMethodNotAllowed {
		c.addf("POST %s: status %d, want 405", status.StatusPath, w.Code)
	}
}

func (c *checker) checkReport() {
	en, ok := c.report(url.Values{"lang": {"en"}}, nil)
	if !ok {
		return
	}
	if en.Counts.NeedsYou != len(en.NeedsYou) {
		c.addf("counts.needsYou is %d, but needsYou lists %d", en.Counts.NeedsYou, len(en.NeedsYou))
	}
	if en.Counts.Work != len(en.Work) {
		c.addf("counts.work is %d, but work lists %d", en.Counts.Work, len(en.Work))
	}
	c.unique("needsYou", needIDs(en))
	c.unique("work", taskIDs(en))

	if again, ok := c.report(url.Values{"lang": {"en"}}, nil); ok {
		if a, b := needIDs(en), needIDs(again); !sameSet(a, b) {
			c.addf("needsYou ids changed between two reports: %q, then %q", a, b)
		}
		if a, b := taskIDs(en), taskIDs(again); !sameSet(a, b) {
			c.addf("work ids changed between two reports: %q, then %q", a, b)
		}
	}

	if len(en.NeedsYou) == 0 {
		c.addf("needsYou is empty, so its ids and languages cannot be compared; give the handler test data with at least one item")
		return
	}
	needTexts := func(r status.Report) map[string]string {
		m := map[string]string{}
		for _, n := range r.NeedsYou {
			m[n.ID] = n.Text
		}
		return m
	}
	de, ok := c.report(url.Values{"lang": {"de"}}, nil)
	if !ok {
		return
	}
	if !textsDiffer(needTexts(en), needTexts(de)) {
		c.addf("lang=de returns the same needsYou texts as lang=en")
	}
	if header, ok := c.report(nil, http.Header{"Accept-Language": {"de"}}); ok {
		if textsDiffer(needTexts(de), needTexts(header)) {
			c.addf("Accept-Language: de returns other needsYou texts than lang=de")
		}
	}
}

// report fetches and checks one report; ok is false when it cannot be read.
func (c *checker) report(query url.Values, header http.Header) (status.Report, bool) {
	var r status.Report
	w := c.do(http.MethodGet, status.StatusPath, query, header, true)
	if w.Code != http.StatusOK {
		c.addf("GET %s: status %d, want 200", status.StatusPath, w.Code)
		return r, false
	}
	body := w.Body.Bytes()
	c.contentType("report", w)
	if len(body) > maxReportBytes {
		c.addf("report is %d bytes, want at most %d", len(body), maxReportBytes)
	}
	c.schema("report", reportSchema, body)
	c.noSecrets("report", body)
	if err := json.Unmarshal(body, &r); err != nil {
		c.addf("report does not decode: %v", err)
		return r, false
	}
	return r, true
}

func (c *checker) checkLog() {
	seen := map[string]bool{}
	var last status.LogEntry
	after := ""
	ended := false
	for range maxLogPages {
		page, ok := c.logPage(url.Values{"after": {after}, "limit": {"1"}})
		if !ok {
			return
		}
		if len(page.Entries) == 0 {
			if page.Next != after {
				c.addf("log after %q with nothing newer returns next %q, want %q", after, page.Next, after)
			}
			ended = true
			break
		}
		if len(page.Entries) > 1 {
			c.addf("log with limit=1 returned %d entries", len(page.Entries))
			return
		}
		e := page.Entries[0]
		if seen[e.ID] {
			c.addf("log returned entry %q twice while paging with next", e.ID)
			return
		}
		if len(seen) > 0 && e.At.Before(last.At) {
			c.addf("log entry %s is older than the entry before it", e.ID)
		}
		seen[e.ID] = true
		last = e
		after = page.Next
	}
	if !ended {
		c.addf("log did not end after %d pages", maxLogPages)
	}
	if len(seen) < 2 {
		c.addf("log has %d entries, so its cursor cannot be checked; give the handler test data with at least two", len(seen))
	}

	for _, limit := range []string{"0", "many"} {
		q := url.Values{"limit": {limit}}
		if w := c.do(http.MethodGet, status.LogPath, q, nil, true); w.Code != http.StatusBadRequest {
			c.addf("GET %s?%s: status %d, want 400", status.LogPath, q.Encode(), w.Code)
		}
	}

	if len(seen) == 0 {
		return
	}
	logTexts := func(lang string) (map[string]string, bool) {
		page, ok := c.logPage(url.Values{"lang": {lang}, "limit": {"200"}})
		m := map[string]string{}
		for _, e := range page.Entries {
			m[e.ID] = e.Text
		}
		return m, ok
	}
	en, okEN := logTexts("en")
	de, okDE := logTexts("de")
	if okEN && okDE && !textsDiffer(en, de) {
		c.addf("lang=de returns the same log texts as lang=en")
	}
}

func (c *checker) logPage(query url.Values) (status.LogPage, bool) {
	var p status.LogPage
	w := c.do(http.MethodGet, status.LogPath, query, nil, true)
	if w.Code != http.StatusOK {
		c.addf("GET %s?%s: status %d, want 200", status.LogPath, query.Encode(), w.Code)
		return p, false
	}
	body := w.Body.Bytes()
	c.contentType("log", w)
	c.schema("log", logSchema, body)
	c.noSecrets("log", body)
	if err := json.Unmarshal(body, &p); err != nil {
		c.addf("log does not decode: %v", err)
		return p, false
	}
	return p, true
}

func (c *checker) contentType(what string, w *httptest.ResponseRecorder) {
	ct := w.Header().Get("Content-Type")
	if mt, _, _ := mime.ParseMediaType(ct); mt != "application/json" {
		c.addf("%s Content-Type is %s, want application/json", what, ct)
	}
}

var (
	reportSchema = sync.OnceValue(func() *jsonschema.Schema { return compile("v1.json", status.ReportSchema) })
	logSchema    = sync.OnceValue(func() *jsonschema.Schema { return compile("log-v1.json", status.LogSchema) })
)

func compile(name, schema string) *jsonschema.Schema {
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schema))
	if err != nil {
		panic(fmt.Sprintf("statustest: schema %s: %v", name, err))
	}
	cmp := jsonschema.NewCompiler()
	cmp.AssertFormat()
	if err := cmp.AddResource(name, doc); err != nil {
		panic(fmt.Sprintf("statustest: schema %s: %v", name, err))
	}
	return cmp.MustCompile(name)
}

func (c *checker) schema(what string, schema func() *jsonschema.Schema, body []byte) {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		c.addf("%s is not JSON: %v", what, err)
		return
	}
	if err := schema().Validate(inst); err != nil {
		c.addf("%s does not match the schema: %v", what, err)
	}
}

// secretWords are parts of field names that hint at credentials, which have
// no place in a report any member can read.
var secretWords = []string{"token", "password", "passwd", "secret", "apikey", "api_key", "credential"}

func (c *checker) noSecrets(what string, body []byte) {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return
	}
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, child := range v {
				lower := strings.ToLower(k)
				if slices.ContainsFunc(secretWords, func(w string) bool { return strings.Contains(lower, w) }) {
					c.addf("%s has a field named %q", what, k)
				}
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(v)
}

func (c *checker) unique(list string, ids []string) {
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			c.addf("%s lists the id %q twice", list, id)
		}
		seen[id] = true
	}
}

func needIDs(r status.Report) []string {
	ids := make([]string, len(r.NeedsYou))
	for i, n := range r.NeedsYou {
		ids[i] = n.ID
	}
	return ids
}

func taskIDs(r status.Report) []string {
	ids := make([]string, len(r.Work))
	for i, t := range r.Work {
		ids[i] = t.ID
	}
	return ids
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// textsDiffer reports whether any id present in both maps has another text.
func textsDiffer(a, b map[string]string) bool {
	for id, text := range a {
		if other, ok := b[id]; ok && other != text {
			return true
		}
	}
	return false
}
