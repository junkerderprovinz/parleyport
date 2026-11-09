package status_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/junkerderprovinz/parleyport/kit/status"
)

func compile(t *testing.T, name, schema string) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schema))
	if err != nil {
		t.Fatalf("%s is not JSON: %v", name, err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(name, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(name)
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return s
}

func validate(t *testing.T, s *jsonschema.Schema, body string) error {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(body))
	if err != nil {
		t.Fatalf("%q is not JSON: %v", body, err)
	}
	return s.Validate(inst)
}

func fullReport() status.Report {
	at := time.Date(2026, 11, 9, 10, 2, 11, 0, time.UTC)
	return status.Report{
		App: status.App{ID: "example-app", Name: "Example", Version: "9.4.0", Commit: "b6fe55b", UI: "https://tower.lan:3443/"},
		Instance: status.Instance{
			ID: "3f9c40", Name: "Tower", Container: "4b1d0c9e",
			Mounts: []status.Mount{{Container: "/data", Host: "/mnt/user/appdata/example"}},
		},
		State: status.StateOK,
		NeedsYou: []status.Need{{
			ID: "copy-stale", Severity: status.SeverityWarn, Code: "copy.stale",
			Text: "The off-site copy is 9 days old.", Since: at, Link: "/storage",
		}},
		Work: []status.Task{{
			ID: "run-8812", Kind: status.KindBackup, Title: "Container: web",
			Progress: new(0.42), StartedAt: at, BlocksRestart: true,
		}},
		Next:         []status.Scheduled{{Kind: status.KindBackup, Title: "Everything", At: at.Add(17 * time.Hour)}},
		Capabilities: []string{"backup.request"},
		SampledAt:    at,
	}
}

func servedReport(t *testing.T, r status.Report) string {
	t.Helper()
	w := serve(t, status.Handler(&fakeSource{report: r}, allow), http.MethodGet, status.StatusPath, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	return w.Body.String()
}

func TestReportSchema_AcceptsWhatHandlerWrites(t *testing.T) {
	s := compile(t, "v1.json", status.ReportSchema)
	for name, r := range map[string]status.Report{
		"every field": fullReport(),
		"bare":        {App: status.App{ID: "example-app", Name: "Example", Version: "1.0.0"}, Instance: status.Instance{ID: "1", Name: "Tower"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validate(t, s, servedReport(t, r)); err != nil {
				t.Errorf("schema refuses the report: %v", err)
			}
		})
	}
}

func TestReportSchema_RefusesWhatBreaksTheContract(t *testing.T) {
	s := compile(t, "v1.json", status.ReportSchema)
	tests := []struct {
		name  string
		spoil func(m map[string]any)
	}{
		{"unknown state", func(m map[string]any) { m["state"] = "attention" }},
		{"other contract", func(m map[string]any) { m["contract"] = 2 }},
		{"extra field", func(m map[string]any) { m["token"] = "x" }},
		{"missing app", func(m map[string]any) { delete(m, "app") }},
		{"upper-case app id", func(m map[string]any) { m["app"].(map[string]any)["id"] = "Example" }},
		{"time without a zone", func(m map[string]any) { m["sampledAt"] = "2026-11-09 10:05" }},
		{"progress above one", func(m map[string]any) { m["work"].([]any)[0].(map[string]any)["progress"] = 1.5 }},
		{"unknown work kind", func(m map[string]any) { m["work"].([]any)[0].(map[string]any)["kind"] = "copy" }},
		{"unknown severity", func(m map[string]any) { m["needsYou"].([]any)[0].(map[string]any)["severity"] = "fatal" }},
		{"need without text", func(m map[string]any) { m["needsYou"].([]any)[0].(map[string]any)["text"] = "" }},
		{"negative count", func(m map[string]any) { m["counts"].(map[string]any)["work"] = -1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal([]byte(servedReport(t, fullReport())), &m); err != nil {
				t.Fatal(err)
			}
			tt.spoil(m)
			body, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if validate(t, s, string(body)) == nil {
				t.Errorf("schema accepts %s", body)
			}
		})
	}
}

func TestLogSchema(t *testing.T) {
	s := compile(t, "log-v1.json", status.LogSchema)
	page := status.LogPage{
		Entries: []status.LogEntry{{ID: "41", At: time.Date(2026, 11, 9, 3, 0, 0, 0, time.UTC), Level: status.SeverityError, Code: "run.failed", Text: "The backup failed.", Link: "/runs/41"}},
		Next:    "41",
	}
	w := serve(t, status.Handler(&fakeSource{page: page}, allow), http.MethodGet, status.LogPath, nil)
	if err := validate(t, s, w.Body.String()); err != nil {
		t.Errorf("schema refuses the page: %v", err)
	}
	for _, bad := range []string{
		`{"entries":null,"next":""}`,
		`{"entries":[],"next":"","more":true}`,
		`{"entries":[{"id":"1","at":"2026-11-09T03:00:00Z","level":"debug","code":"x","text":"y"}],"next":"1"}`,
		`{"entries":[{"id":"1","at":"yesterday","level":"info","code":"x","text":"y"}],"next":"1"}`,
	} {
		if validate(t, s, bad) == nil {
			t.Errorf("schema accepts %s", bad)
		}
	}
}
