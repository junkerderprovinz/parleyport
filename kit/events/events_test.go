package events_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/junkerderprovinz/parleyport/kit/events"
	"github.com/junkerderprovinz/parleyport/kit/status"
)

var kindTests = []struct {
	kind  events.Kind
	valid bool
}{
	{events.BackupFailed, true},
	{events.DownloadDone, true},
	{events.RunDone, true},
	{events.FileReceived, true},
	{"run.done_late", true},
	{"share.link.opened", true},
	{"backup", false},
	{"Backup.failed", false},
	{"backup..failed", false},
	{"backup.failed.", false},
	{".failed", false},
	{"backup.1failed", false},
	{"backup failed", false},
	{"", false},
}

func TestKind_Valid(t *testing.T) {
	for _, tt := range kindTests {
		t.Run(string(tt.kind), func(t *testing.T) {
			if got := tt.kind.Valid(); got != tt.valid {
				t.Errorf("Kind(%q).Valid() = %v, want %v", tt.kind, got, tt.valid)
			}
		})
	}
}

func schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(events.Schema))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("v1.json", doc); err != nil {
		t.Fatal(err)
	}
	return c.MustCompile("v1.json")
}

func validate(t *testing.T, s *jsonschema.Schema, v any) error {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	return s.Validate(inst)
}

func event() events.Event {
	return events.Event{
		ID:       "01JC8X",
		Kind:     events.BackupFailed,
		At:       time.Date(2026, 11, 9, 3, 0, 0, 0, time.UTC),
		Severity: status.SeverityError,
		Source:   events.Source{App: "example-app", Instance: "3f9c40"},
		Subject:  "web",
		Link:     "/runs/8812",
		Fields:   map[string]string{"run": "8812"},
		Depth:    1,
	}
}

func TestSchema_AcceptsEvents(t *testing.T) {
	s := schema(t)
	bare := events.Event{
		ID: "1", Kind: events.FileReceived, At: time.Now(), Severity: status.SeverityInfo,
		Source: events.Source{App: "example-app", Instance: "a1"},
	}
	for name, e := range map[string]events.Event{"every field": event(), "bare": bare} {
		t.Run(name, func(t *testing.T) {
			if err := validate(t, s, e); err != nil {
				t.Errorf("schema refuses the event: %v", err)
			}
		})
	}
}

func TestSchema_AgreesWithKindValid(t *testing.T) {
	s := schema(t)
	for _, tt := range kindTests {
		t.Run(string(tt.kind), func(t *testing.T) {
			e := event()
			e.Kind = tt.kind
			if accepted := validate(t, s, e) == nil; accepted != tt.valid {
				t.Errorf("schema accepts %q: %v, Valid says %v", tt.kind, accepted, tt.valid)
			}
		})
	}
}

func TestSchema_RefusesBrokenEvents(t *testing.T) {
	s := schema(t)
	tests := []struct {
		name  string
		spoil func(m map[string]any)
	}{
		{"no source", func(m map[string]any) { delete(m, "source") }},
		{"no instance", func(m map[string]any) { delete(m["source"].(map[string]any), "instance") }},
		{"unknown severity", func(m map[string]any) { m["severity"] = "fatal" }},
		{"negative depth", func(m map[string]any) { m["depth"] = -1 }},
		{"field that is not text", func(m map[string]any) { m["fields"] = map[string]any{"size": 12} }},
		{"time without a zone", func(m map[string]any) { m["at"] = "2026-11-09 03:00" }},
		{"extra field", func(m map[string]any) { m["text"] = "Backup failed" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(event())
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatal(err)
			}
			tt.spoil(m)
			if validate(t, s, m) == nil {
				t.Errorf("schema accepts %v", m)
			}
		})
	}
}
