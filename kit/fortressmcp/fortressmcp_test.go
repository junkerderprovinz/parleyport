package fortressmcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/goleak"

	"github.com/junkerderprovinz/parleyport/kit/fortress"
	"github.com/junkerderprovinz/parleyport/kit/fortressmcp"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/status"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// fake is a fortress as the tools see it. Every member's ActAction runs the
// action in offers, for a caller of the app "notes" on the device "Desk".
type fake struct {
	mu      sync.Mutex
	members []fortress.Member
	reports map[string]status.Report
	logs    map[string][]status.LogEntry
	offers  map[string]fortress.Action
	off     map[string]bool
	acts    []string
}

func newFake(members ...fortress.Member) *fake {
	return &fake{
		members: members,
		reports: map[string]status.Report{},
		logs:    map[string][]status.LogEntry{},
		offers:  map[string]fortress.Action{},
		off:     map[string]bool{},
	}
}

func (f *fake) Members() []fortress.Member {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.members)
}

func (f *fake) Status(_ context.Context, id, _ string) (status.Report, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.reports[id]
	if !ok {
		return status.Report{}, &fortress.Refusal{Status: 404, Code: "not_found"}
	}
	return r, nil
}

// Log pages through the member's entries with the index of the last one read
// as the cursor.
func (f *fake) Log(_ context.Context, id string, q status.LogQuery) (status.LogPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entries := f.logs[id]
	start := 0
	if q.After != "" {
		n, _ := strconv.Atoi(q.After)
		start = n + 1
	}
	end := min(start+min(q.Limit, status.MaxLogLimit), len(entries))
	if start >= end {
		return status.LogPage{Entries: []status.LogEntry{}, Next: q.After}, nil
	}
	return status.LogPage{Entries: slices.Clone(entries[start:end]), Next: strconv.Itoa(end - 1)}, nil
}

func (f *fake) Act(ctx context.Context, id, action string, body []byte) ([]byte, error) {
	f.mu.Lock()
	a, ok := f.offers[id]
	off := f.off[id]
	f.acts = append(f.acts, id)
	f.mu.Unlock()
	switch {
	case action != fortressmcp.ActAction || !ok:
		return nil, fortress.ErrNoSuchAction
	case off:
		return nil, fortress.ErrPermissionOff
	}
	out, err := a.Run(ctx, fortress.Caller{ID: "me", App: "notes", Device: "Desk"}, body)
	var no *fortress.Refusal
	if errors.As(err, &no) {
		return nil, &fortress.Refusal{Status: 409, Code: no.Code}
	}
	return out, err
}

func (f *fake) setOff(id string, off bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.off[id] = off
}

func (f *fake) actsAt() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.acts)
}

func instance(id, app, device string, online bool, actions ...string) fortress.Member {
	return fortress.Member{
		ID: id, Kind: member.KindInstance, Device: device, Deployment: "container",
		App:     fortress.App{ID: app, Name: strings.ToUpper(app[:1]) + app[1:], Version: "1.2.0"},
		Address: "http://192.168.1.20:8080", Relay: online,
		LastSeen: time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC),
		Actions:  actions,
	}
}

type callerKey struct{}

func callerFrom(ctx context.Context) (fortress.Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(fortress.Caller)
	return c, ok
}

// target is the server of an app with a tool it offers to the fortress,
// drop, and two it keeps to itself. drop answers with the caller its app let
// in and refuses an empty path with a tool error of its own.
func target() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "files", Version: "1.2.0"}, nil)
	schema := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           map[string]any{"path": map[string]any{"type": "string", "description": "What to drop."}},
		"required":             []string{"path"},
	}
	srv.AddTool(&mcp.Tool{Name: "drop", Title: "Drop a file", Description: "Drops a file.", InputSchema: schema},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			from, ok := callerFrom(ctx)
			if !ok {
				return toolError("not_permitted", "nobody let this call in"), nil
			}
			var in struct {
				Path string `json:"path"`
			}
			dec := json.NewDecoder(bytes.NewReader(req.Params.Arguments))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&in); err != nil {
				return toolError("invalid_arguments", err.Error()), nil
			}
			if in.Path == "" {
				return toolError("empty_path", "say which file"), nil
			}
			out := map[string]any{"dropped": in.Path, "for": from.App + "@" + from.Device}
			text, _ := json.Marshal(out)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(text)}}, StructuredContent: out}, nil
		})
	for _, name := range []string{"wipe", "peek"} {
		srv.AddTool(&mcp.Tool{Name: name, Description: name, InputSchema: map[string]any{"type": "object"}},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ran"}}}, nil
			})
	}
	return srv
}

func toolError(code, msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError:           true,
		Content:           []mcp.Content{&mcp.TextContent{Text: code + ": " + msg}},
		StructuredContent: map[string]any{"error": map[string]any{"code": code, "message": msg}},
	}
}

// enter lets every app in but "blocked", and hands the tools the caller.
func enter(ctx context.Context, from fortress.Caller) (context.Context, error) {
	if from.App == "blocked" {
		return nil, &fortress.Refusal{Code: "not_allowed_here"}
	}
	return context.WithValue(ctx, callerKey{}, from), nil
}

func offer(f *fake, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.offers[id] = fortressmcp.Offer(target(), []string{"drop"}, enter)
}

type mayActKey struct{}

// harness is the server of this instance's app with the fortress tools on
// it, and a client connected to it.
type harness struct {
	client *mcp.ClientSession
	mu     sync.Mutex
	called []string
}

func connect(t *testing.T, f fortressmcp.Fortress, mayAct bool) *harness {
	t.Helper()
	h := &harness{}
	srv := mcp.NewServer(&mcp.Implementation{Name: "notes", Version: "1.0.0"}, nil)
	srv.AddTool(&mcp.Tool{Name: "get_notes", Description: "Notes.", InputSchema: map[string]any{"type": "object"}},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "none"}}}, nil
		})
	fortressmcp.Add(srv, fortressmcp.Config{
		Fortress: func() fortressmcp.Fortress { return f },
		MayAct:   func(ctx context.Context) bool { v, _ := ctx.Value(mayActKey{}).(bool); return v },
		Called: func(_ context.Context, tool, outcome string) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.called = append(h.called, tool+" "+outcome)
		},
	})
	ctx := context.WithValue(context.Background(), mayActKey{}, mayAct)
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "assistant", Version: "1.0.0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cs.Close()
		_ = ss.Wait()
	})
	h.client = cs
	return h
}

func (h *harness) calls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.called)
}

func (h *harness) call(t *testing.T, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	params := &mcp.CallToolParams{Name: name}
	if args != nil {
		params.Arguments = args
	}
	res, err := h.client.CallTool(ctx, params)
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	return res
}

func (h *harness) tools(t *testing.T) map[string]*mcp.Tool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out := map[string]*mcp.Tool{}
	for tool, err := range h.client.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		out[tool.Name] = tool
	}
	return out
}

func text(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("result has %d content blocks, want 1", len(res.Content))
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("result content is %T, want text", res.Content[0])
	}
	return tc.Text
}

func decode(t *testing.T, res *mcp.CallToolResult, v any) {
	t.Helper()
	if res.IsError {
		t.Fatalf("the tool answered an error: %s", text(t, res))
	}
	if err := json.Unmarshal([]byte(text(t, res)), v); err != nil {
		t.Fatal(err)
	}
}

func errorCode(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if !res.IsError {
		t.Fatalf("the tool answered %s, want an error", text(t, res))
	}
	content, _ := res.StructuredContent.(map[string]any)
	body, _ := content["error"].(map[string]any)
	code, _ := body["code"].(string)
	return code
}

func noAddress(t *testing.T, s string) {
	t.Helper()
	for _, part := range []string{"192.168.1.20", "8080", "http"} {
		if strings.Contains(s, part) {
			t.Errorf("the answer gives away an address (%s): %s", part, s)
		}
	}
}

func TestMembersShowAppNameDeviceAndReachButNoAddress(t *testing.T) {
	viewer := instance("v1", "tile", "Phone", true)
	viewer.Kind = member.KindViewer
	f := newFake(instance("a1", "files", "Tower", true, fortressmcp.ActAction), instance("b1", "jobs", "Cellar", false), viewer)
	h := connect(t, f, false)

	res := h.call(t, "fortress_members", nil)
	noAddress(t, text(t, res))
	var got struct {
		Members []struct {
			ID, App, Name, Version, Device, Kind, State string
			Tools                                       bool
		}
	}
	decode(t, res, &got)
	if len(got.Members) != 3 {
		t.Fatalf("members: %+v, want three", got.Members)
	}
	files, jobs, tile := got.Members[0], got.Members[1], got.Members[2]
	if files.ID != "a1" || files.App != "files" || files.Name != "Files" || files.Version != "1.2.0" ||
		files.Device != "Tower" || files.Kind != "instance" || files.State != "connected" || !files.Tools {
		t.Errorf("files reads %+v", files)
	}
	if jobs.State != "unreachable" || jobs.Tools {
		t.Errorf("jobs reads %+v, want unreachable without tools", jobs)
	}
	if tile.Kind != "viewer" {
		t.Errorf("tile reads %+v, want a viewer", tile)
	}
	if c := h.calls(); !slices.Equal(c, []string{"fortress_members ok"}) {
		t.Errorf("Called saw %v", c)
	}
}

func TestWithoutAFortressTheToolsSaySo(t *testing.T) {
	h := connect(t, nil, true)
	for _, name := range []string{"fortress_members", "fortress_status", "fortress_log"} {
		if code := errorCode(t, h.call(t, name, nil)); code != "no_fortress" {
			t.Errorf("%s outside a fortress: %q, want no_fortress", name, code)
		}
	}
}

func TestStatusReadsEveryConnectedMemberAndLeavesLinksOut(t *testing.T) {
	f := newFake(instance("a1", "files", "Tower", true), instance("c1", "jobs", "Attic", false), instance("b1", "jobs", "Cellar", true))
	progress := 0.5
	f.reports["a1"] = status.Report{
		App:      status.App{ID: "files", Name: "Files", Version: "1.2.0", UI: "http://192.168.1.20:8080/"},
		State:    status.StateWarning,
		NeedsYou: []status.Need{{ID: "n", Severity: status.SeverityWarn, Code: "copy.old", Text: "The copy is old.", Link: "http://192.168.1.20:8080/copies"}},
		Work:     []status.Task{{ID: "w", Kind: status.KindBackup, Title: "Backing up", Progress: &progress}},
		Next:     []status.Scheduled{{Kind: status.KindCheck, Title: "Check", At: time.Date(2026, 11, 12, 3, 0, 0, 0, time.UTC)}},
	}
	f.reports["b1"] = status.Report{App: status.App{ID: "jobs", Name: "Jobs"}, State: status.StateOK}
	h := connect(t, f, false)

	res := h.call(t, "fortress_status", nil)
	noAddress(t, text(t, res))
	var got struct {
		Members []struct {
			App, Device, State string
			Report             *struct {
				State    string
				NeedsYou []struct{ Severity, Code, Text string }
				Work     []struct {
					Kind, Title string
					Progress    float64
				}
				Next []struct{ Kind, Title string }
			}
		}
	}
	decode(t, res, &got)
	if len(got.Members) != 3 {
		t.Fatalf("status of %d members, want 3: %s", len(got.Members), text(t, res))
	}
	files := got.Members[0]
	if files.State != "connected" || files.Report == nil || files.Report.State != "warning" ||
		len(files.Report.NeedsYou) != 1 || files.Report.NeedsYou[0].Text != "The copy is old." ||
		len(files.Report.Work) != 1 || files.Report.Work[0].Progress != 0.5 || len(files.Report.Next) != 1 {
		t.Errorf("files reads %+v", files)
	}
	attic := got.Members[1]
	if attic.Device != "Attic" || attic.State != "unreachable" || attic.Report != nil {
		t.Errorf("the unreachable member reads %+v", attic)
	}

	res = h.call(t, "fortress_status", map[string]any{"app": "jobs", "device": "cellar"})
	decode(t, res, &got)
	if len(got.Members) != 1 || got.Members[0].Device != "Cellar" || got.Members[0].Report.State != "ok" {
		t.Errorf("jobs on Cellar reads %s", text(t, res))
	}
}

func TestLogShowsTheLatestEntriesOfEveryMemberNewestFirst(t *testing.T) {
	f := newFake(instance("a1", "files", "Tower", true), instance("c1", "jobs", "Attic", false), instance("b1", "jobs", "Cellar", true))
	start := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	for i := range 450 {
		f.logs["a1"] = append(f.logs["a1"], status.LogEntry{
			ID: strconv.Itoa(i), At: start.Add(time.Duration(2*i) * time.Minute), Level: status.SeverityInfo,
			Code: "run.done", Text: fmt.Sprintf("files ran %d", i), Link: "http://192.168.1.20:8080/runs",
		})
	}
	f.logs["b1"] = []status.LogEntry{{ID: "1", At: start.Add(897 * time.Minute), Level: status.SeverityError, Code: "job.failed", Text: "jobs failed"}}
	h := connect(t, f, false)

	res := h.call(t, "fortress_log", map[string]any{"limit": 3})
	noAddress(t, text(t, res))
	var got struct {
		Entries []struct {
			App, Device, Level, Code, Text string
			At                             time.Time
		}
		Unreachable []struct{ App, Device string }
	}
	decode(t, res, &got)
	var texts []string
	for _, e := range got.Entries {
		texts = append(texts, e.App+"@"+e.Device+": "+e.Text)
	}
	want := []string{"files@Tower: files ran 449", "jobs@Cellar: jobs failed", "files@Tower: files ran 448"}
	if !slices.Equal(texts, want) {
		t.Errorf("log reads %v, want %v", texts, want)
	}
	if len(got.Unreachable) != 1 || got.Unreachable[0].Device != "Attic" {
		t.Errorf("unreachable: %+v, want Attic", got.Unreachable)
	}

	res = h.call(t, "fortress_log", map[string]any{"app": "jobs"})
	decode(t, res, &got)
	if len(got.Entries) != 1 || got.Entries[0].Text != "jobs failed" {
		t.Errorf("the log of jobs reads %s", text(t, res))
	}
}

func TestToolsOfferedThroughTheFortressAreListedUnderTheirApp(t *testing.T) {
	f := newFake(
		instance("a1", "files", "Tower", true, fortressmcp.ActAction),
		instance("b1", "jobs", "Cellar", true, fortressmcp.ActAction),
		instance("c1", "maps", "Attic", true),
		instance("d1", "docs", "Shed", false, fortressmcp.ActAction),
	)
	for _, id := range []string{"a1", "b1", "d1"} {
		offer(f, id)
	}
	f.setOff("b1", true)
	h := connect(t, f, true)

	tools := h.tools(t)
	for _, name := range []string{"get_notes", "fortress_members", "fortress_status", "fortress_log", "files_drop"} {
		if tools[name] == nil {
			t.Errorf("%s is not listed", name)
		}
	}
	for _, name := range []string{"files_wipe", "files_peek", "jobs_drop", "docs_drop"} {
		if tools[name] != nil {
			t.Errorf("%s is listed", name)
		}
	}
	drop := tools["files_drop"]
	if drop == nil {
		t.FailNow()
	}
	if !strings.Contains(drop.Description, "Files") || !strings.HasSuffix(drop.Description, "Drops a file.") || !strings.Contains(drop.Title, "Drop a file") {
		t.Errorf("files_drop reads %q, %q", drop.Title, drop.Description)
	}
	schema, _ := drop.InputSchema.(map[string]any)
	props, _ := schema["properties"].(map[string]any)
	if props["path"] == nil || props["device"] == nil {
		t.Errorf("files_drop takes %v, want path and device", props)
	}
	if req, _ := schema["required"].([]any); len(req) != 1 || req[0] != "path" {
		t.Errorf("files_drop requires %v, want only path while one device runs files", schema["required"])
	}
	for _, id := range f.actsAt() {
		if id == "c1" || id == "d1" {
			t.Errorf("%s was asked for its tools", id)
		}
	}
}

func TestACallRunsAtTheMemberThatOffersTheTool(t *testing.T) {
	f := newFake(instance("a1", "files", "Tower", true, fortressmcp.ActAction))
	offer(f, "a1")
	h := connect(t, f, true)

	res := h.call(t, "files_drop", map[string]any{"path": "notes.txt", "device": "Tower"})
	var got struct{ Dropped, For string }
	decode(t, res, &got)
	if got.Dropped != "notes.txt" || got.For != "notes@Desk" {
		t.Errorf("files_drop answered %+v", got)
	}

	if code := errorCode(t, h.call(t, "files_drop", map[string]any{"path": ""})); code != "empty_path" {
		t.Errorf("the tool's own error came back as %q, want empty_path", code)
	}
	if code := errorCode(t, h.call(t, "files_drop", map[string]any{"path": "a", "size": 1})); code != "invalid_arguments" {
		t.Errorf("an argument the tool does not take came back as %q, want invalid_arguments", code)
	}
	if c := h.calls(); !slices.Equal(c, []string{"files_drop ok", "files_drop empty_path", "files_drop invalid_arguments"}) {
		t.Errorf("Called saw %v", c)
	}
}

func TestTheMemberDecidesWhoGetsIn(t *testing.T) {
	f := newFake(instance("a1", "files", "Tower", true, fortressmcp.ActAction))
	var entered atomic.Int32
	f.offers["a1"] = fortressmcp.Offer(target(), []string{"drop"}, func(ctx context.Context, from fortress.Caller) (context.Context, error) {
		if entered.Add(1) > 1 {
			return nil, &fortress.Refusal{Code: "budget_spent"}
		}
		return enter(ctx, from)
	})
	h := connect(t, f, true)
	if h.tools(t)["files_drop"] == nil {
		t.Fatal("files_drop is not listed")
	}
	if code := errorCode(t, h.call(t, "files_drop", map[string]any{"path": "a"})); code != "budget_spent" {
		t.Errorf("a call the member refused: %q, want budget_spent", code)
	}
}

func TestAClientThatMayOnlyReadCannotCallAnotherAppsTools(t *testing.T) {
	f := newFake(instance("a1", "files", "Tower", true, fortressmcp.ActAction))
	offer(f, "a1")
	h := connect(t, f, false)
	if h.tools(t)["files_drop"] == nil {
		t.Fatal("files_drop is not listed")
	}
	before := len(f.actsAt())
	if code := errorCode(t, h.call(t, "files_drop", map[string]any{"path": "a"})); code != "not_permitted" {
		t.Errorf("a client that may only read called files_drop: %q, want not_permitted", code)
	}
	if after := len(f.actsAt()); after != before {
		t.Errorf("the member was asked %d times for a call that may not run", after-before)
	}
}

func TestWithTwoDevicesACallNamesOne(t *testing.T) {
	f := newFake(
		instance("a1", "files", "Tower", true, fortressmcp.ActAction),
		instance("a2", "files", "Cellar", true, fortressmcp.ActAction),
	)
	offer(f, "a1")
	offer(f, "a2")
	h := connect(t, f, true)

	drop := h.tools(t)["files_drop"]
	if drop == nil {
		t.Fatal("files_drop is not listed")
	}
	schema, _ := drop.InputSchema.(map[string]any)
	if req, _ := schema["required"].([]any); !slices.Contains(req, any("device")) {
		t.Errorf("files_drop requires %v, want device as two devices run files", schema["required"])
	}
	if code := errorCode(t, h.call(t, "files_drop", map[string]any{"path": "a"})); code != "device_needed" {
		t.Errorf("a call without a device: %q, want device_needed", code)
	}
	if code := errorCode(t, h.call(t, "files_drop", map[string]any{"path": "a", "device": "Garage"})); code != "unknown_device" {
		t.Errorf("a call on a device nobody runs: %q, want unknown_device", code)
	}
	before := len(f.actsAt())
	h.call(t, "files_drop", map[string]any{"path": "a", "device": "cellar"})
	h.call(t, "files_drop", map[string]any{"path": "b", "device": "a1"})
	if acts := f.actsAt()[before:]; !slices.Equal(acts, []string{"a2", "a1"}) {
		t.Errorf("the calls went to %v, want a2 then a1", acts)
	}
}

func TestAPermissionSwitchedOffRefusesTheCall(t *testing.T) {
	f := newFake(instance("a1", "files", "Tower", true, fortressmcp.ActAction))
	offer(f, "a1")
	h := connect(t, f, true)
	if h.tools(t)["files_drop"] == nil {
		t.Fatal("files_drop is not listed")
	}
	f.setOff("a1", true)
	if code := errorCode(t, h.call(t, "files_drop", map[string]any{"path": "a"})); code != "permission_off" {
		t.Errorf("a call with the permission off: %q, want permission_off", code)
	}
}

func TestAMemberGoneQuietCannotBeCalled(t *testing.T) {
	f := newFake(instance("a1", "files", "Tower", true, fortressmcp.ActAction))
	offer(f, "a1")
	h := connect(t, f, true)
	if h.tools(t)["files_drop"] == nil {
		t.Fatal("files_drop is not listed")
	}
	f.mu.Lock()
	f.members[0].Relay = false
	f.mu.Unlock()
	if code := errorCode(t, h.call(t, "files_drop", map[string]any{"path": "a"})); code != "unreachable" {
		t.Errorf("a call at a member that went away: %q, want unreachable", code)
	}
	if h.tools(t)["files_drop"] != nil {
		t.Error("files_drop is still listed after its member went away")
	}
}

func TestOfferRunsOnlyTheToolsItNames(t *testing.T) {
	a := fortressmcp.Offer(target(), []string{"drop"}, enter)
	if a.Name != fortressmcp.ActAction {
		t.Errorf("the action is called %q, want %q", a.Name, fortressmcp.ActAction)
	}
	from := fortress.Caller{ID: "me", App: "notes", Device: "Desk"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := a.Run(ctx, from, nil)
	if err != nil {
		t.Fatal(err)
	}
	var list struct{ Tools []mcp.Tool }
	if err := json.Unmarshal(out, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Tools) != 1 || list.Tools[0].Name != "drop" {
		t.Errorf("the offer lists %s, want drop alone", out)
	}

	for _, body := range []string{`{"tool":"wipe"}`, `{"tool":"peek","arguments":{}}`} {
		var no *fortress.Refusal
		if _, err := a.Run(ctx, from, []byte(body)); !errors.As(err, &no) || no.Code != "no_such_tool" {
			t.Errorf("%s: %v, want no_such_tool", body, err)
		}
	}
	var no *fortress.Refusal
	if _, err := a.Run(ctx, from, []byte("not json")); !errors.As(err, &no) || no.Code != "bad_request" {
		t.Errorf("a broken body: %v, want bad_request", err)
	}
	if _, err := a.Run(ctx, fortress.Caller{App: "blocked"}, nil); !errors.As(err, &no) || no.Code != "not_allowed_here" {
		t.Errorf("an app the member keeps out listed its tools: %v", err)
	}
}
