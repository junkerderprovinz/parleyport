package fortressmcp

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/junkerderprovinz/parleyport/kit/fortress"
	"github.com/junkerderprovinz/parleyport/kit/member"
)

const (
	// listEvery is how long the tools a member listed are taken as they
	// are, and listTimeout how long it may take to list them.
	listEvery   = time.Minute
	listTimeout = 5 * time.Second
	// deviceArg is the argument a forwarded tool takes to name the device
	// it runs on, and which the member never sees.
	deviceArg = "device"
)

// offered is what one member last listed of its tools.
type offered struct {
	version string
	at      time.Time
	tools   []*mcp.Tool
}

// route is a tool of another app as this server lists it, and the members
// that run it, as Members sorts them.
type route struct {
	tool    *mcp.Tool
	name    string
	app     fortress.App
	members []fortress.Member
}

// offering are the members that may have tools for this server: connected
// instances that offer ActAction.
func offering(f Fortress) []fortress.Member {
	var out []fortress.Member
	for _, m := range f.Members() {
		if m.Kind == member.KindInstance && m.Online() && slices.Contains(m.Actions, ActAction) {
			out = append(out, m)
		}
	}
	return out
}

// routes are the tools the connected members offer, by name. A member is
// asked again once its list is older than listEvery or its app changed
// version.
func (h *hall) routes(ctx context.Context) []*route {
	f := h.fortress()
	if f == nil {
		return nil
	}
	ms := offering(f)
	h.ask(ctx, f, ms)
	byName := map[string]*route{}
	h.mu.Lock()
	for _, m := range ms {
		for _, t := range h.offers[m.ID].tools {
			name := m.App.ID + "_" + t.Name
			r := byName[name]
			if r == nil {
				r = &route{tool: t, name: t.Name, app: m.App}
				byName[name] = r
			}
			r.members = append(r.members, m)
		}
	}
	h.mu.Unlock()
	out := make([]*route, 0, len(byName))
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		r := byName[name]
		if tool := forwarded(name, r); tool != nil {
			r.tool = tool
			out = append(out, r)
		}
	}
	return out
}

// route is the tool of another app called name. Only a name that starts
// with the app of a member offering tools makes it ask the members.
func (h *hall) route(ctx context.Context, name string) (*route, bool) {
	f := h.fortress()
	if f == nil {
		return nil, false
	}
	app, _, found := strings.Cut(name, "_")
	if !found || !slices.ContainsFunc(f.Members(), func(m fortress.Member) bool {
		return m.App.ID == app && slices.Contains(m.Actions, ActAction)
	}) {
		return nil, false
	}
	for _, r := range h.routes(ctx) {
		if r.tool.Name == name {
			return r, true
		}
	}
	// A tool whose members all went away is still theirs, and the call
	// learns that nobody runs it now.
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range f.Members() {
		if m.App.ID != app {
			continue
		}
		for _, t := range h.offers[m.ID].tools {
			if app+"_"+t.Name == name {
				return &route{tool: &mcp.Tool{Name: name}, name: t.Name, app: m.App}, true
			}
		}
	}
	return nil, false
}

// ask lists the tools of every member in ms whose list is out of date, side
// by side, and forgets the lists of members that left the fortress. A member
// that does not answer, or does not let this app in, lists none until it is
// asked again.
func (h *hall) ask(ctx context.Context, f Fortress, ms []fortress.Member) {
	h.refresh.Lock()
	defer h.refresh.Unlock()
	now := time.Now()
	h.mu.Lock()
	var stale []fortress.Member
	for _, m := range ms {
		o, ok := h.offers[m.ID]
		if !ok || o.version != m.App.Version || now.Sub(o.at) >= listEvery {
			stale = append(stale, m)
		}
	}
	h.mu.Unlock()

	var wg sync.WaitGroup
	lists := make([][]*mcp.Tool, len(stale))
	for i, m := range stale {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, listTimeout)
			defer cancel()
			lists[i] = list(ctx, f, m.ID)
		})
	}
	wg.Wait()

	h.mu.Lock()
	defer h.mu.Unlock()
	for i, m := range stale {
		h.offers[m.ID] = offered{version: m.App.Version, at: now, tools: lists[i]}
	}
	all := f.Members()
	for id := range h.offers {
		if !slices.ContainsFunc(all, func(m fortress.Member) bool { return m.ID == id }) {
			delete(h.offers, id)
		}
	}
}

func list(ctx context.Context, f Fortress, id string) []*mcp.Tool {
	out, err := f.Act(ctx, id, ActAction, nil)
	if err != nil {
		return nil
	}
	var answer listAnswer
	if json.Unmarshal(out, &answer) != nil {
		return nil
	}
	return answer.Tools
}

// forwarded is the tool r runs, named name, with the device argument added.
// A tool that takes a device argument of its own cannot have it added and is
// left out, as is one whose schema is no object.
func forwarded(name string, r *route) *mcp.Tool {
	var input map[string]any
	raw, err := json.Marshal(r.tool.InputSchema)
	if err != nil || json.Unmarshal(raw, &input) != nil || input["type"] != "object" {
		return nil
	}
	props, _ := input["properties"].(map[string]any)
	if _, taken := props[deviceArg]; taken {
		return nil
	}
	props = maps.Clone(props)
	if props == nil {
		props = map[string]any{}
	}
	appName := r.appName()
	var devices []string
	for _, m := range r.members {
		devices = append(devices, m.Device)
	}
	note := fmt.Sprintf("The device whose %s runs this, as fortress_members names it.", appName)
	if len(devices) > 1 {
		note += fmt.Sprintf(" Needed while more than one device runs %s: %s.", appName, strings.Join(devices, ", "))
	}
	props[deviceArg] = map[string]any{"type": "string", "description": note}
	input["properties"] = props
	if len(devices) > 1 {
		required, _ := input["required"].([]any)
		input["required"] = append(slices.Clone(required), deviceArg)
	}

	tool := *r.tool
	tool.Name = name
	tool.InputSchema = input
	tool.Description = fmt.Sprintf("Runs in %s, another app in this fortress, which checks the call against its own rules and limits. %s",
		appName, r.tool.Description)
	tool.Title = fmt.Sprintf("%s (%s)", cmp.Or(r.tool.Title, r.tool.Name), appName)
	if r.tool.Annotations != nil {
		a := *r.tool.Annotations
		a.Title = tool.Title
		tool.Annotations = &a
	}
	return &tool
}

// call runs r for the client behind ctx at the member it picks.
func (h *hall) call(ctx context.Context, r *route, args json.RawMessage) *mcp.CallToolResult {
	if h.cfg.MayAct != nil && !h.cfg.MayAct(ctx) {
		return toolError("not_permitted", "This client may only read here, so it cannot use the tools of other apps.")
	}
	f := h.fortress()
	if f == nil {
		return noFortress()
	}
	var in map[string]json.RawMessage
	if len(args) > 0 && string(args) != "null" && json.Unmarshal(args, &in) != nil {
		return toolError("invalid_arguments", "The arguments are not a JSON object.")
	}
	var device string
	if raw, ok := in[deviceArg]; ok {
		if json.Unmarshal(raw, &device) != nil {
			return toolError("invalid_arguments", "device takes the name of a device as text.")
		}
		delete(in, deviceArg)
	}
	m, bad := r.pick(device)
	if bad != nil {
		return bad
	}
	body, err := json.Marshal(actRequest{Tool: r.name, Arguments: in})
	if err != nil {
		return toolError("invalid_arguments", err.Error())
	}
	out, err := f.Act(ctx, m.ID, ActAction, body)
	if err != nil {
		return refused(m, err)
	}
	var res mcp.CallToolResult
	if json.Unmarshal(out, &res) != nil {
		return toolError("bad_answer", fmt.Sprintf("%s on %s answered with something that is no tool result.", r.appName(), m.Device))
	}
	if res.Content == nil {
		res.Content = []mcp.Content{}
	}
	return &res
}

func (r *route) appName() string {
	return cmp.Or(r.app.Name, r.app.ID)
}

// pick is the member that runs r for a call naming device, which may be
// left out while only one member runs it.
func (r *route) pick(device string) (fortress.Member, *mcp.CallToolResult) {
	name := r.appName()
	if device != "" {
		for _, m := range r.members {
			if matches(m, device) {
				return m, nil
			}
		}
		return fortress.Member{}, toolError("unknown_device", fmt.Sprintf("No device called %q runs %s in this fortress right now.", device, name))
	}
	switch len(r.members) {
	case 0:
		return fortress.Member{}, toolError("unreachable", fmt.Sprintf("No device that runs %s can be reached right now.", name))
	case 1:
		return r.members[0], nil
	}
	var devices []string
	for _, m := range r.members {
		devices = append(devices, m.Device)
	}
	return fortress.Member{}, toolError("device_needed",
		fmt.Sprintf("More than one device runs %s: %s. Name one with device.", name, strings.Join(devices, ", ")))
}

// refused is the tool error for a call m did not run.
func refused(m fortress.Member, err error) *mcp.CallToolResult {
	name := cmp.Or(m.App.Name, m.App.ID)
	var no *fortress.Refusal
	switch {
	case errors.Is(err, fortress.ErrPermissionOff):
		return toolError("permission_off", fmt.Sprintf(
			"%s on %s does not let this app use its tools. The switch for it is with the fortress permissions.", name, m.Device))
	case errors.Is(err, fortress.ErrNoSuchAction):
		return toolError("no_such_tool", fmt.Sprintf("%s on %s does not offer its tools to the fortress.", name, m.Device))
	case errors.As(err, &no):
		return toolError(no.Code, fmt.Sprintf("%s on %s turned the call down: %s.", name, m.Device, no.Code))
	}
	return toolError("unreachable", fmt.Sprintf("%s on %s did not answer.", name, m.Device))
}
