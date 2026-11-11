// Package fortressmcp brings a fortress into an app's MCP server, so an
// assistant set up with one app sees the whole household.
//
// Add gives the server three tools that only read: fortress_members,
// fortress_status and fortress_log. It also lists the tools the other members
// offer through ActAction, each under its app's name, such as files_drop for
// the tool drop of the app files, and hands a call to the member that offers
// it. That member runs the tool through its own server, with its own checks
// and budgets, for the caller the fortress names; Offer is its side. Whether
// one app may call another's tools at all is the fortress permission for
// ActAction, which the member checks.
package fortressmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/junkerderprovinz/parleyport/kit/fortress"
	"github.com/junkerderprovinz/parleyport/kit/status"
)

// ActAction is the fortress action a member offers its tools through. An app
// that calls them names it in fortress.Config.Uses, so its permission shows
// up in Permissions.
const ActAction = "mcp.act"

// Fortress is what the tools need of a *fortress.Fortress.
type Fortress interface {
	Members() []fortress.Member
	Status(ctx context.Context, id, lang string) (status.Report, error)
	Log(ctx context.Context, id string, q status.LogQuery) (status.LogPage, error)
	Act(ctx context.Context, id, action string, body []byte) ([]byte, error)
}

// Config is what Add needs from the app.
type Config struct {
	// Fortress is the fortress the instance is in now, nil while it is in
	// none.
	Fortress func() Fortress
	// MayAct reports whether the client a request came from may call the
	// tools of other members. The fortress tools that read are open to every
	// client. nil lets every client act.
	MayAct func(ctx context.Context) bool
	// Called, if set, learns of every call of a tool Add brought in, with
	// the tool's name and "ok" or the code of the error it answered.
	Called func(ctx context.Context, tool, outcome string)
}

// Add puts the fortress tools on srv and the tools the other members offer
// in its list. srv keeps its own tools as they are.
func Add(srv *mcp.Server, cfg Config) {
	h := &hall{cfg: cfg, offers: map[string]offered{}}
	for _, t := range h.readTools() {
		srv.AddTool(t.tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return h.done(ctx, t.tool.Name, t.run(ctx, req.Params.Arguments)), nil
		})
	}
	srv.AddReceivingMiddleware(h.middleware)
}

// hall is the fortress as one app's server shows it.
type hall struct {
	cfg Config

	// refresh is held while the members are asked for their tools, so that
	// requests arriving together ask once.
	refresh sync.Mutex
	mu      sync.Mutex
	offers  map[string]offered
}

func (h *hall) fortress() Fortress {
	if h.cfg.Fortress == nil {
		return nil
	}
	return h.cfg.Fortress()
}

// middleware adds the tools of the other members to the last page of the
// list and runs a call of one of them, leaving everything else to next.
func (h *hall) middleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		switch method {
		case "tools/list":
			res, err := next(ctx, method, req)
			list, ok := res.(*mcp.ListToolsResult)
			if err != nil || !ok || list.NextCursor != "" {
				return res, err
			}
			for _, r := range h.routes(ctx) {
				list.Tools = append(list.Tools, r.tool)
			}
			return list, nil
		case "tools/call":
			call, ok := req.(*mcp.CallToolRequest)
			if !ok || call.Params == nil {
				break
			}
			if r, found := h.route(ctx, call.Params.Name); found {
				return h.done(ctx, r.tool.Name, h.call(ctx, r, call.Params.Arguments)), nil
			}
		}
		return next(ctx, method, req)
	}
}

// done tells Called how a call went and hands back its result.
func (h *hall) done(ctx context.Context, tool string, res *mcp.CallToolResult) *mcp.CallToolResult {
	if h.cfg.Called != nil {
		outcome := "ok"
		if res.IsError {
			outcome = codeOf(res)
		}
		h.cfg.Called(ctx, tool, outcome)
	}
	return res
}

// ok answers with v as structured content and as the one text block, which
// is what a client that cannot read structured content shows.
func ok(v any) *mcp.CallToolResult {
	text, _ := json.Marshal(v)
	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: string(text)}},
		StructuredContent: v,
	}
}

func toolError(code, msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError:           true,
		Content:           []mcp.Content{&mcp.TextContent{Text: code + ": " + msg}},
		StructuredContent: map[string]any{"error": map[string]any{"code": code, "message": msg}},
	}
}

// codeOf is the code of a tool error, built here or by another member, or
// "error" for one that carries none.
func codeOf(res *mcp.CallToolResult) string {
	content, _ := res.StructuredContent.(map[string]any)
	body, _ := content["error"].(map[string]any)
	if code, _ := body["code"].(string); code != "" {
		return code
	}
	return "error"
}

func noFortress() *mcp.CallToolResult {
	return toolError("no_fortress", "This app has not joined a fortress, so there are no other apps to show.")
}

// decodeArgs reads a tool's arguments into v. An argument the tool does not
// take is refused, so a client learns that it was never read.
func decodeArgs(raw json.RawMessage, v any) *mcp.CallToolResult {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return toolError("invalid_arguments", strings.TrimPrefix(err.Error(), "json: "))
	}
	return nil
}
