package fortressmcp

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/junkerderprovinz/parleyport/kit/fortress"
)

// actRequest is the body of ActAction: a call of Tool with Arguments, or,
// without a tool, a request for the list.
type actRequest struct {
	Tool      string                     `json:"tool,omitempty"`
	Arguments map[string]json.RawMessage `json:"arguments,omitempty"`
}

type listAnswer struct {
	Tools []*mcp.Tool `json:"tools"`
}

// Enter lets a call from another member in. It returns ctx with whatever the
// app's tools check, such as the rights a call from that member has, or an
// error to keep it out; a *fortress.Refusal says no with a code of its own.
type Enter func(ctx context.Context, from fortress.Caller) (context.Context, error)

// Offer is the action that lets the other members call the tools of srv
// named in tools, and list them. Every call passes enter first and then runs
// through srv like a call of the app's own clients, so the tools check it as
// they check any other. srv should hold only the app's own tools.
func Offer(srv *mcp.Server, tools []string, enter Enter) fortress.Action {
	o := offer{srv: srv, tools: slices.Clone(tools), enter: enter}
	return fortress.Action{Name: ActAction, Run: o.run}
}

type offer struct {
	srv   *mcp.Server
	tools []string
	enter Enter
}

func (o offer) run(ctx context.Context, from fortress.Caller, body []byte) ([]byte, error) {
	var in actRequest
	if len(body) > 0 && json.Unmarshal(body, &in) != nil {
		return nil, &fortress.Refusal{Code: "bad_request"}
	}
	if in.Tool != "" && !slices.Contains(o.tools, in.Tool) {
		return nil, &fortress.Refusal{Code: "no_such_tool"}
	}
	inner, err := o.enter(ctx, from)
	if err != nil {
		return nil, err
	}
	session, done, err := o.connect(inner)
	if err != nil {
		return nil, err
	}
	defer done()
	if in.Tool == "" {
		answer := listAnswer{Tools: []*mcp.Tool{}}
		for t, err := range session.Tools(ctx, nil) {
			if err != nil {
				return nil, err
			}
			if slices.Contains(o.tools, t.Name) {
				answer.Tools = append(answer.Tools, t)
			}
		}
		return json.Marshal(answer)
	}
	params := &mcp.CallToolParams{Name: in.Tool}
	if in.Arguments != nil {
		params.Arguments = in.Arguments
	}
	res, err := session.CallTool(ctx, params)
	if err != nil {
		return nil, err
	}
	return json.Marshal(res)
}

// connect opens a session on srv whose calls run under ctx, which is where a
// tool finds what enter put there.
func (o offer) connect(ctx context.Context) (*mcp.ClientSession, func(), error) {
	st, ct := mcp.NewInMemoryTransports()
	ss, err := o.srv.Connect(ctx, st, nil)
	if err != nil {
		return nil, nil, err
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "fortress", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		_ = ss.Close()
		return nil, nil, err
	}
	return cs, func() {
		_ = cs.Close()
		_ = ss.Wait()
	}, nil
}
