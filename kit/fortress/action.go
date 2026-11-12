package fortress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/events"
	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/status"
)

// Action is something an app does when another member asks, such as
// starting a job or taking a backup.
type Action struct {
	// Name has the form a.b, such as "jobs.run".
	Name string
	// Run does it for from with the body the caller sent and returns the
	// answer. A *Refusal says no with a code the caller sees; the caller sees
	// any other error as "internal", and it is logged.
	Run func(ctx context.Context, from Caller, body []byte) ([]byte, error)
}

// Caller is the member an action runs for.
type Caller struct {
	ID     string
	App    string
	Device string
}

// Refusal is an answer that says no, with the code the other member or its
// app gave and the HTTP status it came with. An action's Run returns one to
// say no in its own words, with a Status from 400 to 599 or none for 409
// Conflict.
type Refusal struct {
	Status int
	Code   string
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("fortress: refused with %q (%d)", r.Code, r.Status)
}

// Errors of Act. Any other refusal is a *Refusal.
var (
	ErrPermissionOff = errors.New("fortress: the permission for this action is switched off")
	ErrNoSuchAction  = errors.New("fortress: the app does not offer this action")
	// ErrNotUsed is a call from an app that does not list the action in
	// Config.Uses, for which there is no permission to switch on. It is an
	// ErrPermissionOff as well.
	ErrNotUsed error = notUsed{}
)

type notUsed struct{}

func (notUsed) Error() string {
	return "fortress: the app does not say it uses this action, so no permission lets it run it"
}

func (notUsed) Is(target error) bool { return target == ErrPermissionOff }

// refusal reads the answer status with body as an error: the fortress's own
// codes and the group's, which name the code apart from the text.
func refusal(status int, body []byte) error {
	var answer struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	code := string(body)
	if json.Unmarshal(body, &answer) == nil {
		code = answer.Code
		if code == "" {
			code = answer.Error
		}
	}
	switch code {
	case "permission_off":
		return ErrPermissionOff
	case "no_such_action":
		return ErrNoSuchAction
	case "not_used":
		return ErrNotUsed
	case "stream_broken":
		return group.ErrStreamBroken
	}
	if len(code) > maxText {
		code = code[:maxText]
	}
	return &Refusal{Status: status, Code: code}
}

// Act asks member id to run action with body and returns its answer.
func (f *Fortress) Act(ctx context.Context, id, action string, body []byte) ([]byte, error) {
	if !validAction(action) {
		return nil, fmt.Errorf("fortress: %q is no action", action)
	}
	path := actPrefix + action
	if d := events.Depth(ctx); d > 0 {
		path += "?" + url.Values{"depth": {strconv.Itoa(d)}}.Encode()
	}
	status, out, err := f.group.Call(ctx, id, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, f.refused(id, status, out)
	}
	return out, nil
}

// refused is the refusal member id answered with. A member that says the
// phrase changed is asked again at once what it is, which tells NewKeys to
// ask it for the new keys.
func (f *Fortress) refused(id string, status int, body []byte) error {
	err := refusal(status, body)
	if no := (*Refusal)(nil); errors.As(err, &no) && no.Code == phraseChanged {
		f.again(f.described, id, time.Time{})
	}
	return err
}

// serveAction runs action for the member caller, if its app may.
func (f *Fortress) serveAction(w http.ResponseWriter, r *http.Request, caller, action string) {
	if !slices.Contains(f.about.Actions, action) {
		writeError(w, http.StatusNotFound, "no_such_action")
		return
	}
	from, ok := f.allowed(w, r, caller, action)
	if !ok {
		return
	}
	a, ok := f.actions[action]
	if !ok {
		writeError(w, http.StatusMisdirectedRequest, "stream_only")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx := r.Context()
	if d, err := strconv.Atoi(r.URL.Query().Get("depth")); err == nil && d > 0 {
		ctx = events.WithDepth(ctx, min(d, events.MaxDepth))
	}
	out, err := a.Run(ctx, from, body)
	if err != nil {
		failed(w, r, action, from.App, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// allowed is the member caller as an action runs for it, once its app may run
// action here. Otherwise it answers w with why not. An app runs only what it
// lists in Config.Uses, since Permissions has a switch for nothing else.
func (f *Fortress) allowed(w http.ResponseWriter, r *http.Request, caller, action string) (Caller, bool) {
	a := f.aboutOf(caller)
	if (a.App.ID == "" || !slices.Contains(a.Uses, action)) && f.describe(r.Context(), caller, time.Now()) {
		a = f.aboutOf(caller)
	}
	app := a.App.ID
	switch {
	case app == "":
		writeError(w, http.StatusForbidden, "unknown_app")
		return Caller{}, false
	case !slices.Contains(a.Uses, action):
		writeError(w, http.StatusForbidden, "not_used")
		return Caller{}, false
	case !f.permitted(app, action):
		writeError(w, http.StatusForbidden, "permission_off")
		return Caller{}, false
	}
	device := ""
	if m, ok := listed(f.group, caller); ok {
		device = m.Name
	}
	return Caller{ID: caller, App: app, Device: device}, true
}

// failed answers w for an action that returned err: a *Refusal with its code
// and status, anything else as "internal", which is logged.
func failed(w http.ResponseWriter, r *http.Request, action, app string, err error) {
	var no *Refusal
	if errors.As(err, &no) {
		status := no.Status
		if status < 400 || status > 599 {
			status = http.StatusConflict
		}
		writeError(w, status, no.Code)
		return
	}
	slog.ErrorContext(r.Context(), "fortress: an action failed", "action", action, "app", app, "err", err)
	writeError(w, http.StatusInternalServerError, "internal")
}

// Status reads member id's status report, its texts in lang if the app has
// them.
func (f *Fortress) Status(ctx context.Context, id, lang string) (status.Report, error) {
	path := status.StatusPath
	if lang != "" {
		path += "?" + url.Values{"lang": {lang}}.Encode()
	}
	var r status.Report
	body, err := f.get(ctx, id, path)
	if err == nil {
		err = json.Unmarshal(body, &r)
	}
	return r, err
}

// Log reads a page of member id's log.
func (f *Fortress) Log(ctx context.Context, id string, q status.LogQuery) (status.LogPage, error) {
	v := url.Values{}
	if q.After != "" {
		v.Set("after", q.After)
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.Lang != "" {
		v.Set("lang", q.Lang)
	}
	path := status.LogPath
	if len(v) > 0 {
		path += "?" + v.Encode()
	}
	var p status.LogPage
	body, err := f.get(ctx, id, path)
	if err == nil {
		err = json.Unmarshal(body, &p)
	}
	return p, err
}
