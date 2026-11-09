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
	"strconv"
	"time"

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
// say no in its own words.
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
)

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
	status, out, err := f.group.Call(ctx, id, http.MethodPost, actPrefix+action, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, refusal(status, out)
	}
	return out, nil
}

// serveAction runs action for the member caller, if its app may.
func (f *Fortress) serveAction(w http.ResponseWriter, r *http.Request, caller, action string) {
	a, ok := f.actions[action]
	if !ok {
		writeError(w, http.StatusNotFound, "no_such_action")
		return
	}
	app := f.appOf(caller)
	if app == "" && f.describe(r.Context(), caller, time.Now()) {
		app = f.appOf(caller)
	}
	if app == "" {
		writeError(w, http.StatusForbidden, "unknown_app")
		return
	}
	if !f.permitted(app, action) {
		writeError(w, http.StatusForbidden, "permission_off")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	device := ""
	if m, ok := listed(f.group, caller); ok {
		device = m.Name
	}
	out, err := a.Run(r.Context(), Caller{ID: caller, App: app, Device: device}, body)
	var no *Refusal
	switch {
	case errors.As(err, &no):
		writeError(w, http.StatusConflict, no.Code)
		return
	case err != nil:
		slog.ErrorContext(r.Context(), "fortress: an action failed", "action", action, "app", app, "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
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
