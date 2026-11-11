package fortress

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/member"
)

// ImportAction is the permission behind Import: an app that hands backups
// back lists it in Config.Uses. Unlike every other permission it is off until
// somebody switches it on, since an import replaces what the app holds.
const ImportAction = "backup.import"

const importPath = prefix + "import"

// Import hands member id a backup, n bytes long, as its Config.Import takes
// it. It goes only directly on this network; a member reachable through the
// relay alone gets group.ErrNotDirect. The backup goes out once the member's
// app starts to read it, so a refusal comes back without it. A backup that
// arrives damaged gives group.ErrStreamBroken and is not kept.
func (f *Fortress) Import(ctx context.Context, id string, backup io.Reader, n int64) error {
	status, body, err := f.group.Upload(ctx, id, importPath, backup, n)
	if err != nil {
		return err
	}
	if status == http.StatusNoContent {
		return nil
	}
	return refusal(status, body)
}

// serveImport hands a backup another member sent to the app, if that
// member's app may import here. The group calls it for uploads alone, which
// come directly.
func (f *Fortress) serveImport(w http.ResponseWriter, r *http.Request) {
	caller, ok := group.CallerOf(r.Context())
	switch {
	case !ok || caller.Kind != member.KindInstance:
		writeError(w, http.StatusForbidden, "forbidden")
		return
	case r.URL.Path != importPath || r.Method != http.MethodPost || f.importer == nil:
		writeError(w, http.StatusNotFound, "no_such_action")
		return
	}
	from, ok := f.allowed(w, r, caller.ID, ImportAction)
	if !ok {
		return
	}
	err := f.importer(r.Context(), from, r.Body, r.ContentLength)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, group.ErrStreamBroken):
		writeError(w, http.StatusBadRequest, "stream_broken")
	default:
		failed(w, r, ImportAction, from.App, err)
	}
}

// onByDefault reports whether the permission for action stands before anybody
// switched it.
func onByDefault(action string) bool {
	return action != ImportAction
}
