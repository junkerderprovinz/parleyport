package fortress

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/member"
)

// ExportAction is the permission behind Export: an app that fetches backups
// lists it in Config.Uses, and switching it off keeps that app from fetching
// one here.
const ExportAction = "backup.export"

const exportPath = prefix + "export"

// Export fetches member id's backup, as its Config.Export hands it over. It
// goes only directly on this network; a member reachable through the relay
// alone gets group.ErrNotDirect. A read of the backup fails with
// group.ErrStreamBroken once it breaks off or does not match the length and
// SHA-256 the member signed, at the latest where it would end, so a damaged
// backup never reads as whole. The caller closes it.
func (f *Fortress) Export(ctx context.Context, id string) (io.ReadCloser, error) {
	status, body, err := f.group.Stream(ctx, id, exportPath)
	if err != nil {
		return nil, err
	}
	if status == http.StatusOK {
		return body, nil
	}
	defer func() { _ = body.Close() }()
	b, _ := io.ReadAll(body)
	return nil, refusal(status, b)
}

// serveExport hands this instance's backup to the member that asked, if its
// app may have it. The group calls it for streams alone, which come directly.
func (f *Fortress) serveExport(w http.ResponseWriter, r *http.Request) {
	caller, ok := group.CallerOf(r.Context())
	switch {
	case !ok || caller.Kind != member.KindInstance:
		writeError(w, http.StatusForbidden, "forbidden")
		return
	case r.URL.Path != exportPath || r.Method != http.MethodGet || f.export == nil:
		writeError(w, http.StatusNotFound, "no_such_action")
		return
	}
	from, ok := f.allowed(w, r, caller.ID, ExportAction)
	if !ok {
		return
	}
	backup, n, err := f.export(r.Context(), from)
	if err != nil {
		failed(w, r, ExportAction, from.App, err)
		return
	}
	defer func() { _ = backup.Close() }()
	w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
	if _, err := io.Copy(w, backup); err != nil {
		slog.WarnContext(r.Context(), "fortress: a backup export broke off", "app", from.App, "err", err)
	}
}
