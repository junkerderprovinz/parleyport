package legacy

import (
	"strings"

	"github.com/junkerderprovinz/parleyport/kit/notify"
)

// FromEnv reads the shell-style settings MATRIX_HOMESERVER, MATRIX_TOKEN,
// MATRIX_ROOM, APPRISE_URL (an Apprise key's endpoint) and UNRAID_NOTIFY
// ("true", "yes", "1" or "on"). Every message went to every channel, so each
// gets On always.
func FromEnv(vars map[string]string) []notify.Channel {
	get := func(key string) string { return strings.TrimSpace(vars[key]) }
	hs, token, room := get("MATRIX_HOMESERVER"), get("MATRIX_TOKEN"), get("MATRIX_ROOM")
	var out []notify.Channel
	if filled(hs, token, room) {
		out = append(out, notify.Channel{ID: "matrix", Kind: notify.KindMatrix, Enabled: all(hs, token, room), On: notify.OnAlways,
			Matrix: &notify.Matrix{Homeserver: hs, Room: room, Token: token}})
	}
	if u := get("APPRISE_URL"); u != "" {
		out = append(out, notify.Channel{ID: "apprise", Kind: notify.KindApprise, Enabled: true, On: notify.OnAlways,
			Apprise: &notify.Apprise{URL: u}})
	}
	switch strings.ToLower(get("UNRAID_NOTIFY")) {
	case "true", "yes", "1", "on":
		out = append(out, notify.Channel{ID: "unraid", Kind: notify.KindUnraid, Enabled: true, On: notify.OnAlways})
	}
	return settled(out)
}
