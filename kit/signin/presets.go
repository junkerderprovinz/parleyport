package signin

import "net/http"

// Preset is what the server needs to know about one kind of sign-in
// service. The ids are those of the catalog in the user interface, which
// knows names and marks, so each default lives in one place.
type Preset struct {
	ID          string `json:"id"`
	Scopes      string `json:"scopes"`
	NameClaim   string `json:"nameClaim"`
	GroupsClaim string `json:"groupsClaim"`
	// ProxyUser and ProxyGroups are the headers the service sets when it
	// guards the app as a proxy, where it can.
	ProxyUser   string `json:"proxyUser,omitempty"`
	ProxyGroups string `json:"proxyGroups,omitempty"`
}

// Presets are the sign-in services the package knows, the app owner's own
// last.
var Presets = []Preset{
	{ID: "pocket-id", Scopes: "openid profile email groups", NameClaim: "preferred_username", GroupsClaim: "groups"},
	{ID: "authentik", Scopes: "openid profile email", NameClaim: "preferred_username", GroupsClaim: "groups", ProxyUser: "X-authentik-username", ProxyGroups: "X-authentik-groups"},
	{ID: "authelia", Scopes: "openid profile email groups", NameClaim: "preferred_username", GroupsClaim: "groups", ProxyUser: "Remote-User", ProxyGroups: "Remote-Groups"},
	// Keycloak reports groups only with a mapper on the client. Without one,
	// realm_access.roles carries the realm roles.
	{ID: "keycloak", Scopes: "openid profile email", NameClaim: "preferred_username", GroupsClaim: "groups"},
	// Kanidm names groups as name@domain, and the table takes them so.
	{ID: "kanidm", Scopes: "openid profile email groups", NameClaim: "preferred_username", GroupsClaim: "groups"},
	// Zitadel reports project roles as the keys of one object.
	{ID: "zitadel", Scopes: "openid profile email urn:zitadel:iam:org:project:roles", NameClaim: "preferred_username", GroupsClaim: "urn:zitadel:iam:org:project:roles"},
	{ID: "custom", Scopes: "openid profile email", NameClaim: "preferred_username", GroupsClaim: "groups"},
}

func preset(id string) (Preset, bool) {
	for _, p := range Presets {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

func (a *Auth) getPresets(w http.ResponseWriter, _ *http.Request, _ *found) {
	ok(w, map[string]any{"presets": Presets})
}
