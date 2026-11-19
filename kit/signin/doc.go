// Package signin is the sign-in every app of the kit shares: password,
// two-factor, passkeys, sessions, API tokens, the reset through the
// container log, the sign-in log, sign-in services over OIDC and a trusted
// proxy. An app opens it on its own store and key, puts Guard in front of
// its routes and mounts Handler, which serves the contract /api/signin/v1
// described in openapi.yaml and the browser routes under /signin/.
//
// The words mean the same in code, contract and every app:
//
//   - An account is who can be signed in to an app. Exactly one account is
//     the owner, the one that set the first password. The owner's role never
//     comes from outside, so the owner's password always gets in.
//   - A role is what an account may do in the app, from Config.Roles, the
//     admin first.
//   - A sign-in service is a service that says who someone is, spoken to
//     over OIDC: Pocket ID, authentik, Authelia, Keycloak, Kanidm, Zitadel or
//     one of the app owner's own. Its presets share their ids with the
//     catalog in the user interface.
//   - A service group is a group the sign-in service or the proxy reports for
//     someone. A table per service maps service groups to roles.
//   - A trusted proxy is a reverse proxy in front of the app whose header
//     with the name the app believes, from its own address and with a shared
//     secret only.
//   - Passkey, two-factor, session and API token mean what they mean
//     anywhere.
//
// Until a password is set nobody can sign in, so the app is open and every
// visitor is admin. Sign-in services, the proxy, passkeys and tokens wait for
// that password, which keeps the owner able to get in when a service is
// down.
//
// The package names no app and carries no text. Errors are codes such as
// passwordShort, and the user interface turns them into sentences.
package signin
