// Package signin is the sign-in every app of the kit shares: password,
// two-factor, passkeys, sessions, API tokens, the reset through the
// container log, the sign-in log and sign-in services over OIDC. An app
// opens it on its own store and key, puts Guard in front of
// its routes and mounts Handler, which serves the contract /api/signin/v1
// described in openapi.yaml and the browser routes under /signin/, both
// below the app's base path.
//
// The words mean the same in code, contract and every app:
//
//   - An account is who can be signed in to an app. At most one account is
//     the owner, the one that set the first password. The owner's role never
//     comes from outside, so the owner's password always gets in.
//   - A role is what an account may do in the app, from Config.Roles, the
//     admin first.
//   - A sign-in service is a service that says who someone is, spoken to
//     over OIDC: Pocket ID, authentik, Authelia, Keycloak, Kanidm, Zitadel or
//     one of the app owner's own. Its presets share their ids with the
//     catalog in the user interface, and a service set up without one is
//     recognised as a preset from its discovery where that is certain. The
//     package never names a service itself. An app can also set one up
//     itself, in Config.Services.
//   - A service group is a group the sign-in service reports for someone.
//     It is kept on the account. Who may sign in at all is the service's
//     decision. A newcomer it lets through gets the role an admin chose for
//     the service, Config.ServiceRole unless one was chosen, and an app
//     that sets up a service itself can decide in Hooks.Admit.
//   - Passkey, two-factor, session and API token mean what they mean
//     anywhere.
//
// A password is always optional, and every part of an app works without
// one. Until a password is set or a sign-in service is on, nobody can sign
// in, so the app is open and every visitor is admin. A password of any
// length is taken; one under Config.MinPassword comes back with a hint the
// app may show. A sign-in service an admin adds while the app is open goes
// on with its test sign-in, which binds the owner and closes the app, and
// the reset through the log stays the way back in when the service is
// down. Tokens made while the app is open end when it closes. Passkeys and
// two-factor wait for a password. An app behind a service that guards it as
// a reverse proxy sets no password, and that service alone protects it. An
// app that one of its own Config.Services guards stays closed without a
// password through Config.Closed, and only that service lets anyone in.
// An operator who sets the owner's password from outside, such as from an
// environment variable, hands it in as Config.PinnedPassword. It closes the
// app, the page offers no reset, and changing or removing it answers pinned.
//
// An app with accounts of its own before the package imports them once, and
// keeps its account table in step through Hooks.Changing and the account
// methods of Auth. Hooks.Ended and Legacy.Drop run from an outbox in the
// store until the app took them, so a lost hook or a restart never leaves
// one of the app's ways in open.
//
// The package names no app and carries no text. Errors are codes such as
// passwordLong, and the user interface turns them into sentences.
package signin
