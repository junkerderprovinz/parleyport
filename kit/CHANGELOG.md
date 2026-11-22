# Changelog

Every version of the kit, written by hand. The kit is versioned apart from the server, with tags of the form `kit/vX.Y.Z`. What changed in the relay itself is in the [server's release notes](https://github.com/junkerderprovinz/parleyport/releases).

## Unreleased

One sign-in for every app of the kit, in the new package `signin`.

**Adopting apps:**

- **Moving up:** nothing changes for an app that does not use `signin`.
- **Taking it on:** open it with `signin.Open` on a store from `sqlstore`, `filestore` or `memstore`, put `Guard` in front of the app's routes and mount `Handler` on `/api/signin/v1/` and `/signin/`. `signintest.Run` checks the app against the contract.

## ✨ Added

- **`signin` signs people in with a password, two-factor, passkeys and sign-in services over OIDC.** It also brings sessions, API tokens, the reset through the container log and the sign-in log, and the contract in `openapi.yaml` answers with codes only. Until a password is set the app is open.
- **An app with accounts of its own moves them over once.** `Config.Import` and `Legacy` take old passwords, second factors, recovery codes, passkeys, tokens and sessions as they are. An old session counts as its swapped one for two minutes, for the requests a page sends at once, and an account bound to a service by name alone is claimed by its first sign-in from there.
- **Going back to the older version brings no ended way in back.** `Legacy.Drop` hears every ending of an imported account from an outbox in the store until the app has taken it, also when a single token or passkey goes.
- **An app keeps its own account table in step.** `Config.NewID` gives new accounts the app's ids, `Hooks.Changing` hears every change before it is written, and the account methods of `Auth` let the app's own screens do what the contract's account routes do. A removed account's name stays taken until the app has cleaned up after it.
- **A sign-in service needs only its issuer, client and secret.** The kit recognises Pocket ID, authentik, Authelia, Keycloak, Kanidm and Zitadel from their discovery documents when nobody picked a provider, takes scopes and claims from that preset unless the service gives its own, and shows no name of its own for a service set up without one.
- **A newcomer from a sign-in service gets the role chosen for that service.** An admin picks it in the service's form, `Config.ServiceRole` is the default and `GET roles` names it. Changing it later leaves existing accounts alone.
- **An app sets up a sign-in service itself and decides who comes in.** `Config.Services` keeps the paths the service already knows and needs no test sign-in, `Config.Closed` keeps such an app closed without a password, and `Hooks.Admit` turns people away or gives them a role, on every sign-in and renewal.
- **The app's own ways in follow the same rules.** `CheckPassword` checks HTTP Basic credentials under the sign-in's throttle and says how long to wait, `TokenVisitor` reads a token, `Alive` tells a terminal whether its session still counts, and `SignInAgain` answers an app's own `Mint` as the contract does. An admin's API token can list other accounts' sessions, tokens and passkeys, and only a session changes them.
- **A service that sends an empty groups claim is told apart from one that sends none.** `Hooks.Admit` and `Hooks.SignedIn` get an empty list for someone who left every group and nil for a missing claim, on sign-in and renewal alike.
- **It works below a base path and behind a Unix socket.** `Config.Base` keeps cookies and every way back under the app's path, and `Config.TrustedPeer` names a proxy without an address.

## 1.0.5 - 2026-11-19

A member that closes while it checks a newcomer no longer shuts that newcomer out.

**Adopting apps:**

- **Moving up:** `go get github.com/junkerderprovinz/parleyport/kit@v1.0.5`. Nothing else changes.
- **Plugins:** take `cmd/fortress` and `cmd/notify` from ParleyPort 1.3.1.

## 🐛 Fixed

- **A member that closes while it checks a newcomer no longer shuts that newcomer out.** It answered the call as if the group took nobody new on this phrase, and the newcomer stopped listing it for good, so two fortress instances that first met while one of them restarted could never learn each other's app. Such a call goes unanswered, and the newcomer tries again.

## 1.0.4 - 2026-11-18

Notifications that say a problem is over, and a steadier MQTT bridge.

**Adopting apps:**

- **Moving up:** `go get github.com/junkerderprovinz/parleyport/kit@v1.0.4`. `notify.Event` gains the field `Recovery`, and existing code builds unchanged.
- **Plugins:** take `cmd/fortress` and `cmd/notify` from ParleyPort 1.3.0. A plugin that kept a second channel for the all-clear can drop it.

## ✨ Added

- **`notify.Event.Recovery` marks the news that a problem is over.** A channel set to failures only carries such an event whatever its severity, so whoever heard of the problem also hears that it ended. `cmd/notify send` reads it as `"recovery": true`.

## 🐛 Fixed

- **`mqttha` keeps the device available after a quick reconnect.** When the broker published the will of a dropped connection only after the bridge had reconnected, the device stayed unavailable until the next reconnect. The bridge answers that late `offline` with `online`.
- **`mqttha` reports the connection right after a reconnect.** A lost connection that the MQTT client reported only once the reconnect stood left `Bridge.Status` at `lost` while the bridge was connected.

## 1.0.3 - 2026-11-18

A phrase change counts every member that took the new phrase.

**Adopting apps:**

- **Moving up:** `go get github.com/junkerderprovinz/parleyport/kit@v1.0.3`. Nothing in the API changes.
- **Plugins:** nothing to do. `cmd/fortress` and `cmd/notify` work as in ParleyPort 1.3.0.

## 🐛 Fixed

- **A member whose answer gets lost during a phrase change still counts as having taken it.** `ChangePhrase` handed the new phrase to each member once, so a member whose answer never came back was reported as left although it held the new phrase. The hand-over is tried twice more after a short pause, and a member answers a change it already took without keeping the phrase again.

## 1.0.2 - 2026-11-18

Local network discovery on hosts with one network interface.

**Adopting apps:**

- **Moving up:** `go get github.com/junkerderprovinz/parleyport/kit@v1.0.2`. Nothing in the API changes.
- **Plugins:** take `cmd/fortress` and `cmd/notify` from ParleyPort 1.3.0.

## ⚡ Improved

- **golang.org/x/net 0.63.0.**

## 🐛 Fixed

- **`lan` keeps listening on a host with one network interface.** `ListenMulticastUDP` already joins the group on the interface the system picks, so the second join there fails, and `Start` took that for no join at all and closed the socket. A container on a bridge network, or any host with a single network, neither heard the other members nor announced itself, and members met through the relay only.

## 1.0.1 - 2026-11-14

Security fixes for direct calls and fortress frames.

**Adopting apps:**

- **Moving up:** `go get github.com/junkerderprovinz/parleyport/kit@v1.0.1`. Nothing in the API changes.
- **Plugins:** take `cmd/fortress` and `cmd/notify` from ParleyPort 1.3.0.

## 🐛 Fixed

- **A direct call stays on `DirectPath`.** A query or fragment in an announced address used to swallow the path, so anyone holding the phrase could make a member post its call to any page of a host it reaches. `group` now puts only the address's own path in front of `DirectPath`.
- **`fortress` checks a frame's head and body against the limit before it allocates them.** A part past the limit is refused instead of overflowing the size or the four-byte length on a 32-bit platform.
- **The websocket of an opened page is dialed under a fixed host.** The target was already checked to be a path and the dial only reaches the app's own pipe. The host is now part of the constant prefix as well.
- **golang.org/x/net 0.62.0**, with the fix for GHSA-5cv4-jp36-h3mw in the HTML parser.

## 1.0.0 - 2026-11-14

The first version: everything an app needs to pair its instances, join a fortress and talk to the rest of the household.

**Adopting apps:**

- **Moving up:** `go get github.com/junkerderprovinz/parleyport/kit@v1.0.0`. An app on a pseudo-version of the kit moves up the same way.
- **Uses:** list every action your app calls at other members in `fortress.Config.Uses`. A call to an action that isn't listed is refused with 403 `not_used`, which `Act` returns as `ErrNotUsed` (it also counts as `ErrPermissionOff`).
- **Streams:** `backup.export` and `backup.import` travel as streams only. Asked for through `Act`, they answer 421 `stream_only` rather than claiming the app doesn't offer them.
- **Relay:** answers of up to 8 MiB and answers in parts need ParleyPort 1.2.0 on the relay. An older relay carries answers of up to 4 MiB in one piece, as before.

## ✨ Added

- **Pairing by phrase alone.** `phrase`, `keys` and `member` turn twelve words into the keys of a group, and `group` pairs an app's instances with them. On one network the members find each other through `lan` and talk directly, elsewhere they meet on a relay through `relay`.
- **The fortress.** `fortress` joins every app of a household under one phrase, with a switch for every action an app offers the others. After a phrase change, members that missed it follow on their own for 30 days, while a newcomer on the old phrase gets `groupClosed` and sees no members, even at a member that hasn't followed yet. A member that can't hand the new phrase over, such as a plugin or an instance that followed late, still answers the members on the old phrase for those 30 days, on the relay and on the local network, and tells them only that the phrase changed. `Fortress.PhraseChanged` reports it, so the app asks for the new words, and a member that moved shows as away there.
- **Taking a member out.** A new phrase is sealed for each member it goes to, so a member taken out, which still knows the old phrase, can't read it on the way. After a removal the fortress takes no new member until the phrase changes, since the one taken out still holds the phrase: a newcomer is refused with `group.ClosedUntilNewPhrase`, which `Fortress.ShutOut` reports and `cmd/fortress` turns into exit code 3. Every member closes as it hears of the removal, plugins and members that were away included, and a new phrase goes only to the members met before it.
- **Logos and servers travel with the members.** `fortress.App.Icon` carries an app's logo and `Config.Host` the server an instance runs on. Every member keeps both, so it shows the logo of an app that's away and finds the apps on its own server, whatever each one calls itself. A plugin hands its logo to `cmd/fortress join -icon`.
- **Opening another member's pages.** `fortress.Config.UI` offers an app's web interface to the others, and `Open` with `OpenHandler` shows it to a signed-in user of another app in a sandboxed frame, websockets and event streams included. The member's own sign-in stays in front, its cookies never leave it, and the permission `ui.open` can be switched off like any other.
- **Taken out while away.** A member that was off when another took it out hears it from the group on its next call and gets `OnRemoved` like any other. `cmd/fortress` then forgets the membership, leaves `removed-here` in its directory and fails until `join` runs again.
- **Leaving.** `Fortress.Leave` tells the members in reach that an instance left, so they drop it at once instead of listing it as away, and the members that were away hear it from the others. Leaving counts as no removal. `cmd/fortress leave` does the same for a plugin.
- **A new address goes out at once.** An app that learns its own direct address after it opened the fortress hands it over with `Fortress.SetSelf`, and the members dial the new one right away.
- **Status, events and rules.** `status` is the report and log every app answers, and `statustest` checks an app against it in the app's own tests. `events` keeps an app's events in a ring the other members read, and the fortress runs rules on them.
- **Notifications.** `notify` sends events to webhooks, Discord, Slack, Gotify, ntfy, Matrix, mail, Apprise, Healthchecks and Unraid's own notifications, with every secret masked on the way to a settings page.
- **Home Assistant.** `mqttha` announces an app as a device with sensors and buttons through MQTT discovery.
- **Host paths.** `hostpath` translates between a folder in a container and the same folder on the host.
- **Backups and large answers.** A member can stream a backup to another and take one back, directly on the local network. Answers over the relay can be as large as an app allows, up to 8 MiB, and travel in parts of 1 MiB.
- **MCP.** `fortressmcp` brings the fortress into an app's MCP server.
- **Helpers.** `cmd/fortress` and `cmd/notify` do the same for plugins without Go code. Both are attached to every ParleyPort release. A plugin joined with `-lan` takes the members' calls on its own network while a command runs, so it reaches them with the relay off too. An app with a port of its own for these calls serves them with `group.ServeDirect`, which bounds the connections it holds, in all and from one address, and lets go of slow and idle ones.
