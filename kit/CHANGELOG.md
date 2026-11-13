# Changelog

Every version of the kit, written by hand. The kit is versioned apart from the server, with tags of the form `kit/vX.Y.Z`. What changed in the relay itself is in the [server's release notes](https://github.com/junkerderprovinz/parleyport/releases).

## 1.0.0 - 2026-11-12

The first version: everything an app needs to pair its instances, join a fortress and talk to the rest of the household.

**Adopting apps:**

- **Moving up:** `go get github.com/junkerderprovinz/parleyport/kit@v1.0.0`. An app on a pseudo-version of the kit moves up the same way.
- **Uses:** list every action your app calls at other members in `fortress.Config.Uses`. A call to an action that isn't listed is refused with 403 `not_used`, which `Act` returns as `ErrNotUsed` (it also counts as `ErrPermissionOff`).
- **Streams:** `backup.export` and `backup.import` travel as streams only. Asked for through `Act`, they answer 421 `stream_only` rather than claiming the app doesn't offer them.
- **Relay:** answers of up to 8 MiB and answers in parts need ParleyPort 1.2.0 on the relay. An older relay carries answers of up to 4 MiB in one piece, as before.

## ✨ Added

- **Pairing by phrase alone.** `phrase`, `keys` and `member` turn twelve words into the keys of a group, and `group` pairs an app's instances with them. On one network the members find each other through `lan` and talk directly, elsewhere they meet on a relay through `relay`.
- **The fortress.** `fortress` joins every app of a household under one phrase, with a switch for every action an app offers the others. After a phrase change, members that missed it follow on their own for 30 days, while a newcomer on the old phrase gets `groupClosed` and sees no members, even at a member that hasn't followed yet. A new phrase is sealed for each member it goes to, so a member taken out, which still knows the old phrase, can't read it on the way. After a removal it goes only to the members met before it, since the one taken out may be back under a new key. An app that joined since enters the new phrase itself.
- **Logos and servers travel with the members.** `fortress.App.Icon` carries an app's logo and `Config.Host` the server an instance runs on. Every member keeps both, so it shows the logo of an app that's away and finds the apps on its own server, whatever each one calls itself. A plugin hands its logo to `cmd/fortress join -icon`.
- **Opening another member's pages.** `fortress.Config.UI` offers an app's web interface to the others, and `Open` with `OpenHandler` shows it to a signed-in user of another app in a sandboxed frame, websockets and event streams included. The member's own sign-in stays in front, its cookies never leave it, and the permission `ui.open` can be switched off like any other.
- **Taken out while away.** A member that was off when another took it out hears it from the group on its next call and gets `OnRemoved` like any other. `cmd/fortress` then forgets the membership, leaves `removed-here` in its directory and fails until `join` runs again.
- **Status, events and rules.** `status` is the report and log every app answers, and `statustest` checks an app against it in the app's own tests. `events` keeps an app's events in a ring the other members read, and the fortress runs rules on them.
- **Notifications.** `notify` sends events to webhooks, Discord, Slack, Gotify, ntfy, Matrix, mail, Apprise, Healthchecks and Unraid's own notifications, with every secret masked on the way to a settings page.
- **Home Assistant.** `mqttha` announces an app as a device with sensors and buttons through MQTT discovery.
- **Host paths.** `hostpath` translates between a folder in a container and the same folder on the host.
- **Backups and large answers.** A member can stream a backup to another and take one back, directly on the local network. Answers over the relay can be as large as an app allows, up to 8 MiB, and travel in parts of 1 MiB.
- **MCP.** `fortressmcp` brings the fortress into an app's MCP server.
- **Helpers.** `cmd/fortress` and `cmd/notify` do the same for plugins without Go code. Both are attached to every ParleyPort release. A plugin joined with `-lan` takes the members' calls on its own network while a command runs, so it reaches them with the relay off too. An app with a port of its own for these calls serves them with `group.ServeDirect`, which bounds the connections it holds and lets go of slow and idle ones.
