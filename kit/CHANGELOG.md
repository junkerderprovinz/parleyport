# Changelog

Every version of the kit, written by hand. The kit is versioned apart from the server, with tags of the form `kit/vX.Y.Z`. What changed in the relay itself is in the [server's release notes](https://github.com/junkerderprovinz/parleyport/releases).

## 1.0.0 - 2026-11-12

The first version: everything an app needs to pair its instances, join a fortress and talk to the rest of the household.

**Adopting apps:**

- **Moving up:** `go get github.com/junkerderprovinz/parleyport/kit@v1.0.0`. An app on a pseudo-version of the kit moves up the same way.
- **Relay:** answers of up to 8 MiB and answers in parts need ParleyPort 1.2.0 on the relay. An older relay carries answers of up to 4 MiB in one piece, as before.

## ✨ Added

- **Pairing by phrase alone.** `phrase`, `keys` and `member` turn twelve words into the keys of a group, and `group` pairs an app's instances with them. On one network the members find each other through `lan` and talk directly, elsewhere they meet on a relay through `relay`.
- **The fortress.** `fortress` joins every app of a household under one phrase, with a switch for every action an app offers the others. After a phrase change, members that missed it follow on their own for 30 days.
- **Status, events and rules.** `status` is the report and log every app answers, and `statustest` checks an app against it in the app's own tests. `events` keeps an app's events in a ring the other members read, and the fortress runs rules on them.
- **Notifications.** `notify` sends events to webhooks, Discord, Slack, Gotify, ntfy, Matrix, mail, Apprise, Healthchecks and Unraid's own notifications, with every secret masked on the way to a settings page.
- **Home Assistant.** `mqttha` announces an app as a device with sensors and buttons through MQTT discovery.
- **Host paths.** `hostpath` translates between a folder in a container and the same folder on the host.
- **Backups and large answers.** A member can stream a backup to another and take one back, directly on the local network. Answers over the relay can be as large as an app allows, up to 8 MiB, and travel in parts of 1 MiB.
- **MCP.** `fortressmcp` brings the fortress into an app's MCP server.
- **Helpers.** `cmd/fortress` and `cmd/notify` do the same for plugins without Go code. Both are attached to every ParleyPort release.
