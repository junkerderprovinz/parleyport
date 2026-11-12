# kit

The client side of ParleyPort, as a Go module of its own:

```
go get github.com/junkerderprovinz/parleyport/kit
```

Apps that pair their instances import it for the pieces they would otherwise each keep a copy of: the pairing phrase, member keys, the relay client, finding the other instances on the network, the group with its approvals, the fortress that ties apps together, the events and rules that let one app act on what happened in another, notifications, the status report, the Home Assistant bridge, and the tools that let an app's MCP server show and call the rest of its fortress. Like the server, it names no app.

`cmd/fortress` is a small command for apps without Go code, such as a plugin written in shell: it joins a fortress with the phrase, lists the members, reads their status and asks one of them to run an action.

`cmd/notify` does the same for messages: it sends an event to the channels in a file, tries one channel, and shows and saves the channels for a settings page with every secret masked. Both are attached to each ParleyPort release for linux/amd64 and arm64.

It is versioned apart from the server, with tags of the form `kit/vX.Y.Z`. Within 1.x an update keeps every app building, and [CHANGELOG.md](CHANGELOG.md) says what each version brought.
