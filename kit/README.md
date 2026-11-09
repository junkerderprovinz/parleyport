# kit

The client side of ParleyPort, as a Go module of its own:

```
go get github.com/junkerderprovinz/parleyport/kit
```

Apps that pair their instances import it for the pieces they would otherwise each keep a copy of: the pairing phrase, member keys, the relay client, finding the other instances on the network, the group with its approvals, the fortress that ties apps together, notifications, the status report and the Home Assistant bridge. Like the server, it names no app.

It is versioned apart from the server, with tags of the form `kit/vX.Y.Z`. Until the first apps run on it, the version stays at 0.x and the API may still change.
