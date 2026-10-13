ParleyPort now speaks the relay protocol of KnightLoader 1.9. BombVault and older KnightLoader releases connect exactly as before.

## ✨ Added

- **KnightLoader 1.9 can connect.** The relay now opens every connection with a challenge. KnightLoader 1.9 waits for it before it says hello, so until now it never got past the first frame. BombVault and older KnightLoader releases skip the challenge and send their hello right away, as they always have.
- **Settings for a relay behind a proxy.** `PARLEYPORT_PUBLIC_URL` tells the relay the address your instances dial. `PARLEYPORT_TRUSTED_PROXIES` names the reverse proxies whose `X-Forwarded-For` header it believes, so failed handshakes count against the caller and not against the proxy. A trusted range can be no wider than a /28, or a /124 for IPv6. Both settings also work under their `KL_RELAY_*` names.

## 🔒 Security

- **Only the instance itself can reclaim its place.** A KnightLoader 1.9 member proves its id with a key only it holds. Once it has done that, another connection gets the id only by proving the same key, so knowing the relay key is no longer enough to take over its calls. A proof counts for one connection and one relay name, so it can't be played back later or passed on by another relay. BombVault doesn't prove its id, and for BombVault the newest connection still wins, as before.
- **A call carries its real sender.** The relay writes the sending connection's id into every call it forwards, and it drops a call that names a field twice or spells it in another case.
- **Relay keys can be kept to one instance.** KnightLoader uses this for the group an instance leaves at a reset. ParleyPort on its own never keeps a key that way.

## 🐛 Fixed

- **An instance alone on its key stays reachable after a quick reconnect.** If it came back before the relay dropped its old socket, devices that joined afterwards could not see it.
