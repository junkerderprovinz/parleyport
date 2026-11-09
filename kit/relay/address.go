package relay

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// DefaultURL is the project relay a member dials unless its owner names
// another. Because it is compiled in, a phrase only has to carry the secret.
const DefaultURL = "wss://parleyport.halleluja.design/relay/connect"

// connectPath is appended to an address that does not name the socket itself,
// so both "https://relay.example.com" and an instance a proxy serves under
// "https://example.com/alpha" work.
const connectPath = "/relay/connect"

// PairingCode is the text of the QR code shown beside a phrase: the words
// alone on the project relay, and on a relay of the instance's own the words
// and that relay on a second line. A device that only knows the project relay
// counts thirteen words and refuses the code instead of pairing elsewhere.
func PairingCode(words, relayURL string) string {
	dial, err := connectURL(relayURL)
	if err != nil || dial == DefaultURL {
		return words
	}
	return words + "\n" + dial
}

// connectURL turns a configured address into the WebSocket URL to dial. It
// takes the https:// address given to a reverse proxy as well as a wss:// URL.
func connectURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("relay: %q is not a relay address", raw)
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("relay: %q must be an http(s) or ws(s) address", raw)
	}
	// A path ending in /connect names the socket, wherever a proxy mounted
	// it. Any other path is where a proxy serves an instance, whose relay
	// sits below it.
	p := strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(p, "/connect") {
		p += connectPath
	}
	u.Path, u.RawPath = p, ""
	return u.String(), nil
}

// RelayHost is the name a hello's proof gives the relay it is meant for: the
// host of address in lower case, without port, IPv6 brackets or the dot of a
// fully qualified name. The port goes because a reverse proxy listens on
// another one than the relay behind it.
func RelayHost(address string) string {
	address = strings.TrimSpace(address)
	if !strings.Contains(address, "://") {
		address = "http://" + address
	}
	u, err := url.Parse(address)
	if err != nil {
		return ""
	}
	host := u.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
}
