package relay

import (
	"strings"
	"testing"
	"unicode"
)

func TestConnectURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"https gets the path appended", "https://relay.example.com", "wss://relay.example.com/relay/connect"},
		{"a trailing slash is a bare host too", "https://relay.example.com/", "wss://relay.example.com/relay/connect"},
		{"http and a port", "http://192.168.20.30:8760", "ws://192.168.20.30:8760/relay/connect"},
		{"whitespace from a settings field", "  https://relay.example.com  ", "wss://relay.example.com/relay/connect"},
		{"a ws url is already one", "ws://127.0.0.1:8760/relay/connect", "ws://127.0.0.1:8760/relay/connect"},
		{"a mounted path is kept", "https://home.example.com/home-relay/connect", "wss://home.example.com/home-relay/connect"},
		{"an instance under a path has the relay below it", "https://example.com/alpha", "wss://example.com/alpha/relay/connect"},
		{"and with a trailing slash", "https://example.com/apps/alpha/", "wss://example.com/apps/alpha/relay/connect"},
		{"a full address under a path is kept", "https://example.com/alpha/relay/connect", "wss://example.com/alpha/relay/connect"},
		{"a slash after the socket goes", "https://example.com/alpha/relay/connect/", "wss://example.com/alpha/relay/connect"},
		{"no scheme", "relay.example.com", ""},
		{"a scheme nobody can dial", "ftp://relay.example.com", ""},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := connectURL(tc.in)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("got %q, want %q rejected", got, tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("connectURL(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRelayHost: the relay a hello's proof names.
func TestRelayHost(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"a dialled address", "wss://relay.example.com/relay/connect", "relay.example.com"},
		{"the port goes", "ws://192.168.20.30:8760/relay/connect", "192.168.20.30"},
		{"in lower case", "https://Relay.Example.COM", "relay.example.com"},
		{"without the dot of a full name", "https://relay.example.com./alpha", "relay.example.com"},
		{"an IPv6 literal without its brackets", "ws://[::1]:8760/relay/connect", "::1"},
		{"a bare host", "relay.example.com", "relay.example.com"},
		{"a bare host and a port", "127.0.0.1:8760", "127.0.0.1"},
		{"whitespace from a setting", "  https://relay.example.com  ", "relay.example.com"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		if got := RelayHost(tc.in); got != tc.want {
			t.Errorf("%s: RelayHost(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestTheDefaultRelayIsTheProjectRelay(t *testing.T) {
	if got := RelayHost(DefaultURL); got != "parleyport.halleluja.design" {
		t.Errorf("the default relay is %s, want parleyport.halleluja.design", got)
	}
	if got, err := connectURL(DefaultURL); err != nil || got != DefaultURL {
		t.Errorf("connectURL(DefaultURL) = %q, %v; want it to be a full socket address already", got, err)
	}
}

func TestPairingCode(t *testing.T) {
	const words = "abandon ability able about above absent absorb abstract absurd abuse access accident"
	tests := []struct {
		name  string
		relay string
		want  string
	}{
		{"no relay of its own", "", words},
		{"the project relay", DefaultURL, words},
		{"the project relay as typed", "https://parleyport.halleluja.design", words},
		{"an address the instance cannot dial", "relay.example.com", words},
		{"its own relay", "https://relay.example.com", words + "\nwss://relay.example.com/relay/connect"},
		{"its own relay under a path", "https://example.com/alpha", words + "\nwss://example.com/alpha/relay/connect"},
		{"a relay without TLS is named as it is dialled", "http://192.168.20.30:8760", words + "\nws://192.168.20.30:8760/relay/connect"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := PairingCode(words, tc.relay); got != tc.want {
				t.Fatalf("PairingCode(%q) = %q, want %q", tc.relay, got, tc.want)
			}
		})
	}
}

// A device that reads the code as words alone has to refuse a code that names
// a relay rather than pair on the project relay and find nobody there.
func TestAPairingCodeWithARelayIsNotAPhrase(t *testing.T) {
	const words = "abandon ability able about above absent absorb abstract absurd abuse access accident"
	code := PairingCode(words, "https://relay.example.com")
	split := strings.FieldsFunc(code, func(r rune) bool { return r == ',' || r == ';' || unicode.IsSpace(r) })
	if len(split) == 12 {
		t.Fatalf("%q reads as twelve words", code)
	}
}
