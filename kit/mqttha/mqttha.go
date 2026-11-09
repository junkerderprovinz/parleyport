// Package mqttha announces an app instance to Home Assistant over MQTT: one
// device with the sensors and buttons the app describes, found through Home
// Assistant's MQTT discovery.
package mqttha

import (
	"context"
	"errors"
)

// Broker is where the bridge connects and as whom. It is the part of the
// settings one instance can hand to another.
type Broker struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	TLS      bool   `json:"tls"`
}

// Config is the connection and the names the instance goes by.
type Config struct {
	Enabled bool
	Broker  Broker
	// ID is the client id, the device identifier and the start of every
	// unique_id, such as "alpha_a1b2c3d4". Home Assistant keys its entity
	// registry on it, so it has to survive restarts.
	ID string
	// Topic is the root of the instance's own topics, such as "alpha/a1b2c3d4".
	Topic string
}

// Device is what Home Assistant shows for the instance.
type Device struct {
	Name         string
	Manufacturer string
	Model        string
	Version      string
}

// Kind is the Home Assistant component an entity is.
type Kind string

const (
	Sensor Kind = "sensor"
	Button Kind = "button"
)

// Entity is one sensor or button of the device.
type Entity struct {
	Kind Kind
	// Key names the entity in its topics, its unique_id and the state: lower
	// case letters, digits and underscores, starting with a letter.
	Key         string
	Name        string
	Icon        string
	DeviceClass string
	StateClass  string
	Unit        string
	// Options makes a sensor an enum with these states. A value outside them
	// is sent as unknown, since Home Assistant would reject it and keep
	// showing the last one.
	Options []string
	// Fields go into the discovery payload as they are, for what the fields
	// above do not cover. They cannot replace the topics, the device or the
	// unique_id.
	Fields map[string]any
}

// Reading is the device as it stands now. Values holds each sensor's value by
// key. A missing value, a nil or a zero time.Time shows as unknown, and a
// time.Time goes out as RFC 3339.
type Reading struct {
	Device   Device
	Entities []Entity
	Values   map[string]any
}

// Source is the app behind the bridge.
type Source interface {
	// Read is called after every connect and every 15 seconds. A reading that
	// has not changed sends nothing.
	Read(ctx context.Context) (Reading, error)
	// Press runs the button with this key. It has to return once ctx is done,
	// since switching the bridge off waits for it.
	Press(ctx context.Context, key string) error
}

// Problem says in a stable word why the bridge is not connected, for the app
// to translate.
type Problem string

const (
	// Unreachable means no broker answered at the address.
	Unreachable Problem = "unreachable"
	// Refused means the broker answered and turned the login down.
	Refused Problem = "refused"
	// Lost means a standing connection broke; the bridge keeps reconnecting.
	Lost Problem = "lost"
)

// Status is how the connection stands. Error carries the broker's or the
// network's own words.
type Status struct {
	Connected bool    `json:"connected"`
	Problem   Problem `json:"problem,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// ErrNotConnected is returned when the device should leave Home Assistant
// but the broker cannot be reached to say so. Home Assistant then still lists
// it until it is removed there or the bridge is switched on and off again.
var ErrNotConnected = errors.New("mqttha: not connected to the broker")
