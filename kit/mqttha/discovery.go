package mqttha

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
)

// DiscoveryPrefix is the topic root Home Assistant listens on for discovery,
// its default and what almost every installation keeps.
const DiscoveryPrefix = "homeassistant"

const pressPayload = "PRESS"

var (
	keyRe   = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	idRe    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	topicRe = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`)
)

func (c Config) host() string                 { return strings.Trim(c.Broker.Host, "[]") }
func (c Config) availabilityTopic() string    { return c.Topic + "/availability" }
func (c Config) stateTopic() string           { return c.Topic + "/state" }
func (c Config) pressTopic(key string) string { return c.Topic + "/press/" + key }

// commandTopic is where button e is pressed. A command of its own may not
// fall on the state, the availability or the press topics.
func (c Config) commandTopic(e Entity) (string, error) {
	if e.Command == "" {
		return c.pressTopic(e.Key), nil
	}
	if !topicRe.MatchString(e.Command) || e.Command == "state" || e.Command == "availability" || strings.HasPrefix(e.Command, "press/") {
		return "", fmt.Errorf("mqttha: button %s cannot be pressed on %q", e.Key, e.Command)
	}
	return c.Topic + "/" + e.Command, nil
}

func (c Config) discoveryTopic(kind Kind, key string) string {
	return DiscoveryPrefix + "/" + string(kind) + "/" + c.ID + "/" + key + "/config"
}

// discoveryFilter matches every discovery topic of the instance, including
// those of entities an earlier run announced.
func (c Config) discoveryFilter() string {
	return DiscoveryPrefix + "/+/" + c.ID + "/+/config"
}

// place is what decides where the device lives. When it changes, the device
// has to be removed from the old place.
type place struct {
	host  string
	port  int
	tls   bool
	id    string
	topic string
}

func (c Config) place() place {
	return place{c.host(), c.Broker.Port, c.Broker.TLS, c.ID, c.Topic}
}

func (c Config) validate() error {
	switch {
	case c.host() == "":
		return fmt.Errorf("mqttha: the broker has no host")
	case c.Broker.Port < 1 || c.Broker.Port > 65535:
		return fmt.Errorf("mqttha: port %d is not between 1 and 65535", c.Broker.Port)
	case !idRe.MatchString(c.ID):
		return fmt.Errorf("mqttha: id %q takes letters, digits, dashes and underscores", c.ID)
	case !topicRe.MatchString(c.Topic):
		return fmt.Errorf("mqttha: topic %q takes letters, digits, dashes and underscores between slashes", c.Topic)
	}
	return nil
}

// announcement is what one reading puts on the broker.
type announcement struct {
	discovery map[string][]byte
	state     []byte
	buttons   map[string]bool
	// commands holds the key of the button each command topic presses.
	commands map[string]string
	// unlisted holds the enum values left out because their options lack them.
	unlisted map[string]any
}

func announce(cfg Config, r Reading) (announcement, error) {
	a := announcement{discovery: map[string][]byte{}, buttons: map[string]bool{}, commands: map[string]string{}, unlisted: map[string]any{}}
	device := map[string]any{"identifiers": []string{cfg.ID}}
	setIf(device, "name", r.Device.Name)
	setIf(device, "manufacturer", r.Device.Manufacturer)
	setIf(device, "model", r.Device.Model)
	setIf(device, "sw_version", r.Device.Version)

	state := map[string]any{}
	for _, e := range r.Entities {
		if !keyRe.MatchString(e.Key) {
			return announcement{}, fmt.Errorf("mqttha: entity key %q takes lower case letters, digits and underscores, starting with a letter", e.Key)
		}
		if _, dup := state[e.Key]; dup || a.buttons[e.Key] {
			return announcement{}, fmt.Errorf("mqttha: two entities have the key %q", e.Key)
		}
		c := maps.Clone(e.Fields)
		if c == nil {
			c = map[string]any{}
		}
		setIf(c, "name", e.Name)
		setIf(c, "icon", e.Icon)
		c["unique_id"] = cfg.ID + "_" + e.Key
		c["availability_topic"] = cfg.availabilityTopic()
		c["device"] = device
		if e.Command != "" && e.Kind != Button {
			return announcement{}, fmt.Errorf("mqttha: entity %s is no button and takes no command topic", e.Key)
		}
		switch e.Kind {
		case Sensor:
			c["state_topic"] = cfg.stateTopic()
			c["value_template"] = "{{ value_json." + e.Key + " }}"
			setIf(c, "device_class", e.DeviceClass)
			setIf(c, "state_class", e.StateClass)
			setIf(c, "unit_of_measurement", e.Unit)
			if len(e.Options) > 0 {
				c["device_class"] = "enum"
				c["options"] = e.Options
			}
			v, listed := shown(e, r.Values[e.Key])
			if !listed {
				a.unlisted[e.Key] = r.Values[e.Key]
			}
			state[e.Key] = v
		case Button:
			topic, err := cfg.commandTopic(e)
			if err != nil {
				return announcement{}, err
			}
			if _, dup := a.commands[topic]; dup {
				return announcement{}, fmt.Errorf("mqttha: two buttons are pressed on %s", topic)
			}
			c["command_topic"] = topic
			c["payload_press"] = pressPayload
			a.buttons[e.Key] = true
			a.commands[topic] = e.Key
		default:
			return announcement{}, fmt.Errorf("mqttha: entity %s is a %q, not a sensor or a button", e.Key, e.Kind)
		}
		payload, err := json.Marshal(c)
		if err != nil {
			return announcement{}, fmt.Errorf("mqttha: entity %s: %w", e.Key, err)
		}
		a.discovery[cfg.discoveryTopic(e.Kind, e.Key)] = payload
	}
	var err error
	if a.state, err = json.Marshal(state); err != nil {
		return announcement{}, fmt.Errorf("mqttha: state: %w", err)
	}
	return a, nil
}

// shown is the value a sensor's template reads, and false when an enum's
// options lack it.
func shown(e Entity, v any) (any, bool) {
	if t, ok := v.(time.Time); ok {
		if t.IsZero() {
			return nil, true
		}
		return t.Format(time.RFC3339), true
	}
	if len(e.Options) == 0 || v == nil {
		return v, true
	}
	if s, ok := v.(string); ok && slices.Contains(e.Options, s) {
		return s, true
	}
	return nil, false
}

func setIf(m map[string]any, key, value string) {
	if value != "" {
		m[key] = value
	}
}
