package mqttha

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	mochi "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/hooks/auth"
	"github.com/mochi-mqtt/server/v2/listeners"
	mochipackets "github.com/mochi-mqtt/server/v2/packets"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// testBroker is a broker running inside the test, on a port of its own.
type testBroker struct {
	t      *testing.T
	addr   string
	ledger *auth.Ledger

	mu     sync.Mutex
	srv    *mochi.Server
	closed bool
}

func startBroker(t *testing.T) *testBroker {
	t.Helper()
	return startBrokerWith(t, nil)
}

// startBrokerWith starts a broker that lets in only who ledger allows, or
// everyone when ledger is nil.
func startBrokerWith(t *testing.T, ledger *auth.Ledger) *testBroker {
	t.Helper()
	tb := &testBroker{t: t, addr: "127.0.0.1:0", ledger: ledger}
	tb.serve()
	t.Cleanup(tb.close)
	return tb
}

func (tb *testBroker) serve() {
	tb.t.Helper()
	srv := mochi.New(&mochi.Options{InlineClient: true, Logger: slog.New(slog.DiscardHandler)})
	var err error
	if tb.ledger != nil {
		err = srv.AddHook(new(auth.Hook), &auth.Options{Ledger: tb.ledger})
	} else {
		err = srv.AddHook(new(auth.AllowHook), nil)
	}
	if err != nil {
		tb.t.Fatal(err)
	}
	tcp := listeners.NewTCP(listeners.Config{ID: "test", Address: tb.addr})
	if err := srv.AddListener(tcp); err != nil {
		tb.t.Fatal(err)
	}
	if err := srv.Serve(); err != nil {
		tb.t.Fatal(err)
	}
	tb.mu.Lock()
	tb.srv, tb.addr, tb.closed = srv, tcp.Address(), false
	tb.mu.Unlock()
}

func (tb *testBroker) close() {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if !tb.closed {
		tb.closed = true
		tb.settle()
		_ = tb.srv.Close()
	}
}

// settle waits for clients that are closing to leave the broker. mochi's
// Close takes the client list's read lock twice, and a client deleted in
// between deadlocks both.
func (tb *testBroker) settle() {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && tb.anyClosing() {
		time.Sleep(5 * time.Millisecond)
	}
}

func (tb *testBroker) anyClosing() bool {
	for _, cl := range tb.srv.Clients.GetAll() {
		if cl.Closed() {
			return true
		}
	}
	return false
}

// restart replaces the broker by a fresh one on the same port, which has
// forgotten every retained message.
func (tb *testBroker) restart() {
	tb.close()
	tb.serve()
}

func (tb *testBroker) server() *mochi.Server {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.srv
}

func (tb *testBroker) port() int {
	_, p, _ := net.SplitHostPort(tb.addr)
	n, _ := strconv.Atoi(p)
	return n
}

func (tb *testBroker) retained(topic string) (string, bool) {
	pks := tb.server().Topics.Messages(topic)
	if len(pks) == 0 {
		return "", false
	}
	return string(pks[0].Payload), true
}

// retainedUnder lists the retained topics matching filter.
func (tb *testBroker) retainedUnder(filter string) []string {
	var out []string
	for _, pk := range tb.server().Topics.Messages(filter) {
		out = append(out, pk.TopicName)
	}
	slices.Sort(out)
	return out
}

// retainedOf lists what is retained for the instance, in its own topics and
// in discovery.
func (tb *testBroker) retainedOf(cfg Config) []string {
	return append(tb.retainedUnder(cfg.Topic+"/#"), tb.retainedUnder("homeassistant/+/"+cfg.ID+"/#")...)
}

func (tb *testBroker) publish(topic, payload string, retain bool) {
	tb.t.Helper()
	if err := tb.server().Publish(topic, []byte(payload), retain, 1); err != nil {
		tb.t.Fatal(err)
	}
}

// drop cuts a client off the way a dead network does, without a DISCONNECT.
func (tb *testBroker) drop(clientID string) {
	tb.t.Helper()
	cl, ok := tb.server().Clients.Get(clientID)
	if !ok {
		tb.t.Fatalf("no client %s on the broker", clientID)
	}
	// cl.Stop would race the broker's read loop, which ends quietly and skips
	// the will when it sees the client stopped first. A closed socket always
	// fails the read, as a dead network does.
	_ = cl.Net.Conn.Close()
}

// watch records every payload published to topic from now on.
func (tb *testBroker) watch(topic string) func() []string {
	tb.t.Helper()
	var mu sync.Mutex
	var seen []string
	err := tb.server().Subscribe(topic, 1, func(_ *mochi.Client, _ mochipackets.Subscription, pk mochipackets.Packet) {
		mu.Lock()
		seen = append(seen, string(pk.Payload))
		mu.Unlock()
	})
	if err != nil {
		tb.t.Fatal(err)
	}
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// testSource is the app side: what it shows and the buttons pressed.
type testSource struct {
	mu      sync.Mutex
	reading Reading
	readErr error
	hold    chan struct{}
	presses chan string
}

func newSource() *testSource {
	return &testSource{reading: alphaReading(), presses: make(chan string, 16)}
}

func (s *testSource) Read(context.Context) (Reading, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reading, s.readErr
}

func (s *testSource) Press(ctx context.Context, key string) error {
	s.presses <- key
	s.mu.Lock()
	hold := s.hold
	s.mu.Unlock()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
		}
	}
	return nil
}

func (s *testSource) set(r Reading) {
	s.mu.Lock()
	s.reading = r
	s.mu.Unlock()
}

func alphaReading() Reading {
	return Reading{
		Device: Device{Name: "Alpha (tower)", Manufacturer: "Alpha", Model: "Alpha", Version: "v1.2.0"},
		Entities: []Entity{
			{Kind: Sensor, Key: "state", Name: "State", Icon: "mdi:shield-check", Options: []string{"ok", "warning", "overdue", "failed", "off"}},
			{Kind: Sensor, Key: "next_run", Name: "Next run", DeviceClass: "timestamp"},
			{Kind: Sensor, Key: "last_run", Name: "Last run", DeviceClass: "timestamp"},
			{Kind: Sensor, Key: "free_space", Name: "Free space", DeviceClass: "data_size", Unit: "GB", StateClass: "measurement",
				Fields: map[string]any{"suggested_display_precision": 1}},
			{Kind: Sensor, Key: "running", Name: "Running job"},
			{Kind: Button, Key: "run", Name: "Run now", Icon: "mdi:play"},
		},
		Values: map[string]any{
			"state":      "overdue",
			"next_run":   time.Time{},
			"last_run":   time.Date(2027, 1, 15, 8, 0, 0, 0, time.UTC),
			"free_space": 12.5,
		},
	}
}

func alphaConfig(tb *testBroker) Config {
	return Config{
		Enabled: true,
		Broker:  Broker{Host: "127.0.0.1", Port: tb.port()},
		ID:      "alpha_a1b2c3d4",
		Topic:   "alpha/a1b2c3d4",
	}
}

func newTestBridge(t *testing.T, src Source) *Bridge {
	t.Helper()
	b := New(src, slog.New(slog.DiscardHandler))
	b.retryEvery = 50 * time.Millisecond
	t.Cleanup(b.Close)
	return b
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitOnline(t *testing.T, tb *testBroker, cfg Config) {
	t.Helper()
	waitUntil(t, "the device is online", func() bool {
		v, _ := tb.retained(cfg.Topic + "/availability")
		return v == "online"
	})
}

// waitAnnounced waits until the device is online and its first state is out,
// which the bridge sends after the discovery.
func waitAnnounced(t *testing.T, tb *testBroker, cfg Config) {
	t.Helper()
	waitOnline(t, tb, cfg)
	waitUntil(t, "the state is retained", func() bool {
		_, ok := tb.retained(cfg.Topic + "/state")
		return ok
	})
}

func expectPress(t *testing.T, src *testSource, key string) {
	t.Helper()
	select {
	case got := <-src.presses:
		if got != key {
			t.Fatalf("pressed %q, want %q", got, key)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the press of %s ran nothing", key)
	}
}

func expectNoPress(t *testing.T, src *testSource, why string) {
	t.Helper()
	select {
	case got := <-src.presses:
		t.Fatalf("%s ran %s", why, got)
	case <-time.After(200 * time.Millisecond):
	}
}

func discoveryOf(t *testing.T, tb *testBroker, topic string) map[string]any {
	t.Helper()
	raw, ok := tb.retained(topic)
	if !ok {
		t.Fatalf("%s is not retained", topic)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("%s: %v", topic, err)
	}
	return cfg
}

func stateOf(t *testing.T, tb *testBroker, cfg Config) map[string]any {
	t.Helper()
	raw, ok := tb.retained(cfg.Topic + "/state")
	if !ok {
		t.Fatal("no state is retained")
	}
	var st map[string]any
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatalf("state %q: %v", raw, err)
	}
	return st
}

func TestSwitchingOnAnnouncesTheDevice(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	b := newTestBridge(t, newSource())
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)

	want := []string{
		"homeassistant/button/alpha_a1b2c3d4/run/config",
		"homeassistant/sensor/alpha_a1b2c3d4/free_space/config",
		"homeassistant/sensor/alpha_a1b2c3d4/last_run/config",
		"homeassistant/sensor/alpha_a1b2c3d4/next_run/config",
		"homeassistant/sensor/alpha_a1b2c3d4/running/config",
		"homeassistant/sensor/alpha_a1b2c3d4/state/config",
	}
	if got := tb.retainedUnder("homeassistant/#"); !slices.Equal(got, want) {
		t.Fatalf("discovery topics\n got %v\nwant %v", got, want)
	}
	if !b.Status().Connected {
		t.Fatalf("status = %+v, want connected", b.Status())
	}
}

func TestEveryEntityBelongsToOneDevice(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	b := newTestBridge(t, newSource())
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	topics := tb.retainedUnder("homeassistant/#")
	if len(topics) != 6 {
		t.Fatalf("%d discovery topics, want 6", len(topics))
	}
	for _, topic := range topics {
		c := discoveryOf(t, tb, topic)
		device, _ := c["device"].(map[string]any)
		ids, _ := device["identifiers"].([]any)
		if len(ids) != 1 || ids[0] != "alpha_a1b2c3d4" || device["name"] != "Alpha (tower)" ||
			device["manufacturer"] != "Alpha" || device["model"] != "Alpha" || device["sw_version"] != "v1.2.0" {
			t.Errorf("%s: device %v", topic, device)
		}
		if c["availability_topic"] != "alpha/a1b2c3d4/availability" {
			t.Errorf("%s: availability_topic %v", topic, c["availability_topic"])
		}
	}
}

func TestUniqueIDsJoinTheInstanceAndTheKey(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	b := newTestBridge(t, newSource())
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	for key, topic := range map[string]string{
		"state": "homeassistant/sensor/alpha_a1b2c3d4/state/config",
		"run":   "homeassistant/button/alpha_a1b2c3d4/run/config",
	} {
		if id := discoveryOf(t, tb, topic)["unique_id"]; id != "alpha_a1b2c3d4_"+key {
			t.Errorf("%s: unique_id %v", topic, id)
		}
	}
}

func TestASensorReadsItsValueFromTheSharedState(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	b := newTestBridge(t, newSource())
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	c := discoveryOf(t, tb, "homeassistant/sensor/alpha_a1b2c3d4/free_space/config")
	for field, want := range map[string]any{
		"name":                        "Free space",
		"state_topic":                 "alpha/a1b2c3d4/state",
		"value_template":              "{{ value_json.free_space }}",
		"device_class":                "data_size",
		"unit_of_measurement":         "GB",
		"state_class":                 "measurement",
		"suggested_display_precision": 1.0,
	} {
		if c[field] != want {
			t.Errorf("%s = %v, want %v", field, c[field], want)
		}
	}
}

func TestAButtonPublishesPressToItsOwnTopic(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	b := newTestBridge(t, newSource())
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	c := discoveryOf(t, tb, "homeassistant/button/alpha_a1b2c3d4/run/config")
	if c["command_topic"] != "alpha/a1b2c3d4/press/run" || c["payload_press"] != "PRESS" || c["icon"] != "mdi:play" {
		t.Fatalf("button config %v", c)
	}
	if _, ok := c["state_topic"]; ok {
		t.Fatal("a button got a state topic")
	}
}

// Home Assistant rejects an enum value its options lack and keeps showing the
// last one, so a state the app forgot to list would freeze the sensor.
func TestOptionsMakeAnEnumSensor(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	b := newTestBridge(t, newSource())
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	c := discoveryOf(t, tb, "homeassistant/sensor/alpha_a1b2c3d4/state/config")
	opts, _ := c["options"].([]any)
	if c["device_class"] != "enum" || len(opts) != 5 || opts[2] != "overdue" {
		t.Fatalf("state sensor: device_class %v, options %v", c["device_class"], c["options"])
	}
	if st := stateOf(t, tb, cfg); st["state"] != "overdue" {
		t.Fatalf("state = %v, want overdue", st["state"])
	}
}

func TestAValueOutsideItsOptionsShowsUnknown(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	src := newSource()
	r := alphaReading()
	r.Values["state"] = "melting"
	src.set(r)
	b := newTestBridge(t, src)
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	st := stateOf(t, tb, cfg)
	if v, ok := st["state"]; !ok || v != nil {
		t.Fatalf("state = %v, want null", st["state"])
	}
}

func TestTheStateCarriesEverySensorAndNothingElse(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	src := newSource()
	r := alphaReading()
	r.Values["stray"] = 1
	src.set(r)
	b := newTestBridge(t, src)
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	st := stateOf(t, tb, cfg)
	if st["last_run"] != "2027-01-15T08:00:00Z" {
		t.Errorf("last_run = %v, want RFC 3339", st["last_run"])
	}
	for _, key := range []string{"next_run", "running"} {
		if v, ok := st[key]; !ok || v != nil {
			t.Errorf("%s = %v (present %v), want null", key, v, ok)
		}
	}
	for _, key := range []string{"stray", "run"} {
		if _, ok := st[key]; ok {
			t.Errorf("the state carries %s", key)
		}
	}
}

func TestAnEntityThatGoesAwayIsRemovedFromHomeAssistant(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	src := newSource()
	b := newTestBridge(t, src)
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	r := alphaReading()
	r.Entities = slices.DeleteFunc(r.Entities, func(e Entity) bool { return e.Kind == Button })
	src.set(r)
	if err := b.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the button is gone", func() bool {
		_, ok := tb.retained("homeassistant/button/alpha_a1b2c3d4/run/config")
		return !ok
	})
	if _, ok := tb.retained("homeassistant/sensor/alpha_a1b2c3d4/state/config"); !ok {
		t.Fatal("a sensor that stayed was removed")
	}
}

func TestDiscoveryLeftFromAnEarlierRunIsCleared(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	stale := "homeassistant/sensor/alpha_a1b2c3d4/gone/config"
	other := "homeassistant/sensor/beta_ffff/gone/config"
	tb.publish(stale, `{"name":"Gone"}`, true)
	tb.publish(other, `{"name":"Gone"}`, true)
	b := newTestBridge(t, newSource())
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	waitUntil(t, "the stale entity is cleared", func() bool {
		if err := b.Refresh(t.Context()); err != nil {
			t.Fatal(err)
		}
		_, ok := tb.retained(stale)
		return !ok
	})
	if _, ok := tb.retained(other); !ok {
		t.Fatal("the entity of another instance was cleared")
	}
}

func TestAButtonPressRunsItsButton(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	src := newSource()
	b := newTestBridge(t, src)
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	tb.publish(cfg.Topic+"/press/state", "PRESS", false)
	tb.publish(cfg.Topic+"/press/printer", "PRESS", false)
	tb.publish(cfg.Topic+"/press/run", "HOLD", false)
	tb.publish(cfg.Topic+"/press/run", "PRESS", false)
	expectPress(t, src, "run")
	expectNoPress(t, src, "a sensor, an unknown key or another payload")
}

// The broker replays a retained press to every new subscriber, so it would run
// the button again on each reconnect.
func TestARetainedPressRunsNothingOnReconnect(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	src := newSource()
	b := newTestBridge(t, src)
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	tb.publish(cfg.Topic+"/press/run", "PRESS", true)
	expectPress(t, src, "run")

	seen := tb.watch(cfg.Topic + "/availability")
	tb.drop(cfg.ID)
	waitUntil(t, "the bridge is back online", func() bool {
		got := seen()
		i := slices.Index(got, "offline")
		return i >= 0 && slices.Contains(got[i:], "online")
	})
	expectNoPress(t, src, "the retained press replayed on reconnect")
}

func TestAPressWhileTheLastOneRunsIsIgnored(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	src := newSource()
	hold := make(chan struct{})
	src.hold = hold
	r := alphaReading()
	r.Entities = append(r.Entities, Entity{Kind: Button, Key: "check", Name: "Check"})
	src.set(r)
	b := newTestBridge(t, src)
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	tb.publish(cfg.Topic+"/press/run", "PRESS", false)
	expectPress(t, src, "run")
	tb.publish(cfg.Topic+"/press/run", "PRESS", false)
	expectNoPress(t, src, "a second press while the first ran")
	tb.publish(cfg.Topic+"/press/check", "PRESS", false)
	expectPress(t, src, "check")

	src.mu.Lock()
	src.hold = nil
	src.mu.Unlock()
	close(hold)
	waitUntil(t, "the run button takes presses again", func() bool {
		tb.publish(cfg.Topic+"/press/run", "PRESS", false)
		select {
		case got := <-src.presses:
			return got == "run"
		case <-time.After(50 * time.Millisecond):
			return false
		}
	})
}

func TestPressesAreLimitedPerMinute(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	src := newSource()
	r := alphaReading()
	var keys []string
	for i := range pressesPerMinute + 1 {
		key := "b" + strconv.Itoa(i)
		keys = append(keys, key)
		r.Entities = append(r.Entities, Entity{Kind: Button, Key: key, Name: key})
	}
	src.set(r)
	b := newTestBridge(t, src)
	var clockMu sync.Mutex
	clock := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	}
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	for _, key := range keys[:pressesPerMinute] {
		tb.publish(cfg.Topic+"/press/"+key, "PRESS", false)
		expectPress(t, src, key)
	}
	last := keys[pressesPerMinute]
	tb.publish(cfg.Topic+"/press/"+last, "PRESS", false)
	expectNoPress(t, src, "a press over the limit")

	clockMu.Lock()
	clock = clock.Add(time.Minute + time.Second)
	clockMu.Unlock()
	tb.publish(cfg.Topic+"/press/"+last, "PRESS", false)
	expectPress(t, src, last)
}

func TestALostConnectionMarksTheDeviceUnavailableUntilItReturns(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	b := newTestBridge(t, newSource())
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	seen := tb.watch(cfg.Topic + "/availability")
	tb.drop(cfg.ID)
	waitUntil(t, "the last will marks the device offline and the reconnect online", func() bool {
		got := seen()
		i := slices.Index(got, "offline")
		return i >= 0 && slices.Contains(got[i:], "online")
	})
	waitUntil(t, "the bridge reports the connection again", func() bool { return b.Status().Connected })
}

func TestAReconnectRepublishesToABrokerThatForgotEverything(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	b := newTestBridge(t, newSource())
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	tb.restart()
	if got := tb.retainedOf(cfg); len(got) != 0 {
		t.Fatalf("the fresh broker holds %v", got)
	}
	waitAnnounced(t, tb, cfg)
	waitUntil(t, "discovery and state are back", func() bool {
		_, state := tb.retained(cfg.Topic + "/state")
		return state && len(tb.retainedUnder("homeassistant/#")) == 6
	})
}

func TestSwitchingOffRemovesTheDevice(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	b := newTestBridge(t, newSource())
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	off := cfg
	off.Enabled = false
	if err := b.Apply(off); err != nil {
		t.Fatal(err)
	}
	if left := tb.retainedOf(cfg); len(left) != 0 {
		t.Fatalf("retained after switching off: %v", left)
	}
	if b.Status().Connected {
		t.Fatal("still connected after switching off")
	}
	waitUntil(t, "the broker lets the client go", func() bool {
		_, ok := tb.server().Clients.Get(cfg.ID)
		return !ok
	})
}

func TestNewTopicsMoveTheDevice(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	b := newTestBridge(t, newSource())
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	moved := cfg
	moved.Topic = "home/alpha"
	if err := b.Apply(moved); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, moved)
	if old := tb.retainedUnder("alpha/#"); len(old) != 0 {
		t.Fatalf("the old topics are still retained: %v", old)
	}
	c := discoveryOf(t, tb, "homeassistant/sensor/alpha_a1b2c3d4/state/config")
	if c["state_topic"] != "home/alpha/state" {
		t.Fatalf("state_topic %v", c["state_topic"])
	}
}

func TestNewCredentialsKeepTheDevice(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	b := newTestBridge(t, newSource())
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	cleared := tb.watch("homeassistant/sensor/alpha_a1b2c3d4/state/config")
	login := cfg
	login.Broker.Username, login.Broker.Password = "ha", "secret"
	if err := b.Apply(login); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the bridge is back", func() bool { return b.Status().Connected })
	if slices.Contains(cleared(), "") {
		t.Fatal("a new password removed the device from Home Assistant")
	}
}

func TestShuttingDownLeavesTheDeviceUnavailable(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	b := newTestBridge(t, newSource())
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitAnnounced(t, tb, cfg)
	b.Close()
	if v, _ := tb.retained(cfg.Topic + "/availability"); v != "offline" {
		t.Fatalf("availability after shutdown = %q, want offline", v)
	}
	if _, ok := tb.retained("homeassistant/sensor/alpha_a1b2c3d4/state/config"); !ok {
		t.Fatal("shutting down removed the entities")
	}
}

func TestABrokerThatRefusesTheLoginIsReported(t *testing.T) {
	t.Parallel()
	tb := startBrokerWith(t, &auth.Ledger{Auth: auth.AuthRules{{Username: "ha", Password: "right", Allow: true}}})
	b := newTestBridge(t, newSource())
	cfg := alphaConfig(tb)
	cfg.Broker.Username, cfg.Broker.Password = "ha", "wrong"
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the refusal is reported", func() bool { return b.Status().Problem == Refused })
	if st := b.Status(); st.Connected || st.Error == "" {
		t.Fatalf("status = %+v", st)
	}
}

func TestABrokerThatDoesNotAnswerIsReported(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	cfg := alphaConfig(tb)
	tb.close()
	b := newTestBridge(t, newSource())
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the silence is reported", func() bool { return b.Status().Problem == Unreachable })
}

func TestABrokerThatComesUpLaterIsReached(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	cfg := alphaConfig(tb)
	tb.close()
	b := newTestBridge(t, newSource())
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the silence is reported", func() bool { return b.Status().Problem == Unreachable })
	tb.serve()
	waitAnnounced(t, tb, cfg)
}

func TestSwitchingOffWithoutTheBrokerSaysTheDeviceStays(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	cfg := alphaConfig(tb)
	tb.close()
	b := newTestBridge(t, newSource())
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	off := cfg
	off.Enabled = false
	if err := b.Apply(off); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("err = %v, want ErrNotConnected", err)
	}
}

func TestAConfigThatCannotWorkIsRefused(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	good := alphaConfig(tb)
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"no host", func(c *Config) { c.Broker.Host = "" }},
		{"port out of range", func(c *Config) { c.Broker.Port = 70000 }},
		{"wildcard in the topic", func(c *Config) { c.Topic = "alpha/#" }},
		{"empty topic level", func(c *Config) { c.Topic = "alpha//a1" }},
		{"slash in the id", func(c *Config) { c.ID = "alpha/a1" }},
		{"no id", func(c *Config) { c.ID = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := good
			tt.edit(&cfg)
			b := newTestBridge(t, newSource())
			if err := b.Apply(cfg); err == nil {
				t.Fatal("Apply took it")
			}
		})
	}
}

func TestAnEntityThatCannotWorkFailsTheRefresh(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		entity Entity
	}{
		{"key with a dot", Entity{Kind: Sensor, Key: "a.b", Name: "A"}},
		{"key starting with a digit", Entity{Kind: Sensor, Key: "1a", Name: "A"}},
		{"duplicate key", Entity{Kind: Button, Key: "state", Name: "A"}},
		{"unknown kind", Entity{Kind: "switch", Key: "power", Name: "A"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tb := startBroker(t)
			src := newSource()
			b := newTestBridge(t, src)
			cfg := alphaConfig(tb)
			if err := b.Apply(cfg); err != nil {
				t.Fatal(err)
			}
			waitAnnounced(t, tb, cfg)
			r := alphaReading()
			r.Entities = append(r.Entities, tt.entity)
			src.set(r)
			if err := b.Refresh(t.Context()); err == nil {
				t.Fatal("Refresh took it")
			}
		})
	}
}

func TestAFailedReadPublishesNothing(t *testing.T) {
	t.Parallel()
	tb := startBroker(t)
	src := newSource()
	src.readErr = errors.New("database locked")
	b := newTestBridge(t, src)
	cfg := alphaConfig(tb)
	if err := b.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	waitOnline(t, tb, cfg)
	if err := b.Refresh(t.Context()); err == nil {
		t.Fatal("Refresh hid the read error")
	}
	if got := tb.retainedUnder("homeassistant/#"); len(got) != 0 {
		t.Fatalf("published %v from a failed read", got)
	}
}
