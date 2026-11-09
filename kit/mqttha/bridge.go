package mqttha

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/eclipse/paho.mqtt.golang/packets"
)

// waitFor bounds every wait on the broker, so a dead one cannot hold up a
// settings save or a shutdown.
const waitFor = 5 * time.Second

// readFor bounds one reading of the source.
const readFor = 30 * time.Second

// pressesPerMinute caps the button presses the bridge acts on, whoever sends
// them.
const pressesPerMinute = 6

// Bridge keeps one connection to the broker and the device on it up to date.
// Its methods are safe for concurrent use.
type Bridge struct {
	src Source
	log *slog.Logger

	pollEvery  time.Duration
	retryEvery time.Duration
	now        func() time.Time

	applyMu   sync.Mutex
	refreshMu sync.Mutex

	mu     sync.Mutex
	cur    *session
	status Status
}

// New returns a bridge that is not connected yet. A nil log logs to
// slog.Default.
func New(src Source, log *slog.Logger) *Bridge {
	if log == nil {
		log = slog.Default()
	}
	return &Bridge{
		src:        src,
		log:        log,
		pollEvery:  15 * time.Second,
		retryEvery: 15 * time.Second,
		now:        time.Now,
	}
}

// session is one connection with the configuration it was made for. It lives
// from Apply to the next Apply or Close.
type session struct {
	cfg    Config
	client mqtt.Client
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	stopped bool
	// published is the discovery sent since the last connect; retained is
	// every discovery topic the broker keeps for the instance, ours and those
	// left by an earlier run.
	published map[string][]byte
	retained  map[string]bool
	state     []byte
	buttons   map[string]bool
	pending   map[string]bool
	pressed   []time.Time
}

// goUnlessStopped runs f in the session, unless it has stopped already.
func (s *session) goUnlessStopped(f func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	s.wg.Go(f)
	return true
}

func (s *session) stop() {
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
	s.cancel()
	s.wg.Wait()
}

// Status reports how the connection stands.
func (b *Bridge) Status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.status
}

// Apply switches the bridge to cfg. When the broker's address, the id or the
// topic changed, or cfg is switched off, the device is removed from Home
// Assistant first, so none is left behind under an old name; that returns
// ErrNotConnected when the old broker cannot be reached. New credentials
// alone only reconnect.
func (b *Bridge) Apply(cfg Config) error {
	if cfg.Enabled {
		if err := cfg.validate(); err != nil {
			return err
		}
	}
	b.applyMu.Lock()
	defer b.applyMu.Unlock()

	b.mu.Lock()
	old := b.cur
	b.mu.Unlock()
	if old != nil && old.cfg == cfg {
		return nil
	}
	var err error
	if old != nil {
		old.stop()
		if !cfg.Enabled || old.cfg.place() != cfg.place() {
			err = b.remove(old)
		}
		old.client.Disconnect(250)
	}
	b.mu.Lock()
	b.cur, b.status = nil, Status{}
	b.mu.Unlock()
	if cfg.Enabled {
		b.connect(cfg)
	}
	return err
}

// Close marks the device unavailable and disconnects, leaving its entities in
// Home Assistant for the next start.
func (b *Bridge) Close() {
	b.applyMu.Lock()
	defer b.applyMu.Unlock()
	b.mu.Lock()
	s := b.cur
	b.cur, b.status = nil, Status{}
	b.mu.Unlock()
	if s == nil {
		return
	}
	s.stop()
	if s.client.IsConnected() {
		s.client.Publish(s.cfg.availabilityTopic(), 1, true, "offline").WaitTimeout(waitFor)
	}
	s.client.Disconnect(250)
}

// Refresh reads the source and publishes what changed: the discovery of
// entities that came, went or look different, then the state. It does
// nothing while the bridge is not connected.
func (b *Bridge) Refresh(ctx context.Context) error {
	b.mu.Lock()
	s := b.cur
	b.mu.Unlock()
	if s == nil {
		return nil
	}
	return b.refresh(ctx, s)
}

func (b *Bridge) refresh(ctx context.Context, s *session) error {
	b.refreshMu.Lock()
	defer b.refreshMu.Unlock()
	if !s.client.IsConnected() {
		return nil
	}
	r, err := b.src.Read(ctx)
	if err != nil {
		return fmt.Errorf("mqttha: read the source: %w", err)
	}
	a, err := announce(s.cfg, r)
	if err != nil {
		return err
	}
	for key, v := range a.unlisted {
		b.log.Warn("a sensor's options lack its value, so it shows unknown", "sensor", key, "value", v)
	}

	// Publishing under the lock keeps a removal from overtaking it.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil
	}
	for topic := range s.retained {
		if _, ok := a.discovery[topic]; !ok {
			s.client.Publish(topic, 1, true, []byte{})
			delete(s.retained, topic)
			delete(s.published, topic)
		}
	}
	for topic, payload := range a.discovery {
		if !bytes.Equal(s.published[topic], payload) {
			s.client.Publish(topic, 1, true, payload)
			s.published[topic], s.retained[topic] = payload, true
		}
	}
	if !bytes.Equal(a.state, s.state) {
		s.client.Publish(s.cfg.stateTopic(), 1, true, a.state)
		s.state = a.state
	}
	s.buttons = a.buttons
	return nil
}

func (b *Bridge) connect(cfg Config) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{
		cfg:       cfg,
		ctx:       ctx,
		cancel:    cancel,
		published: map[string][]byte{},
		retained:  map[string]bool{},
		buttons:   map[string]bool{},
		pending:   map[string]bool{},
	}
	scheme := "tcp://"
	if cfg.Broker.TLS {
		scheme = "tls://"
	}
	opts := mqtt.NewClientOptions().
		AddBroker(scheme+net.JoinHostPort(cfg.host(), strconv.Itoa(cfg.Broker.Port))).
		SetClientID(cfg.ID).
		SetUsername(cfg.Broker.Username).
		SetPassword(cfg.Broker.Password).
		SetProtocolVersion(4).
		SetCleanSession(true).
		SetKeepAlive(30*time.Second).
		SetConnectTimeout(10*time.Second).
		SetWriteTimeout(waitFor).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(b.retryEvery).
		SetMaxReconnectInterval(4*b.retryEvery).
		SetOrderMatters(false).
		SetBinaryWill(cfg.availabilityTopic(), []byte("offline"), 1, true).
		SetOnConnectHandler(func(c mqtt.Client) { b.onConnect(s, c) }).
		SetConnectionNotificationHandler(func(_ mqtt.Client, n mqtt.ConnectionNotification) { b.notice(s, n) })
	if cfg.Broker.TLS {
		opts.SetTLSConfig(&tls.Config{ServerName: cfg.host(), MinVersion: tls.VersionTLS12})
	}
	s.client = mqtt.NewClient(opts)
	b.mu.Lock()
	b.cur = s
	b.mu.Unlock()
	// With connect retry on, the token only completes once a connection
	// stands; the notifications say why it does not.
	s.client.Connect()
	s.goUnlessStopped(func() { b.poll(s) })
}

func (b *Bridge) onConnect(s *session, c mqtt.Client) {
	b.log.Info("connected to the broker", "host", s.cfg.host())
	presses := c.Subscribe(s.cfg.pressTopic("+"), 1, func(_ mqtt.Client, m mqtt.Message) { b.onPress(s, m) })
	seen := c.Subscribe(s.cfg.discoveryFilter(), 1, func(_ mqtt.Client, m mqtt.Message) { s.noteRetained(m) })
	for _, t := range []mqtt.Token{presses, seen} {
		if !t.WaitTimeout(waitFor) || t.Error() != nil {
			b.log.Warn("could not subscribe, the device stays unavailable until the next connect", "error", t.Error())
			return
		}
	}
	b.setStatus(s, Status{Connected: true})

	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	// A broker without persistence has forgotten the retained messages, so
	// a reconnect sends everything again.
	s.published, s.state = map[string][]byte{}, nil
	c.Publish(s.cfg.availabilityTopic(), 1, true, "online")
	s.mu.Unlock()

	s.goUnlessStopped(func() {
		ctx, cancel := context.WithTimeout(s.ctx, readFor)
		defer cancel()
		if err := b.refresh(ctx, s); err != nil {
			b.log.Warn("could not publish the device", "error", err)
		}
	})
}

func (s *session) noteRetained(m mqtt.Message) {
	if !m.Retained() || len(m.Payload()) == 0 {
		return
	}
	s.mu.Lock()
	s.retained[m.Topic()] = true
	s.mu.Unlock()
}

func (b *Bridge) notice(s *session, n mqtt.ConnectionNotification) {
	switch n := n.(type) {
	case mqtt.ConnectionNotificationFailed:
		problem := Refused
		if errors.Is(n.Reason, packets.ErrorNetworkError) {
			problem = Unreachable
		}
		b.setStatus(s, Status{Problem: problem, Error: n.Reason.Error()})
	case mqtt.ConnectionNotificationLost:
		st := Status{Problem: Lost}
		if n.Reason != nil {
			st.Error = n.Reason.Error()
		}
		b.log.Warn("lost the connection to the broker", "host", s.cfg.host(), "error", n.Reason)
		b.setStatus(s, st)
	}
}

// setStatus records st unless s has been replaced in the meantime.
func (b *Bridge) setStatus(s *session, st Status) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cur == s {
		b.status = st
	}
}

func (b *Bridge) onPress(s *session, m mqtt.Message) {
	key, ok := strings.CutPrefix(m.Topic(), s.cfg.Topic+"/press/")
	if !ok || string(m.Payload()) != pressPayload {
		return
	}
	// The broker hands a retained press to every new subscriber, which would
	// run the button again on each reconnect.
	if m.Retained() {
		b.log.Info("ignored a retained press", "button", key)
		return
	}
	if why := s.takePress(key, b.now()); why != "" {
		b.log.Info("ignored a press", "button", key, "reason", why)
		return
	}
	ran := s.goUnlessStopped(func() {
		defer s.releasePress(key)
		if err := b.src.Press(s.ctx, key); err != nil {
			b.log.Warn("the button failed", "button", key, "error", err)
			return
		}
		b.log.Info("pressed", "button", key)
	})
	if !ran {
		s.releasePress(key)
	}
}

// takePress books a press of key, or says why it is refused.
func (s *session) takePress(key string, now time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.buttons[key] {
		return "the device has no such button"
	}
	if s.pending[key] {
		return "the last press still runs"
	}
	s.pressed = slices.DeleteFunc(s.pressed, func(at time.Time) bool { return now.Sub(at) >= time.Minute })
	if len(s.pressed) >= pressesPerMinute {
		return "too many presses in the last minute"
	}
	s.pressed = append(s.pressed, now)
	s.pending[key] = true
	return ""
}

func (s *session) releasePress(key string) {
	s.mu.Lock()
	delete(s.pending, key)
	s.mu.Unlock()
}

func (b *Bridge) poll(s *session) {
	tick := time.NewTicker(b.pollEvery)
	defer tick.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-tick.C:
			ctx, cancel := context.WithTimeout(s.ctx, readFor)
			if err := b.refresh(ctx, s); err != nil {
				b.log.Warn("could not refresh the device", "error", err)
			}
			cancel()
		}
	}
}

// remove clears every retained message of the instance, which makes Home
// Assistant drop the device and its entities.
func (b *Bridge) remove(s *session) error {
	if !s.client.IsConnected() {
		return ErrNotConnected
	}
	s.mu.Lock()
	topics := []string{s.cfg.stateTopic(), s.cfg.availabilityTopic()}
	for topic := range s.retained {
		topics = append(topics, topic)
	}
	s.mu.Unlock()
	var tokens []mqtt.Token
	for _, topic := range topics {
		tokens = append(tokens, s.client.Publish(topic, 1, true, []byte{}))
	}
	deadline := time.Now().Add(waitFor)
	for _, t := range tokens {
		if !t.WaitTimeout(time.Until(deadline)) {
			return ErrNotConnected
		}
		if err := t.Error(); err != nil {
			return fmt.Errorf("mqttha: remove the device: %w", err)
		}
	}
	return nil
}
