// Package lan lets the members of a group on one network find each other with
// nothing configured, so they can call each other directly instead of over the
// relay.
//
// Every instance sends a small JSON announce to a UDP multicast group of its
// app. Anything on the network can send to that group, so the caller decides
// who counts: a member proves itself with a tag only members can compute, and
// every other announce is listed apart as a stranger, without the address it
// claims. Where multicast does not reach, such as from a container on a Docker
// bridge, Neighbours lists the addresses a sweep of the own network would try.
package lan

import (
	"encoding/json"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/junkerderprovinz/parleyport/kit/relay"
)

const (
	// announceEvery is how often an instance announces itself: one small
	// datagram per instance and interface.
	announceEvery = 5 * time.Second
	// peerTTL keeps a peer listed through a couple of dropped datagrams, so
	// it does not flicker in and out.
	peerTTL   = 3*announceEvery + 2*time.Second
	readLimit = 8 << 10
	// fieldLimit and maxPeers bound what a sender that is not a member can
	// make this process hold. A field over the limit drops the announce
	// rather than being cut, since a tag covers the field as it was sent and a
	// cut address leads somewhere else.
	fieldLimit = 256
	maxPeers   = 256
)

// Config is where the instances of one app meet.
type Config struct {
	// Group is the multicast address and port, in the administratively scoped
	// 239.255/16 (RFC 2365), which routers do not forward beyond the network.
	Group netip.AddrPort
	// Ports are what a sweep tries on every neighbour besides the port of the
	// instance's own address: the ports the app listens on by default.
	Ports []int
}

// Peer is one instance's announce.
type Peer struct {
	// ID is the id the instance goes by in its group, or its own id outside
	// one. It is always 40 lowercase hex digits.
	ID   string `json:"id"`
	Name string `json:"name"`
	// URL is where the instance takes direct calls.
	URL string `json:"url"`
	// Deployment is how the instance runs, such as "container" or "desktop".
	Deployment string `json:"deployment"`
	// Address is where the instance's web interface is. Only a member's is
	// kept, since a domain is nothing to tell every device on the network.
	Address string `json:"address,omitempty"`
	// Sent is the Unix time the announce went out and Tag the membership proof
	// over it and the fields above, empty outside a group. The tag covers the
	// time, so a captured announce stops passing once it is old.
	Sent int64  `json:"sent,omitempty"`
	Tag  string `json:"tag,omitempty"`
	// LastSeen is set by the receiver, never sent.
	LastSeen time.Time `json:"-"`
}

// Service announces this instance and tracks the others. A host without
// multicast simply sees nobody; nothing reports an error after Start, so the
// network failing never stops anything else.
type Service struct {
	cfg Config

	mu        sync.Mutex
	self      Peer
	sign      func(Peer) string
	accept    func(Peer) bool
	members   map[string]Peer
	strangers map[string]Peer

	conn *ipv4.PacketConn
	// started means somebody will close done: Start either closes it or hands
	// that to announceLoop. closing makes a Start after Close return without
	// opening a socket nothing would close.
	started bool
	closing bool

	kick chan struct{}
	quit chan struct{}
	done chan struct{}
	once sync.Once
}

// New returns a Service for cfg that announces nothing and takes nobody for a
// member until SetSelf and SetAccept say otherwise.
func New(cfg Config) *Service {
	return &Service{
		cfg:       cfg,
		members:   map[string]Peer{},
		strangers: map[string]Peer{},
		kick:      make(chan struct{}, 1),
		quit:      make(chan struct{}),
		done:      make(chan struct{}),
	}
}

// Config is where the Service meets the others.
func (s *Service) Config() Config { return s.cfg }

// SetSelf replaces what this instance announces and sends it at once. An empty
// ID or URL stops the announcing. Each announce is stamped with the time it
// goes out and tagged with what sign returns for it; without sign it carries
// no tag and no Address.
func (s *Service) SetSelf(self Peer, sign func(Peer) string) {
	s.mu.Lock()
	s.self, s.sign = self, sign
	s.mu.Unlock()
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// SetAccept replaces the membership check and forgets every member the old
// one admitted, so leaving a group empties the list at once. accept runs under
// the Service's lock and must not call back into it.
func (s *Service) SetAccept(accept func(Peer) bool) {
	s.mu.Lock()
	s.accept = accept
	s.members = map[string]Peer{}
	s.mu.Unlock()
}

// Start joins the multicast group and begins announcing. It never blocks.
func (s *Service) Start() {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.mu.Unlock()

	addr := net.UDPAddrFromAddrPort(s.cfg.Group)
	c, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		close(s.done)
		return
	}
	// The standard library joins on one interface only and turns loopback
	// off, which on a host with several networks delivered nothing at all.
	p := ipv4.NewPacketConn(c)
	_ = p.SetMulticastLoopback(true)
	joined := 0
	for _, ifc := range multicastInterfaces() {
		if p.JoinGroup(&ifc, addr) == nil {
			joined++
		}
	}
	if joined == 0 {
		_ = p.Close()
		close(s.done)
		return
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		_ = p.Close()
		close(s.done)
		return
	}
	s.conn = p
	s.mu.Unlock()
	go s.readLoop(p)
	go s.announceLoop(p, addr)
}

// Close stops announcing and listening. It is safe to call more than once and
// on a Service that never started.
func (s *Service) Close() error {
	s.mu.Lock()
	conn, started := s.conn, s.started
	first := !s.closing
	s.closing = true
	s.mu.Unlock()

	s.once.Do(func() {
		close(s.quit)
		if conn != nil {
			_ = conn.Close()
		}
	})
	if started {
		<-s.done
		return nil
	}
	if first {
		close(s.done)
	}
	return nil
}

func (s *Service) listening() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn != nil
}

// Members is every member seen recently, this instance excluded, sorted by
// name.
func (s *Service) Members() []Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now().Add(-peerTTL))
	return sorted(s.members)
}

// Strangers is every other instance of the app seen recently that is no
// member, sorted by name, for an app that offers to add one by address.
func (s *Service) Strangers() []Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now().Add(-peerTTL))
	return sorted(s.strangers)
}

func sorted(m map[string]Peer) []Peer {
	out := make([]Peer, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *Service) pruneLocked(cutoff time.Time) {
	for _, m := range []map[string]Peer{s.members, s.strangers} {
		for id, p := range m {
			if p.LastSeen.Before(cutoff) {
				delete(m, id)
			}
		}
	}
}

func (s *Service) announceLoop(conn *ipv4.PacketConn, addr *net.UDPAddr) {
	defer close(s.done)
	t := time.NewTicker(announceEvery)
	defer t.Stop()
	for {
		s.announce(conn, addr)
		select {
		case <-s.quit:
			return
		case <-t.C:
		case <-s.kick:
		}
	}
}

func (s *Service) announce(conn *ipv4.PacketConn, addr *net.UDPAddr) {
	s.mu.Lock()
	self, sign := s.self, s.sign
	s.mu.Unlock()
	if self.ID == "" || self.URL == "" {
		return
	}
	self.Sent = time.Now().Unix()
	self.Tag = ""
	if sign != nil {
		self.Tag = sign(self)
	} else {
		self.Address = ""
	}
	payload, err := json.Marshal(self)
	if err != nil {
		return
	}
	// Out of every interface, since on a NAS with a Docker bridge the routing
	// table can pick the wrong one.
	for _, ifc := range multicastInterfaces() {
		if conn.SetMulticastInterface(&ifc) == nil {
			_, _ = conn.WriteTo(payload, nil, addr)
		}
	}
}

func (s *Service) readLoop(conn *ipv4.PacketConn) {
	buf := make([]byte, readLimit)
	for {
		n, _, _, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		var p Peer
		if json.Unmarshal(buf[:n], &p) != nil {
			continue
		}
		s.Observe(p)
	}
}

// Observe files one announce as if it had arrived over the network.
func (s *Service) Observe(p Peer) {
	if !relay.ValidInstanceID(p.ID) || p.URL == "" || len(p.URL) > fieldLimit || len(p.Name) > fieldLimit ||
		len(p.Deployment) > fieldLimit || len(p.Address) > fieldLimit || len(p.Tag) > fieldLimit {
		return
	}
	p.LastSeen = time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ID == s.self.ID {
		return
	}
	member := s.accept != nil && p.Tag != "" && s.accept(p)
	into := s.strangers
	if member {
		into = s.members
		// Datagrams can arrive out of order, and an older announce played
		// back must not bring back an address the member has since left.
		if known, ok := into[p.ID]; ok && p.Sent < known.Sent {
			return
		}
		delete(s.strangers, p.ID)
	} else {
		// A stranger announcing a member's id lands in its own list and
		// never moves the member.
		p.Address = ""
	}
	if _, known := into[p.ID]; !known && len(into) >= maxPeers {
		s.pruneLocked(time.Now().Add(-peerTTL))
		if len(into) >= maxPeers {
			return
		}
	}
	into[p.ID] = p
}

func multicastInterfaces() []net.Interface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := ifs[:0]
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagMulticast != 0 {
			out = append(out, ifc)
		}
	}
	return out
}
