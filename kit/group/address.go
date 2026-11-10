package group

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/lan"
)

// Addresses somebody names rather than announces: the one a prober gives for
// itself, one the owner types in, one a member last answered at. Each is
// dialed only when it is a private IPv4 address or the loopback on a port of
// the group, so whoever names one cannot point this instance at a host or a
// service of their choosing.

// maxAddresses bounds the addresses an app keeps for its group.
const maxAddresses = 32

// Errors of Probe and SetAddresses.
var (
	// ErrStranger is what answers at an address that is no member of the
	// group, such as an instance paired under another phrase.
	ErrStranger = errors.New("group: what answers there is no member of this group")
	// ErrSelf is an address this instance answers at itself.
	ErrSelf = errors.New("group: that address is this instance's own")
	// ErrNotNearby is an address that is not a private IPv4 address or the
	// loopback on a port of the group.
	ErrNotNearby = errors.New("group: the address is not a private one on a port of the group")
)

// Probe asks whoever answers at addr, the address of an instance's web
// interface, who it is. A member of the group that answers is listed as
// reachable there and pinned under the key its answer is signed with, as if
// it had called: approved where the phrase is enough, else waiting for
// approval. It is how an instance that takes no direct calls, such as a
// desktop app, finds the others on its network.
func (g *Group) Probe(ctx context.Context, addr string) (Member, error) {
	base, ok := g.nearby(addr)
	if !ok {
		return Member{}, ErrNotNearby
	}
	h, err := g.probe(ctx, base)
	if err != nil {
		return Member{}, err
	}
	m, ok := g.look(time.Now())[h.ID]
	if !ok {
		return Member{}, ErrRemoved
	}
	return *m, nil
}

// SetAddresses keeps addrs as where instances of the group may answer, for a
// network where nobody announces them. They are probed when the group opens
// and again whenever no member answered there for a while. An address that is
// not nearby refuses the whole list.
func (g *Group) SetAddresses(addrs []string) error {
	if len(addrs) > maxAddresses {
		return fmt.Errorf("group: at most %d addresses", maxAddresses)
	}
	known := make([]string, 0, len(addrs))
	for _, a := range addrs {
		base, ok := g.nearby(a)
		if !ok {
			return fmt.Errorf("%w: %s", ErrNotNearby, a)
		}
		if !slices.Contains(known, base) {
			known = append(known, base)
		}
	}
	g.mu.Lock()
	g.st.Known = known
	err := g.saveLocked()
	g.mu.Unlock()
	g.poke()
	return err
}

// Addresses returns the addresses SetAddresses keeps, each as scheme, host
// and port.
func (g *Group) Addresses() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.st.Known)
}

// nearby is addr cut to scheme, host and port when it may be dialed.
func (g *Group) nearby(addr string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(addr))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return "", false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return "", false
	}
	ip = ip.Unmap()
	if !lan.PrivateIPv4(ip) && !ip.IsLoopback() {
		return "", false
	}
	port := portOf(u)
	if !slices.Contains(g.ports, port) {
		own, err := url.Parse(g.directURL())
		if err != nil || own.Host == "" || portOf(own) != port {
			return "", false
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(ip.String(), port), true
}

func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}

func portNames(ports []int) []string {
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = strconv.Itoa(p)
	}
	return out
}
