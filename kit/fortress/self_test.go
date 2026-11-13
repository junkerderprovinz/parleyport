package fortress

import (
	"net/netip"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/lan"
)

func TestANewDirectAddressGoesOutOnTheNetworkAtOnce(t *testing.T) {
	multicast(t)
	port := freePort(t)
	service := func() *lan.Service {
		s := lan.New(lan.Config{Group: netip.AddrPortFrom(netip.MustParseAddr("239.255.77.251"), port)})
		s.Start()
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	la := service()
	b := open(t, "bravo", "bravo-1", setup{lan: service(), noPair: true})
	waitFor(t, "alpha to hear bravo", func() bool { return announced(la, b.id) == b.srv.URL })

	moved := "http://192.168.77.9:4321"
	b.f.SetSelf(group.Self{Name: b.name, Deployment: "container", Address: moved, DirectURL: moved})
	waitFor(t, "bravo's new address on the network", func() bool { return announced(la, b.id) == moved })
}

// announced is the direct address id announces on l's network, as anyone
// there hears it.
func announced(l *lan.Service, id string) string {
	for _, p := range l.Strangers() {
		if p.ID == id {
			return p.URL
		}
	}
	return ""
}
