package group

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/junkerderprovinz/parleyport/kit/relay"
)

func TestAMemberOfAnOlderVersionIsNamedApart(t *testing.T) {
	url := relayServer(t)
	var changes atomic.Int32
	a := open(t, "alpha", setup{relay: url, onChange: func() { changes.Add(1) }})
	waitFor(t, "alpha on the relay", a.g.RelayConnected)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(url, "http")+"/relay/connect", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.CloseNow() }()
	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatal(err)
	}
	const id = "0123456789abcdef0123456789abcdef"
	sealed, err := relay.SealIdentity(testDomain.FrameKey(testSecret), id, relay.Identity{Name: "attic"})
	if err != nil {
		t.Fatal(err)
	}
	hello, err := relay.Encode(relay.TypeHello, relay.Hello{Key: testDomain.GroupKey(testSecret), Announce: relay.Announce{InstanceID: id, Sealed: sealed}})
	if err != nil {
		t.Fatal(err)
	}
	before := changes.Load()
	if err := conn.Write(ctx, websocket.MessageText, hello); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alpha to name the older member", func() bool {
		o := a.g.Older()
		return len(o) == 1 && o[0] == "attic"
	})
	waitFor(t, "alpha to say something changed", func() bool { return changes.Load() > before })
	if len(a.g.Members()) != 0 {
		t.Fatalf("the older member is listed: %+v", a.g.Members())
	}
	_ = conn.CloseNow()
	waitFor(t, "the older member to go", func() bool { return len(a.g.Older()) == 0 })
}
