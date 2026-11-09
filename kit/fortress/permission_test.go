package fortress

import (
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/relay"
)

func on(perms []Permission, from, to, action string) bool {
	for _, p := range perms {
		if p.From == from && p.To == to && p.Action == action {
			return p.On
		}
	}
	return false
}

func TestPermissionsListWhatAppsUseAtEachOther(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1", "bravo", "bravo-1")
	a, b := n[0], n[1]
	meet(t, a, b)

	got := a.f.Permissions()
	want := []Permission{
		{From: "alpha", To: "alpha", Action: "files.drop", On: true},
		{From: "alpha", To: "bravo", Action: "files.drop", On: true},
		{From: "bravo", To: "alpha", Action: "files.drop", On: true},
		{From: "bravo", To: "bravo", Action: "files.drop", On: true},
	}
	if len(got) != len(want) {
		t.Fatalf("alpha lists %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].From != want[i].From || got[i].To != want[i].To || got[i].Action != want[i].Action || !got[i].On {
			t.Errorf("permission %d is %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSetPermissionRefusesWhatIsNoPermission(t *testing.T) {
	n := inRelay(t, "alpha", "alpha-1")
	for _, p := range [][3]string{{"", "bravo", "files.drop"}, {"alpha", "Bravo!", "files.drop"}, {"alpha", "bravo", "drop"}} {
		if err := n[0].f.SetPermission(p[0], p[1], p[2], false); err == nil {
			t.Errorf("SetPermission%v took it", p)
		}
	}
}

func TestTheLaterSwitchWins(t *testing.T) {
	now := time.Now()
	key := permissionKey{From: "alpha", To: "bravo", Action: "files.drop"}
	table := permissionTable{}
	if !table.merge(key, switchState{On: false, At: now, By: "b"}, now) {
		t.Fatal("a first switch was not taken")
	}
	if table.merge(key, switchState{On: true, At: now.Add(-time.Second), By: "c"}, now) {
		t.Error("an older switch replaced a newer one")
	}
	if table.merge(key, switchState{On: true, At: now, By: "a"}, now) {
		t.Error("a switch at the same time from a smaller id replaced the one there")
	}
	if !table.merge(key, switchState{On: true, At: now, By: "c"}, now) {
		t.Error("a switch at the same time from a larger id was not taken")
	}
	if table.merge(key, switchState{On: false, At: now.Add(2 * relay.ClockSkew), By: "d"}, now) {
		t.Error("a switch from the future was taken, which would stick until then")
	}
	if !table[key].On {
		t.Error("the table lost the switch that won")
	}
}

func TestAMemberAwayCatchesUpOnThePermissions(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url})
	b := open(t, "bravo", "bravo-1", setup{relay: url})
	waitFor(t, "both on the relay", func() bool { return len(a.f.Members()) == 1 && len(b.f.Members()) == 1 })
	meet(t, a, b)
	if err := b.f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.f.SetPermission("alpha", "bravo", "files.drop", false); err != nil {
		t.Fatal(err)
	}
	b.f = reopen(t, b, setup{relay: url})
	waitFor(t, "bravo to catch up", func() bool { return !on(b.f.Permissions(), "alpha", "bravo", "files.drop") })
}
