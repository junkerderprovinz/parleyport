package relay

import (
	"testing"
	"time"
)

func TestReplayGuardAdmitsACallOnceWithinTheSkew(t *testing.T) {
	g := NewReplayGuard()
	now := time.Unix(1_800_000_000, 0)
	g.now = func() time.Time { return now }
	key := keyNumber(1)
	call := ProxyCall{ID: "a", Sent: now.Unix(), Key: key}
	if !g.Admit(call) || g.Admit(call) {
		t.Fatal("a fresh call must pass once and only once")
	}
	for name, c := range map[string]ProxyCall{
		"old":       {ID: "b", Sent: now.Add(-ClockSkew - time.Second).Unix(), Key: key},
		"future":    {ID: "c", Sent: now.Add(ClockSkew + time.Second).Unix(), Key: key},
		"unstamped": {ID: "", Sent: now.Unix(), Key: key},
	} {
		if g.Admit(c) {
			t.Errorf("an %s call was admitted", name)
		}
	}
	now = now.Add(3 * ClockSkew)
	if !g.Admit(ProxyCall{ID: "d", Sent: now.Unix(), Key: key}) || g.Len() != 1 {
		t.Fatalf("remembered %d ids, want only the one from inside the window", len(g.seen))
	}
}

func TestOneMembersCallsCannotUseUpAnothersIDs(t *testing.T) {
	g := NewReplayGuard()
	now := time.Unix(1760000000, 0)
	g.now = func() time.Time { return now }
	honest := identityFrom(2).Public()
	forger := identityFrom(3).Public()

	if !g.Admit(ProxyCall{ID: "next", Sent: now.Unix(), Key: forger}) {
		t.Fatal("the forger's own call was refused")
	}
	if !g.Admit(ProxyCall{ID: "next", Sent: now.Unix(), Key: honest}) {
		t.Error("a member's call was refused because another key sent its id first")
	}
	if g.Admit(ProxyCall{ID: "next", Sent: now.Unix(), Key: honest}) {
		t.Error("the same member's call ran twice")
	}

	for i := 0; i < maxSeenPerMember; i++ {
		g.Admit(ProxyCall{ID: string(rune(0x1000 + i)), Sent: now.Unix(), Key: forger})
	}
	if g.Admit(ProxyCall{ID: "one more", Sent: now.Unix(), Key: forger}) {
		t.Error("one key kept more ids on record than maxSeenPerMember")
	}
	if !g.Admit(ProxyCall{ID: "after the flood", Sent: now.Unix(), Key: honest}) {
		t.Error("a key that filled its own record kept another member out")
	}
}

func TestACallWithoutAKeyIsNeverRecorded(t *testing.T) {
	g := NewReplayGuard()
	now := time.Unix(1760000000, 0)
	g.now = func() time.Time { return now }
	for i := 0; i < 10; i++ {
		if g.Admit(ProxyCall{ID: string(rune(0x1000 + i)), Sent: now.Unix(), From: "phone-flood"}) {
			t.Fatal("a call without a key was admitted")
		}
	}
	if n := g.Len(); n != 0 {
		t.Errorf("the guard kept %d ids of calls without a key, want none", n)
	}
}

// TestManyKeysCostTheGuardLittle admits one call from each of many keys. A
// guard that looks at every key on every call takes seconds for this.
func TestManyKeysCostTheGuardLittle(t *testing.T) {
	g := NewReplayGuard()
	now := time.Unix(1760000000, 0)
	g.now = func() time.Time { return now }
	const keys = 40000
	start := time.Now()
	for i := range keys {
		if !g.Admit(ProxyCall{ID: "only", Sent: now.Unix(), Key: keyNumber(i)}) {
			t.Fatalf("call %d of a new key was refused", i)
		}
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("admitting %d keys took %s", keys, took)
	}
	now = now.Add(2*ClockSkew + time.Second)
	if !g.Admit(ProxyCall{ID: "later", Sent: now.Unix(), Key: keyNumber(0)}) || len(g.seen) != 1 {
		t.Errorf("%d keys on record once the old ids ran out, want only the newest", len(g.seen))
	}
}

// TestManyFullRecordsKeepNoOtherKeyOut fills the records of seventeen keys.
// Each full record refuses only its own key's calls.
func TestManyFullRecordsKeepNoOtherKeyOut(t *testing.T) {
	g := NewReplayGuard()
	now := time.Unix(1760000000, 0)
	g.now = func() time.Time { return now }
	for k := range 17 {
		for i := range maxSeenPerMember {
			g.Admit(ProxyCall{ID: string(rune(0x1000 + i)), Sent: now.Unix(), Key: keyNumber(k)})
		}
	}
	if g.Admit(ProxyCall{ID: "over", Sent: now.Unix(), Key: keyNumber(0)}) {
		t.Error("a full record took one more id instead of refusing it")
	}
	if !g.Admit(ProxyCall{ID: "member", Sent: now.Unix(), Key: keyNumber(1 << 20)}) {
		t.Error("another key's call was refused because other records were full")
	}
	now = now.Add(2*ClockSkew + time.Second)
	if !g.Admit(ProxyCall{ID: "over", Sent: now.Unix(), Key: keyNumber(0)}) {
		t.Error("the guard still refused a key's calls once its ids had run out")
	}
}
