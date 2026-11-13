package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/phrase"
)

func TestAPluginThatLeavesIsDroppedByTheOthersAndForgetsTheFortress(t *testing.T) {
	url := relayServer(t)
	a := openApp(t, url)
	dir := t.TempDir()
	words, err := phrase.Encode(secret)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := cli(t, words+"\n", "join", "-dir", dir, "-app", "watcher", "-name", "tower", "-relay", url); code != 0 {
		t.Fatalf("join: %d %s", code, stderr)
	}
	if code, _, stderr := cli(t, "", "members", "-dir", dir, "-wait", "3s"); code != 0 {
		t.Fatalf("members: %d %s", code, stderr)
	}
	watcher := func() bool {
		for _, m := range a.f.Members() {
			if m.App.ID == "watcher" {
				return true
			}
		}
		return false
	}
	if !watcher() {
		t.Fatal("alpha does not know the plugin")
	}

	if code, _, stderr := cli(t, "", "leave", "-dir", dir, "-wait", "3s"); code != 0 {
		t.Fatalf("leave: %d %s", code, stderr)
	}
	if watcher() {
		t.Error("alpha still lists the plugin after it left")
	}
	if _, err := os.Stat(filepath.Join(dir, "fortress.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the membership is still there: %v", err)
	}
}
