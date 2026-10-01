package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/internal/buildinfo"
)

func TestVersionFlagPrintsVersionAndCommit(t *testing.T) {
	defer func(v, c string) { buildinfo.Version, buildinfo.Commit = v, c }(buildinfo.Version, buildinfo.Commit)
	buildinfo.Version, buildinfo.Commit = "v1.2.3", "0123abcd"

	var out, errOut bytes.Buffer
	versionOnly, err := parseArgs([]string{"-version"}, &out, &errOut)
	if err != nil || !versionOnly {
		t.Fatalf("parseArgs(-version) = %v, %v; want true, nil", versionOnly, err)
	}
	if got := strings.TrimSpace(out.String()); got != "parleyport v1.2.3 (commit 0123abcd)" {
		t.Fatalf("printed %q", got)
	}
}

func TestNoArgumentsStartsTheRelay(t *testing.T) {
	var out, errOut bytes.Buffer
	versionOnly, err := parseArgs(nil, &out, &errOut)
	if err != nil || versionOnly {
		t.Fatalf("parseArgs() = %v, %v; want false, nil", versionOnly, err)
	}
	if out.Len() > 0 {
		t.Fatalf("printed %q", out.String())
	}
}

func TestUnknownFlagOrArgumentIsRefused(t *testing.T) {
	for _, args := range [][]string{{"-verison"}, {"--port", "80"}, {"serve"}} {
		var out, errOut bytes.Buffer
		if _, err := parseArgs(args, &out, &errOut); err == nil {
			t.Errorf("parseArgs(%q) accepted it", args)
		}
		if !strings.Contains(errOut.String(), "-version") {
			t.Errorf("parseArgs(%q) printed no usage: %q", args, errOut.String())
		}
	}
}

func TestSettingPrefersTheNewNameAndFallsBackToTheOldOne(t *testing.T) {
	t.Setenv("KL_RELAY_DOMAIN", "relay.example.org")
	if got := setting("DOMAIN", ""); got != "relay.example.org" {
		t.Fatalf("with only KL_RELAY_DOMAIN set, got %q", got)
	}
	t.Setenv("PARLEYPORT_DOMAIN", "parley.example.org")
	if got := setting("DOMAIN", ""); got != "parley.example.org" {
		t.Fatalf("with both set, got %q", got)
	}
	if got := setting("CERT_DIR", "/fallback"); got != "/fallback" {
		t.Fatalf("with neither set, got %q", got)
	}
}
