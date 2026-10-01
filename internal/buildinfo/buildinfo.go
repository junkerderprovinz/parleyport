// Package buildinfo carries the build version, stamped at release time via
// -ldflags "-X github.com/junkerderprovinz/parleyport/internal/buildinfo.Version=vX.Y.Z".
package buildinfo

import "runtime/debug"

// Version is the running build; "dev" for untagged local builds.
var Version = "dev"

// Commit is the source revision, stamped like Version. Read it through
// Revision.
var Commit = ""

// Revision is the commit this build came from, or "" when nothing knows it.
//
// The ldflags stamp comes first because the container build excludes .git
// and so gets no VCS stamp from the toolchain.
func Revision() string {
	if Commit != "" {
		return Commit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
	}
	return ""
}

// Describe is the line a -version flag prints: the program, Version and, when
// it is known, the Revision.
func Describe(program string) string {
	s := program + " " + Version
	if r := Revision(); r != "" {
		s += " (commit " + r + ")"
	}
	return s
}
