package hostpath

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

// unraid is the mountinfo of a container on Unraid: its configuration and
// downloads from user shares, backups straight from a disk, a share with a
// space in its name, and a share mounted inside another one.
const unraid = `1203 1012 0:345 / / rw,relatime master:530 - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/ABC:/var/lib/docker/overlay2/l/DEF,upperdir=/var/lib/docker/overlay2/1f/diff,workdir=/var/lib/docker/overlay2/1f/work
1204 1203 0:350 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1205 1203 0:351 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
1206 1205 0:352 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
1207 1203 0:353 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
1210 1203 0:46 /appdata/loader /config rw,noatime - fuse.shfs shfs rw,user_id=0,group_id=0,default_permissions,allow_other
1211 1203 0:46 /downloads /downloads rw,noatime - fuse.shfs shfs rw,user_id=0,group_id=0,default_permissions,allow_other
1212 1211 0:46 /isos /downloads/incoming rw,noatime - fuse.shfs shfs rw,user_id=0,group_id=0,default_permissions,allow_other
1213 1203 9:1 /backups /backups rw,noatime - xfs /dev/md1p1 rw,attr2,inode64,noquota
1214 1203 0:46 /media/My\040Films /films rw,noatime - fuse.shfs shfs rw,user_id=0,group_id=0,default_permissions,allow_other
1215 1203 8:17 /var/lib/docker/containers/4b1d/hostname /etc/hostname rw,relatime - btrfs /dev/sdb1 rw,space_cache=v2
`

// native is the mountinfo of a program running straight on a Linux machine.
const native = `22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw,errors=remount-ro
23 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw
24 22 0:5 / /dev rw,nosuid,relatime shared:2 - devtmpfs udev rw,size=8000000k
25 22 8:3 / /home rw,relatime shared:30 - ext4 /dev/sda3 rw
`

func table(t *testing.T, mountinfo string) Table {
	t.Helper()
	tab, err := Parse(strings.NewReader(mountinfo))
	if err != nil {
		t.Fatal(err)
	}
	return tab
}

func TestAFolderInTheContainerHasItsHostPath(t *testing.T) {
	tab := table(t, unraid)
	for in, want := range map[string]string{
		"/downloads":                "/mnt/user/downloads",
		"/downloads/tv/Show S01":    "/mnt/user/downloads/tv/Show S01",
		"/downloads/incoming/a.iso": "/mnt/user/isos/a.iso",
		"/config":                   "/mnt/user/appdata/loader",
		"/backups/2026":             "/dev/block/9:1/backups/2026",
		"/films/Heat (1995)":        "/mnt/user/media/My Films/Heat (1995)",
		"/downloadsextra":           "",
		"/app/data":                 "",
		"/proc/self":                "",
		"/dev/pts/0":                "",
	} {
		got, err := tab.ToHost(in)
		switch {
		case want == "" && !errors.Is(err, ErrNotMounted):
			t.Errorf("ToHost(%q) = %q, %v; want ErrNotMounted", in, got, err)
		case want != "" && (err != nil || got != want):
			t.Errorf("ToHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestAHostPathHasItsFolderInTheContainer(t *testing.T) {
	tab := table(t, unraid)
	for in, want := range map[string]string{
		"/mnt/user/downloads":                  "/downloads",
		"/mnt/user/downloads/tv":               "/downloads/tv",
		"/mnt/user/isos/a.iso":                 "/downloads/incoming/a.iso",
		"/mnt/user/appdata/loader/state":       "/config/state",
		"/dev/block/9:1/backups":               "/backups",
		"/backups":                             "",
		"/mnt/user/media/My Films/Heat (1995)": "/films/Heat (1995)",
		// Hidden under the share mounted inside it.
		"/mnt/user/downloads/incoming/a.iso": "",
		"/mnt/user/music":                    "",
		"/mnt/user/appdata/other":            "",
		"/mnt/disk1/backups":                 "",
		"/var/lib/docker/overlay2":           "",
	} {
		got, err := tab.FromHost(in)
		switch {
		case want == "" && !errors.Is(err, ErrNotMounted):
			t.Errorf("FromHost(%q) = %q, %v; want ErrNotMounted", in, got, err)
		case want != "" && (err != nil || got != want):
			t.Errorf("FromHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestOnTheMachineItselfAPathIsItsOwnHostPath(t *testing.T) {
	tab := table(t, native)
	for _, p := range []string{"/", "/srv/media", "/home/ana/Downloads"} {
		if got, err := tab.ToHost(p); err != nil || got != p {
			t.Errorf("ToHost(%q) = %q, %v", p, got, err)
		}
		if got, err := tab.FromHost(p); err != nil || got != p {
			t.Errorf("FromHost(%q) = %q, %v", p, got, err)
		}
	}
}

func TestWithoutMountinfoAPathIsItsOwnHostPath(t *testing.T) {
	var tab Table
	paths := []string{"/srv/media"}
	if runtime.GOOS == "windows" {
		paths = append(paths, `C:\Users\ana\Downloads`)
	}
	for _, p := range paths {
		if got, err := tab.ToHost(p); err != nil || got != p {
			t.Errorf("ToHost(%q) = %q, %v", p, got, err)
		}
		if got, err := tab.FromHost(p); err != nil || got != p {
			t.Errorf("FromHost(%q) = %q, %v", p, got, err)
		}
	}
}

func TestOnlyCleanAbsolutePathsAreTaken(t *testing.T) {
	for _, tab := range []Table{table(t, unraid), {}} {
		for _, p := range []string{"", "downloads", "/downloads/../config", "/mnt/user/../user/downloads", "/downloads/", "/downloads//tv", "/downloads/./tv"} {
			if _, err := tab.ToHost(p); !errors.Is(err, ErrUnclean) {
				t.Errorf("ToHost(%q): %v, want ErrUnclean", p, err)
			}
			if _, err := tab.FromHost(p); !errors.Is(err, ErrUnclean) {
				t.Errorf("FromHost(%q): %v, want ErrUnclean", p, err)
			}
		}
	}
}

func TestBrokenMountinfoIsAnError(t *testing.T) {
	for _, line := range []string{
		"1210 1203 0:46 /appdata /config rw,noatime fuse.shfs shfs rw",
		"1210 1203 0:46 /appdata",
		"1210 1203 0:46 appdata /config rw - fuse.shfs shfs rw",
		"1210 1203 sdb1 /appdata /config rw - xfs /dev/sdb1 rw",
	} {
		if _, err := Parse(strings.NewReader(line + "\n")); err == nil {
			t.Errorf("Parse took %q", line)
		}
	}
}

func TestSharedListsTheMountsThatHoldHostFolders(t *testing.T) {
	var points []string
	for _, m := range table(t, unraid).Shared() {
		points = append(points, m.Point)
	}
	want := []string{"/config", "/downloads", "/downloads/incoming", "/backups", "/films", "/etc/hostname"}
	if strings.Join(points, " ") != strings.Join(want, " ") {
		t.Errorf("Shared lists %v, want %v", points, want)
	}
	if got := table(t, native).Shared(); len(got) != 0 {
		t.Errorf("on the host itself Shared lists %v", got)
	}
}

// twoDisks mounts a folder of the same name from two disks of one host.
const twoDisks = `1203 1012 0:345 / / rw,relatime - overlay overlay rw
1213 1203 9:1 /backups /backups1 rw,noatime - xfs /dev/md1p1 rw
1214 1203 9:2 /backups /backups2 rw,noatime - xfs /dev/md2p1 rw
`

func TestTwoDisksWithTheSamePathStayApart(t *testing.T) {
	tab := table(t, twoDisks)
	one, err := tab.ToHost("/backups1/a")
	if err != nil {
		t.Fatal(err)
	}
	two, err := tab.ToHost("/backups2/a")
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Fatalf("both disks give %q", one)
	}
	for host, want := range map[string]string{one: "/backups1/a", two: "/backups2/a"} {
		if got, err := tab.FromHost(host); err != nil || got != want {
			t.Errorf("FromHost(%q) = %q, %v; want %q", host, got, err, want)
		}
	}

	// A container with only the first disk does not take the second disk's
	// folder for its own.
	first := table(t, unraid)
	if _, err := first.FromHost(two); !errors.Is(err, ErrNotMounted) {
		t.Errorf("a container without the second disk finds %q: %v", two, err)
	}
	if got, err := first.FromHost(strings.TrimSuffix(one, "/a")); err != nil || got != "/backups" {
		t.Errorf("a container with the first disk finds %q at %q, %v", one, got, err)
	}
}
