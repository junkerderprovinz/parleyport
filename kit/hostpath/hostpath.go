// Package hostpath translates between a folder as a program in a container
// sees it and the same folder on the host, so that two apps in different
// containers can name one folder to each other.
//
// The translation reads the container's own mount table. A folder's host path
// is the root field of the mount that holds it, followed by the rest of the
// folder below the mount point. Unraid's user shares are one FUSE file system
// mounted on the host at /mnt/user, so their roots are taken from there. Disks
// and pools mounted elsewhere on the host name only the folder on the disk.
// Outside a container, and on systems without a mount table, a path is its
// own host path.
package hostpath

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Errors of ToHost and FromHost.
var (
	ErrNotMounted = errors.New("hostpath: the folder is in no mount shared with the host")
	ErrUnclean    = errors.New("hostpath: the path is not a clean absolute path")
)

// Mount is one line of a mount table.
type Mount struct {
	// Root is the folder of the mounted file system that appears at Point.
	Root   string
	Point  string
	FSType string
}

// Table is a mount table. The zero Table translates every path to itself.
type Table struct {
	Mounts []Mount
}

// Load reads the mount table of this process, or returns the zero Table
// where the system has none.
func Load() (Table, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if errors.Is(err, fs.ErrNotExist) {
		return Table{}, nil
	}
	if err != nil {
		return Table{}, err
	}
	defer func() { _ = f.Close() }()
	return Parse(f)
}

// ToHost returns the host path of a folder in this container.
func ToHost(p string) (string, error) {
	t, err := Load()
	if err != nil {
		return "", err
	}
	return t.ToHost(p)
}

// FromHost returns where a host path is in this container.
func FromHost(p string) (string, error) {
	t, err := Load()
	if err != nil {
		return "", err
	}
	return t.FromHost(p)
}

// Parse reads a mount table in the format of /proc/self/mountinfo.
func Parse(r io.Reader) (Table, error) {
	var t Table
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if len(fields) < 6 || sep < 0 || sep+1 >= len(fields) {
			return Table{}, fmt.Errorf("hostpath: a mount table line without its fields: %q", line)
		}
		m := Mount{Root: unescape(fields[3]), Point: unescape(fields[4]), FSType: fields[sep+1]}
		if !path.IsAbs(m.Root) || !path.IsAbs(m.Point) {
			return Table{}, fmt.Errorf("hostpath: a mount table line with a relative path: %q", line)
		}
		t.Mounts = append(t.Mounts, m)
	}
	return t, sc.Err()
}

// unescape undoes the octal escapes the kernel writes for spaces, tabs,
// newlines and backslashes in a path.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1:i+4]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(s string) bool {
	return len(s) == 3 && s[0] >= '0' && s[0] <= '3' && s[1] >= '0' && s[1] <= '7' && s[2] >= '0' && s[2] <= '7'
}

// virtual are the file systems that hold nothing of the host's folders: the
// container's own layers and what the kernel makes up.
var virtual = map[string]bool{
	"overlay": true, "aufs": true, "proc": true, "sysfs": true, "tmpfs": true,
	"devtmpfs": true, "devpts": true, "mqueue": true, "cgroup": true, "cgroup2": true,
	"securityfs": true, "debugfs": true, "tracefs": true, "pstore": true, "bpf": true,
	"configfs": true, "fusectl": true, "nsfs": true, "hugetlbfs": true, "binfmt_misc": true,
}

// onHost reports whether the table is the host's own: its root is a real
// file system mounted whole, which a container's never is.
func (t Table) onHost() bool {
	if len(t.Mounts) == 0 {
		return true
	}
	for _, m := range t.Mounts {
		if m.Point == "/" {
			return m.Root == "/" && !virtual[m.FSType]
		}
	}
	return false
}

// hostOf is where m's mount point is on the host.
func hostOf(m Mount) string {
	if m.FSType == "fuse.shfs" {
		return path.Join("/mnt/user", m.Root)
	}
	return m.Root
}

// below returns the rest of p under dir, and whether p is dir or below it.
func below(p, dir string) (string, bool) {
	if p == dir {
		return "", true
	}
	if dir == "/" {
		return p[1:], true
	}
	rest, ok := strings.CutPrefix(p, dir+"/")
	return rest, ok
}

// ToHost returns the host path of the folder p.
func (t Table) ToHost(p string) (string, error) {
	if err := clean(p); err != nil {
		return "", err
	}
	if t.onHost() {
		return p, nil
	}
	var holder *Mount
	var rest string
	for i, m := range t.Mounts {
		r, ok := below(p, m.Point)
		if ok && (holder == nil || len(m.Point) > len(holder.Point)) {
			holder, rest = &t.Mounts[i], r
		}
	}
	if holder == nil || virtual[holder.FSType] {
		return "", ErrNotMounted
	}
	return path.Join(hostOf(*holder), rest), nil
}

// FromHost returns where the host path p is in this container. A folder
// another mount hides is not there.
func (t Table) FromHost(p string) (string, error) {
	if err := clean(p); err != nil {
		return "", err
	}
	if t.onHost() {
		return p, nil
	}
	found, base := "", ""
	for _, m := range t.Mounts {
		if virtual[m.FSType] {
			continue
		}
		h := hostOf(m)
		rest, ok := below(p, h)
		if !ok {
			continue
		}
		in := path.Join(m.Point, rest)
		if back, err := t.ToHost(in); err != nil || back != p {
			continue
		}
		if found == "" || len(h) > len(base) {
			found, base = in, h
		}
	}
	if found == "" {
		return "", ErrNotMounted
	}
	return found, nil
}

// clean refuses a path that is relative or not in its shortest form, such as
// one with .. or a trailing slash. A Windows path passes on Windows.
func clean(p string) error {
	if path.IsAbs(p) && path.Clean(p) == p {
		return nil
	}
	if filepath.IsAbs(p) && filepath.Clean(p) == p {
		return nil
	}
	return ErrUnclean
}
