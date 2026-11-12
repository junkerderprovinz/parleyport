package fortress

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/member"
)

const (
	membershipFile = "fortress.json"
	stateFile      = "state.json"
)

// Membership is a device's place in a fortress, kept in a directory of its
// own by a plugin or another member without a sealed store.
type Membership struct {
	// App is the id of the app it joins for, Device the device it runs on.
	App    string
	Device string
	// Relay is "" for the project's relay, "off" or the address of an own one.
	Relay string
	// LAN finds the members on this network too.
	LAN  bool
	Uses []string
	// Icon is the app's logo as status.IconFromSVG writes it.
	Icon string
}

// membershipFormat is what the directory keeps: the member key and the keys
// the fortress derives for itself, never the phrase.
type membershipFormat struct {
	App      string   `json:"app"`
	Name     string   `json:"name"`
	Relay    string   `json:"relay,omitempty"`
	LAN      bool     `json:"lan,omitempty"`
	Uses     []string `json:"uses,omitempty"`
	Icon     string   `json:"icon,omitempty"`
	Seed     string   `json:"seed"`
	Group    string   `json:"group"`
	Frame    string   `json:"frame"`
	PeerAuth string   `json:"peerAuth"`
}

// Join keeps m in dir with the keys the fortress derives from secret, under
// the member key dir holds for the same app, else a new one. So joining again
// with a changed phrase comes back as the member the others know rather than
// next to it. Neither the secret nor a key of any app's pairing is kept, so
// whoever takes dir is this one member at most, until somebody removes it.
// The files are readable by their owner alone; on a FAT stick the mount
// decides.
func Join(dir string, secret []byte, m Membership) error {
	set := Domain.Keys(secret)
	seed := ""
	if held, err := readMembership(dir); err == nil && held.App == m.App {
		seed = held.Seed
	}
	if seed == "" {
		id, err := member.NewIdentity(member.KindInstance)
		if err != nil {
			return err
		}
		seed = hex.EncodeToString(id.Seed())
	}
	s := membershipFormat{App: m.App, Name: m.Device, Relay: m.Relay, LAN: m.LAN, Uses: m.Uses, Icon: m.Icon, Seed: seed}
	s.setKeys(set)
	// Opening it once, off the network, checks the app id and the actions
	// before anything is written.
	offline := s
	offline.Relay, offline.LAN = "off", false
	cfg, err := offline.config(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // G703: the operator names the directory
		return err
	}
	f, err := Open(cfg)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return s.write(dir)
}

// Follow takes into the membership kept in dir the keys of the phrase the
// fortress changed to, which f, opened from dir, fetches with NewKeys. It
// reports whether it did; dir then opens under the new phrase as the same
// member. Where no member in reach took a new phrase it changes nothing.
func Follow(ctx context.Context, dir string, f *Fortress) (bool, error) {
	set, err := f.NewKeys(ctx)
	if errors.Is(err, ErrNoNewPhrase) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	s, err := readMembership(dir)
	if err != nil {
		return false, err
	}
	s.setKeys(set)
	return true, s.write(dir)
}

func (s *membershipFormat) setKeys(set keys.Set) {
	s.Group, s.Frame, s.PeerAuth = set.Group, hex.EncodeToString(set.Frame), hex.EncodeToString(set.PeerAuth)
}

func (s membershipFormat) write(dir string) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, membershipFile), raw)
}

// readMembership reads what Join kept in dir.
func readMembership(dir string) (membershipFormat, error) {
	path := filepath.Join(dir, membershipFile)
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the directory
	if err != nil {
		return membershipFormat{}, err
	}
	var s membershipFormat
	if err := json.Unmarshal(raw, &s); err != nil {
		return membershipFormat{}, fmt.Errorf("%s is damaged: %w", path, err)
	}
	return s, nil
}

// Load reads the membership Join kept in dir as the Config to open it with.
// The fortress keeps its state next to it. A membership on this network comes
// with a LAN service on Multicast that the caller starts before Open and
// closes after Close. Where nobody joined, the error is fs.ErrNotExist.
func Load(dir string) (Config, error) {
	s, err := readMembership(dir)
	if err != nil {
		return Config{}, err
	}
	cfg, err := s.config(dir)
	if err != nil {
		return Config{}, fmt.Errorf("%s is damaged: %w", filepath.Join(dir, membershipFile), err)
	}
	if s.LAN {
		cfg.LAN = lan.New(lan.Config{Group: Multicast})
	}
	return cfg, nil
}

func (s membershipFormat) config(dir string) (Config, error) {
	seed, err := hex.DecodeString(s.Seed)
	if err != nil {
		return Config{}, err
	}
	id, err := member.FromSeed(member.KindInstance, seed)
	if err != nil {
		return Config{}, err
	}
	frame, err := hex.DecodeString(s.Frame)
	if err != nil {
		return Config{}, err
	}
	peerAuth, err := hex.DecodeString(s.PeerAuth)
	if err != nil {
		return Config{}, err
	}
	set := keys.Set{Group: s.Group, Frame: frame, PeerAuth: peerAuth}
	if !set.Complete() {
		return Config{}, errors.New("the keys are incomplete")
	}
	cfg := Config{
		App:      App{ID: s.App, Name: s.App, Icon: s.Icon},
		Keys:     set,
		Identity: id,
		Self:     group.Self{Name: s.Name, Deployment: "plugin"},
		Store:    fileStore(filepath.Join(dir, stateFile)),
		Uses:     s.Uses,
	}
	switch s.Relay {
	case "":
		cfg.Relay = group.RelayProject
	case "off":
		cfg.Relay = group.RelayOff
	default:
		cfg.Relay, cfg.RelayURL = group.RelayOwn, s.Relay
	}
	return cfg, nil
}

// writeFile replaces path with raw, so that a crash leaves the old file or the
// new one and never half of either. CreateTemp makes the file readable by its
// owner alone.
func writeFile(path string, raw []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".fortress-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() //nolint:gosec // G703: a file CreateTemp just made
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path) //nolint:gosec // G703: the operator names the directory
}

// fileStore keeps the fortress's state in a file of its own.
type fileStore string

func (p fileStore) Load() ([]byte, error) {
	raw, err := os.ReadFile(string(p))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return raw, err
}

func (p fileStore) Save(raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(string(p)), 0o700); err != nil {
		return err
	}
	return writeFile(string(p), raw)
}
