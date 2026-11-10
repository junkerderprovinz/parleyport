// Command fortress lets an app without Go code, such as a plugin written in
// shell, take part in a fortress: join it with the phrase, list the members,
// read their status and ask one of them to run an action.
//
//	fortress join -dir DIR -app ID -name DEVICE [-relay URL|off] [-lan] [-uses a.b,c.d] < phrase
//	fortress members -dir DIR [-json] [-wait 5s]
//	fortress approve -dir DIR [-wait 5s] MEMBER
//	fortress status -dir DIR [-json] [-lang de] [-wait 5s]
//	fortress act -dir DIR [-wait 5s] MEMBER ACTION [BODY]
//
// MEMBER is a member's id or the id of an app with one instance in reach. DIR
// holds the secret behind the phrase, readable by its owner alone. Every
// command but join joins the fortress for as long as it runs, waits up to
// -wait for the members to show, and leaves.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/fortress"
	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/phrase"
	"github.com/junkerderprovinz/parleyport/kit/status"
)

const (
	configFile = "fortress.json"
	stateFile  = "state.json"
	// settle is how long after the relay connects the members it lists are
	// taken as complete.
	settle = 1500 * time.Millisecond
)

// errUsage is a command line that does not make sense; it exits with 2.
var errUsage = errors.New("usage")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	err := dispatch(ctx, args, stdin, stdout)
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errUsage):
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	default:
		_, _ = fmt.Fprintln(stderr, "fortress:", err)
		return 1
	}
}

func dispatch(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: fortress join|members|approve|status|act -dir DIR", errUsage)
	}
	verb, args := args[0], args[1:]
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "the directory that keeps the membership")
	wait := fs.Duration("wait", 5*time.Second, "how long to wait for the members")
	asJSON := fs.Bool("json", false, "print JSON")
	lang := fs.String("lang", "", "the language of the status texts")
	app := fs.String("app", "", "the id of the app this joins for")
	name := fs.String("name", "", "the device it runs on")
	relayURL := fs.String("relay", "", `the relay: empty for the project's, a URL, or "off"`)
	useLAN := fs.Bool("lan", false, "find members on this network too")
	uses := fs.String("uses", "", "the actions it calls at others, comma separated")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if *dir == "" {
		return fmt.Errorf("%w: %s needs -dir", errUsage, verb)
	}
	rest := fs.Args()
	switch verb {
	case "join":
		if *app == "" || *name == "" {
			return fmt.Errorf("%w: join needs -app and -name", errUsage)
		}
		var list []string
		if *uses != "" {
			list = strings.Split(*uses, ",")
		}
		return join(*dir, settings{App: *app, Name: *name, Relay: *relayURL, LAN: *useLAN, Uses: list}, stdin)
	case "members":
		return withFortress(ctx, *dir, *wait, func(f *fortress.Fortress) error { return members(f, stdout, *asJSON) })
	case "approve":
		if len(rest) != 1 {
			return fmt.Errorf("%w: approve MEMBER", errUsage)
		}
		return withFortress(ctx, *dir, *wait, func(f *fortress.Fortress) error { return approve(ctx, f, rest[0], *wait) })
	case "status":
		return withFortress(ctx, *dir, *wait, func(f *fortress.Fortress) error { return statuses(ctx, f, stdout, *lang, *asJSON) })
	case "act":
		if len(rest) < 2 || len(rest) > 3 {
			return fmt.Errorf("%w: act MEMBER ACTION [BODY]", errUsage)
		}
		var body []byte
		if len(rest) == 3 {
			body = []byte(rest[2])
		}
		return withFortress(ctx, *dir, *wait, func(f *fortress.Fortress) error { return act(ctx, f, stdout, rest[0], rest[1], body) })
	}
	return fmt.Errorf("%w: unknown command %q", errUsage, verb)
}

// settings is what join keeps in DIR. Seed and Secret are the member key and
// what the phrase encodes.
type settings struct {
	App    string   `json:"app"`
	Name   string   `json:"name"`
	Relay  string   `json:"relay,omitempty"`
	LAN    bool     `json:"lan,omitempty"`
	Uses   []string `json:"uses,omitempty"`
	Seed   string   `json:"seed"`
	Secret string   `json:"secret"`
}

func join(dir string, s settings, stdin io.Reader) error {
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	secret, err := phrase.Decode(line)
	if err != nil {
		return err
	}
	id, err := member.NewIdentity(member.KindInstance)
	if err != nil {
		return err
	}
	s.Seed, s.Secret = hex.EncodeToString(id.Seed()), hex.EncodeToString(secret)
	// Opening it once, off the network, checks the app id and the actions
	// before anything is written.
	offline := s
	offline.Relay, offline.LAN = "off", false
	if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // G703: the operator names the directory
		return err
	}
	_, leave, err := open(dir, offline, filepath.Join(dir, stateFile))
	if err != nil {
		return err
	}
	if err := leave(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ") //nolint:gosec // G117: the file is where the secret is kept
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, configFile), raw)
}

// writeFile replaces path with raw, readable by its owner alone, so that a
// crash leaves the old file or the new one and never half of either.
func writeFile(path string, raw []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".fortress-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() //nolint:gosec // G703: a file CreateTemp just made
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		_ = tmp.Close()
		return err
	}
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

// open joins the fortress s describes and returns how to leave it again.
func open(dir string, s settings, state string) (*fortress.Fortress, func() error, error) {
	seed, err := hex.DecodeString(s.Seed)
	if err != nil {
		return nil, nil, fmt.Errorf("%s is damaged: %w", filepath.Join(dir, configFile), err)
	}
	secret, err := hex.DecodeString(s.Secret)
	if err != nil {
		return nil, nil, fmt.Errorf("%s is damaged: %w", filepath.Join(dir, configFile), err)
	}
	id, err := member.FromSeed(member.KindInstance, seed)
	if err != nil {
		return nil, nil, err
	}
	cfg := fortress.Config{
		App:      fortress.App{ID: s.App, Name: s.App},
		Secret:   secret,
		Identity: id,
		Self:     group.Self{Name: s.Name, Deployment: "plugin"},
		Store:    fileStore(state),
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
	if !s.LAN {
		f, err := fortress.Open(cfg)
		if err != nil {
			return nil, nil, err
		}
		return f, f.Close, nil
	}
	cfg.LAN = lan.New(lan.Config{Group: fortress.Multicast})
	cfg.LAN.Start()
	f, err := fortress.Open(cfg)
	if err != nil {
		_ = cfg.LAN.Close()
		return nil, nil, err
	}
	return f, func() error { return errors.Join(f.Close(), cfg.LAN.Close()) }, nil
}

// withFortress joins the fortress kept in dir, waits for its members and runs
// do.
func withFortress(ctx context.Context, dir string, wait time.Duration, do func(*fortress.Fortress) error) error {
	raw, err := os.ReadFile(filepath.Join(dir, configFile)) //nolint:gosec // G304: the operator names the directory
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s holds no fortress yet; run fortress join first", dir)
	}
	if err != nil {
		return err
	}
	var s settings
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("%s is damaged: %w", filepath.Join(dir, configFile), err)
	}
	f, leave, err := open(dir, s, filepath.Join(dir, stateFile))
	if err != nil {
		return err
	}
	settled(ctx, f, s.Relay != "off", wait)
	return errors.Join(do(f), leave())
}

// settled waits until the relay lists the members and every approved member
// in reach said what it is, or until wait ran out.
func settled(ctx context.Context, f *fortress.Fortress, relayed bool, wait time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	var connected time.Time
	for {
		now := time.Now()
		if relayed && f.RelayConnected() && connected.IsZero() {
			connected = now
		}
		if (!relayed || !connected.IsZero() && now.Sub(connected) >= settle) && described(f) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func described(f *fortress.Fortress) bool {
	for _, m := range f.Members() {
		if m.Kind == member.KindInstance && m.State == group.StateApproved && m.Online() && m.App.ID == "" {
			return false
		}
	}
	return true
}

type memberOut struct {
	ID         string       `json:"id"`
	Kind       member.Kind  `json:"kind"`
	App        fortress.App `json:"app"`
	Device     string       `json:"device"`
	Deployment string       `json:"deployment,omitempty"`
	State      group.State  `json:"state"`
	Online     bool         `json:"online"`
	Direct     bool         `json:"direct"`
	LastSeen   time.Time    `json:"lastSeen,omitzero"`
	Actions    []string     `json:"actions"`
}

func outOf(m fortress.Member) memberOut {
	actions := m.Actions
	if actions == nil {
		actions = []string{}
	}
	return memberOut{ID: m.ID, Kind: m.Kind, App: m.App, Device: m.Device, Deployment: m.Deployment, State: m.State,
		Online: m.Online(), Direct: m.Direct, LastSeen: m.LastSeen, Actions: actions}
}

func members(f *fortress.Fortress, w io.Writer, asJSON bool) error {
	out := []memberOut{}
	for _, m := range f.Members() {
		out = append(out, outOf(m))
	}
	if asJSON {
		return json.NewEncoder(w).Encode(out)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tAPP\tVERSION\tDEVICE\tSTATE\tONLINE")
	for _, m := range out {
		state := string(m.State)
		if state == "" {
			state = "unknown"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%t\n", m.ID, m.App.ID, m.App.Version, m.Device, state, m.Online)
	}
	return tw.Flush()
}

// approve approves member id once it asked here, waiting for that up to
// wait.
func approve(ctx context.Context, f *fortress.Fortress, id string, wait time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	for {
		for _, m := range f.Members() {
			if m.ID == id && m.State != group.StateUnknown {
				return f.Approve(id)
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s did not ask to be approved here", id)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type statusOut struct {
	memberOut
	Report *status.Report `json:"report,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// statuses reads the status of every approved instance in reach.
func statuses(ctx context.Context, f *fortress.Fortress, w io.Writer, lang string, asJSON bool) error {
	out := []statusOut{}
	for _, m := range f.Members() {
		if m.Kind != member.KindInstance || m.State != group.StateApproved || !m.Online() {
			continue
		}
		s := statusOut{memberOut: outOf(m)}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		r, err := f.Status(cctx, m.ID, lang)
		cancel()
		if err != nil {
			s.Error = err.Error()
		} else {
			s.Report = &r
		}
		out = append(out, s)
	}
	if asJSON {
		return json.NewEncoder(w).Encode(out)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "APP\tDEVICE\tSTATE\tNEEDS YOU\tWORK")
	for _, s := range out {
		if s.Report == nil {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t\t\n", s.App.ID, s.Device, s.Error)
			continue
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\n", s.App.ID, s.Device, s.Report.State, len(s.Report.NeedsYou), len(s.Report.Work))
	}
	return tw.Flush()
}

// act runs action at the member target names and prints its answer.
func act(ctx context.Context, f *fortress.Fortress, w io.Writer, target, action string, body []byte) error {
	id, err := resolve(f, target)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := f.Act(ctx, id, action, body)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(out))
	return err
}

// resolve finds the member target names: its id, or an app with exactly one
// approved instance in reach.
func resolve(f *fortress.Fortress, target string) (string, error) {
	var found []string
	for _, m := range f.Members() {
		if m.ID == target {
			return m.ID, nil
		}
		if m.App.ID == target && m.State == group.StateApproved && m.Online() {
			found = append(found, m.ID)
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("no approved member %s is in reach", target)
	case 1:
		return found[0], nil
	}
	return "", fmt.Errorf("%s runs on %d instances in reach; name one by its id", target, len(found))
}
