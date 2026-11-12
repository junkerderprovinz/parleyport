// Command fortress lets an app without Go code, such as a plugin written in
// shell, take part in a fortress: join it with the phrase, list the members,
// read their status, ask one of them to run an action and take one out.
//
//	fortress join -dir DIR -app ID -name DEVICE [-relay URL|off] [-lan] [-uses a.b,c.d] [-icon logo.svg] < phrase
//	fortress members -dir DIR [-json] [-wait 5s]
//	fortress status -dir DIR [-json] [-lang de] [-wait 5s]
//	fortress act -dir DIR [-wait 5s] MEMBER ACTION [BODY]
//	fortress remove -dir DIR [-wait 5s] MEMBER
//
// MEMBER is a member's id or the id of an app with one instance in reach.
// join keeps no phrase: DIR holds the plugin's member key and the keys the
// fortress derives for itself, readable by its owner alone, which open no
// app's pairing and lead back to no phrase. Whoever takes DIR is this one
// member at most, until somebody removes it. After the phrase changes, every
// command follows on its own, as the same member, for 30 days; joining again
// with the new phrase does the same any time. remove prints the member it
// takes out as JSON and returns once the members in reach took the removal;
// DIR keeps it out on every command after. Every command but join takes part
// for as long as it runs, waits up to -wait for the members to show, and
// leaves.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/fortress"
	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/phrase"
	"github.com/junkerderprovinz/parleyport/kit/status"
)

// settle is how long after the relay connects the members it lists are taken
// as complete.
const settle = 1500 * time.Millisecond

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
		// The fortress package already starts its errors with the command's
		// name.
		_, _ = fmt.Fprintln(stderr, "fortress:", strings.TrimPrefix(err.Error(), "fortress: "))
		return 1
	}
}

func dispatch(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: fortress join|members|status|act|remove -dir DIR", errUsage)
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
	icon := fs.String("icon", "", "the app's logo, an SVG file the members show")
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
		m := fortress.Membership{App: *app, Device: *name, Relay: *relayURL, LAN: *useLAN, Uses: list}
		if *icon != "" {
			svg, err := os.ReadFile(*icon) //nolint:gosec // G304: the operator names the logo
			if err != nil {
				return err
			}
			if m.Icon, err = status.IconFromSVG(svg); err != nil {
				return err
			}
		}
		return join(*dir, m, stdin)
	case "members":
		return withFortress(ctx, *dir, *wait, func(f *fortress.Fortress) error { return members(f, stdout, *asJSON) })
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
	case "remove":
		if len(rest) != 1 {
			return fmt.Errorf("%w: remove MEMBER", errUsage)
		}
		return withFortress(ctx, *dir, *wait, func(f *fortress.Fortress) error { return remove(f, stdout, rest[0]) })
	}
	return fmt.Errorf("%w: unknown command %q", errUsage, verb)
}

func join(dir string, m fortress.Membership, stdin io.Reader) error {
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	secret, err := phrase.Decode(line)
	if err != nil {
		return err
	}
	defer clear(secret)
	return fortress.Join(dir, secret, m)
}

// withFortress joins the fortress kept in dir, waits for its members and runs
// do. When the phrase changed since the last run, it follows first.
func withFortress(ctx context.Context, dir string, wait time.Duration, do func(*fortress.Fortress) error) error {
	f, leave, err := openDir(ctx, dir, wait)
	if err != nil {
		return err
	}
	// A member out of reach is asked for the new keys again on the next run,
	// and do says what the old phrase still reaches.
	if moved, _ := fortress.Follow(ctx, dir, f); moved {
		if err := errors.Join(f.Close(), leave()); err != nil {
			return err
		}
		if f, leave, err = openDir(ctx, dir, wait); err != nil {
			return err
		}
	}
	return errors.Join(do(f), f.Close(), leave())
}

// openDir joins the fortress kept in dir and waits for its members. leave
// closes what it started besides the fortress.
func openDir(ctx context.Context, dir string, wait time.Duration) (f *fortress.Fortress, leave func() error, err error) {
	cfg, err := fortress.Load(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("%s holds no fortress yet; run fortress join first", dir)
	}
	if err != nil {
		return nil, nil, err
	}
	leave = func() error { return nil }
	if cfg.LAN != nil {
		cfg.LAN.Start()
		leave = cfg.LAN.Close
	}
	if f, err = fortress.Open(cfg); err != nil {
		return nil, nil, errors.Join(err, leave())
	}
	settled(ctx, f, cfg.Relay != group.RelayOff, wait)
	return f, leave, nil
}

// settled waits until the relay lists the members and every instance in reach
// said what it is, or until wait ran out.
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
		if m.Kind == member.KindInstance && m.Online() && m.App.ID == "" {
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

type statusOut struct {
	memberOut
	Report *status.Report `json:"report,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// statuses reads the status of every instance in reach.
func statuses(ctx context.Context, f *fortress.Fortress, w io.Writer, lang string, asJSON bool) error {
	out := []statusOut{}
	for _, m := range f.Members() {
		if m.Kind != member.KindInstance || !m.Online() {
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
	m, err := resolve(f, target)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := f.Act(ctx, m.ID, action, body)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(out))
	return err
}

// remove takes the member target names out of the fortress and prints it.
// An app name will do only while the fortress knows a single member of it,
// away or not, since taking out the wrong one cannot be undone. Closing the
// fortress afterwards waits until the members in reach heard it.
func remove(f *fortress.Fortress, w io.Writer, target string) error {
	var found []fortress.Member
	for _, m := range f.Members() {
		if m.ID == target || m.App.ID == target {
			found = append(found, m)
		}
	}
	switch {
	case len(found) == 0:
		return fmt.Errorf("no member %s is known", target)
	case len(found) > 1:
		return fmt.Errorf("the fortress knows %d members of %s; name one by its id", len(found), target)
	}
	m := found[0]
	if err := f.Remove(m.ID); err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(outOf(m))
}

// resolve finds the member target names: its id, or an app with exactly one
// instance in reach.
func resolve(f *fortress.Fortress, target string) (fortress.Member, error) {
	var found []fortress.Member
	for _, m := range f.Members() {
		if m.ID == target {
			return m, nil
		}
		if m.App.ID == target && m.Online() {
			found = append(found, m)
		}
	}
	switch len(found) {
	case 0:
		return fortress.Member{}, fmt.Errorf("no member %s is in reach", target)
	case 1:
		return found[0], nil
	}
	return fortress.Member{}, fmt.Errorf("%s runs on %d instances in reach; name one by its id", target, len(found))
}
