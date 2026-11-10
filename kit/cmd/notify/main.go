// Command notify lets an app without Go code, such as a plugin written in
// shell, send its messages through kit/notify and keep the channels in the
// same format as every other app.
//
//	notify send -channels FILE [-source NAME] < event.json
//	notify test -channels FILE [-source NAME] < {"channel": {...}, "event": {...}}
//	notify show -channels FILE
//	notify save -channels FILE < channels.json
//
// show prints the channels with every secret masked, for a settings page.
// save takes such a list back, restores the masked secrets from FILE where
// the destination is unchanged, and replaces FILE only when the list is
// valid. test tries one channel, saved or not, with the saved secrets. send
// prints one result per channel that took the event and exits 1 if any of
// them failed.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/notify"
)

// errUsage is a command line that does not make sense; it exits with 2.
var errUsage = errors.New("usage")

// errFailed is a run whose answer says what went wrong; it exits with 1
// without a message of its own.
var errFailed = errors.New("failed")

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
	case errors.Is(err, errFailed):
		return 1
	default:
		_, _ = fmt.Fprintln(stderr, "notify:", err)
		return 1
	}
}

func dispatch(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: notify send|test|show|save -channels FILE", errUsage)
	}
	verb, args := args[0], args[1:]
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("channels", "", "the file that keeps the channels")
	source := fs.String("source", "", "the sender's name where a service shows one")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if *path == "" {
		return fmt.Errorf("%w: %s needs -channels", errUsage, verb)
	}
	out := json.NewEncoder(stdout)
	switch verb {
	case "send":
		var e event
		if err := json.NewDecoder(stdin).Decode(&e); err != nil {
			return fmt.Errorf("read the event: %w", err)
		}
		d, err := dispatcher(*path, *source)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		results := []result{}
		failed := false
		for _, r := range d.Send(ctx, e.notify()) {
			results = append(results, resultOf(r))
			failed = failed || !r.OK()
		}
		if err := out.Encode(results); err != nil {
			return err
		}
		if failed {
			return errFailed
		}
		return nil
	case "test":
		var in struct {
			Channel notify.Channel `json:"channel"`
			Event   event          `json:"event"`
		}
		if err := json.NewDecoder(stdin).Decode(&in); err != nil {
			return fmt.Errorf("read the channel: %w", err)
		}
		prev, err := load(*path)
		if err != nil {
			return err
		}
		ch := notify.Merge([]notify.Channel{in.Channel}, prev)[0]
		d, err := notify.NewDispatcher(nil, notify.Options{Source: *source})
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		r := d.Test(ctx, ch, in.Event.notify())
		if err := out.Encode(resultOf(r)); err != nil {
			return err
		}
		if !r.OK() {
			return errFailed
		}
		return nil
	case "show":
		list, err := load(*path)
		if err != nil {
			return err
		}
		return out.Encode(shown(list))
	case "save":
		var next []notify.Channel
		if err := json.NewDecoder(stdin).Decode(&next); err != nil {
			return fmt.Errorf("read the channels: %w", err)
		}
		prev, err := load(*path)
		if err != nil {
			return err
		}
		next = notify.Merge(next, prev)
		var problems notify.Problems
		if err := notify.Validate(next); errors.As(err, &problems) {
			if err := out.Encode(map[string]notify.Problems{"problems": problems}); err != nil {
				return err
			}
			return errFailed
		} else if err != nil {
			return err
		}
		if err := store(*path, next); err != nil {
			return err
		}
		return out.Encode(shown(next))
	}
	return fmt.Errorf("%w: unknown command %q", errUsage, verb)
}

// event is notify.Event as JSON.
type event struct {
	Kind     string            `json:"kind"`
	Severity notify.Severity   `json:"severity"`
	Title    string            `json:"title"`
	Body     string            `json:"body"`
	HTML     string            `json:"html"`
	Link     string            `json:"link"`
	Key      string            `json:"key"`
	Ping     notify.Ping       `json:"ping"`
	Fields   map[string]string `json:"fields"`
	Facts    []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"facts"`
}

func (e event) notify() notify.Event {
	n := notify.Event{Kind: e.Kind, Severity: e.Severity, Title: e.Title, Body: e.Body, HTML: e.HTML,
		Link: e.Link, Key: e.Key, Ping: e.Ping, Fields: e.Fields}
	for _, f := range e.Facts {
		n.Facts = append(n.Facts, notify.Fact{Name: f.Name, Value: f.Value})
	}
	return n
}

// result is notify.Result as JSON.
type result struct {
	Channel  string      `json:"channel"`
	Kind     notify.Kind `json:"kind"`
	OK       bool        `json:"ok"`
	Attempts int         `json:"attempts"`
	Status   int         `json:"status,omitempty"`
	Code     string      `json:"code,omitempty"`
	Error    string      `json:"error,omitempty"`
}

func resultOf(r notify.Result) result {
	out := result{Channel: r.Channel, Kind: r.Kind, OK: r.OK(), Attempts: r.Attempts, Status: r.Status, Code: r.Code}
	if r.Err != nil {
		out.Error = r.Err.Error()
	}
	return out
}

func dispatcher(path, source string) (*notify.Dispatcher, error) {
	list, err := load(path)
	if err != nil {
		return nil, err
	}
	d, err := notify.NewDispatcher(list, notify.Options{Source: source})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return d, nil
}

// load reads the channels in path. A missing file holds none.
func load(path string) ([]notify.Channel, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the file
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []notify.Channel
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("%s is damaged: %w", path, err)
	}
	return list, nil
}

func shown(list []notify.Channel) []notify.Channel {
	out := notify.Redacted(list)
	if out == nil {
		out = []notify.Channel{}
	}
	return out
}

// store replaces path with the channels, so that a crash leaves the old file
// or the new one. CreateTemp makes the file readable by its owner alone; on a
// FAT stick the mount decides.
func store(path string, list []notify.Channel) error {
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // G703: the operator names the file
		return err
	}
	tmp, err := os.CreateTemp(dir, ".notify-*")
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
	return os.Rename(tmp.Name(), path) //nolint:gosec // G703: the operator names the file
}
