// Command parleyport is the message relay KnightLoader and BombVault instances
// use when neither side can accept an inbound connection, such as two installs
// on different networks. Both dial out to the relay, which forwards frames
// between connections that present the same relay key.
//
// It downloads nothing, stores nothing and cannot open the frames it forwards.
//
// # TLS
//
// With PARLEYPORT_DOMAIN set it terminates TLS on :443 and manages its own Let's
// Encrypt certificate through tls-alpn-01, so port 80 can stay closed. Without
// it, it serves plain HTTP on PARLEYPORT_ADDR for a local test or a proxy in
// front. The relay key is a credential, so anything reachable from outside a
// trusted network needs one of the two.
//
// # Behind a proxy
//
// PARLEYPORT_TRUSTED_PROXIES lists the proxies, by address or CIDR range and
// separated by commas, whose X-Forwarded-For names the caller for the
// handshake throttle. Unset trusts loopback alone, which fits a proxy on the
// same host; "none" trusts no proxy. A proxy in another container or on
// another machine has to be named, such as 172.18.0.5 for a proxy container
// on a Docker network. A range may be no wider than a /28, or a /124 for IPv6,
// since anybody inside it could pick the address the throttle counts.
//
// PARLEYPORT_PUBLIC_URL is the address instances dial the relay at, such as
// https://relay.example.com, or several separated by commas. A KnightLoader
// member proves its id only to the relay its hello names, so another relay it
// dials with the same key cannot pass this one's challenge on to it. The names
// in PARLEYPORT_DOMAIN count too. With neither set the relay goes by the Host
// header each connection arrives with, which whoever opens the connection
// writes, so a relay reachable from outside sets one of the two.
package main

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/junkerderprovinz/parleyport/internal/buildinfo"
	"github.com/junkerderprovinz/parleyport/internal/relay"
)

// shutdownGrace bounds how long a graceful stop waits for connections. Nothing
// here is mid-transfer, and a cut client reconnects and announces again.
const shutdownGrace = 5 * time.Second

// brandArt is the house ASCII banner printed at startup, a copy of
// .github/assets/banner-raw.txt.
//
//go:embed banner.txt
var brandArt string

func main() {
	versionOnly, err := parseArgs(os.Args[1:], os.Stdout, os.Stderr)
	switch {
	case errors.Is(err, flag.ErrHelp):
		return
	case err != nil:
		os.Exit(2)
	case versionOnly:
		return
	}

	printBanner()

	// The privacy policy promises no record of who connects, but net/http logs
	// the client address on failed TLS handshakes, some HTTP/2 errors and
	// panics. Both the standard logger and the server's ErrorLog are redacted.
	logOut := relay.RedactAddrs(os.Stderr)
	log.SetOutput(logOut)

	// Clear of KnightLoader's :8749 and :9666, so both can run on one host.
	addr := setting("ADDR", ":8760")

	r := relay.New()
	trusted, err := trustedProxies(setting("TRUSTED_PROXIES", ""))
	if err != nil {
		log.Fatalf("PARLEYPORT_TRUSTED_PROXIES: %v", err)
	}
	r.TrustedProxies = func() []netip.Prefix { return trusted }

	// PARLEYPORT_DOMAIN is a comma-separated list because the relay address is
	// compiled into released builds, so after a move the old name still needs
	// a certificate until nothing dials it.
	domains := splitNames(setting("DOMAIN", ""))
	names, err := relayNames(setting("PUBLIC_URL", ""), domains)
	if err != nil {
		log.Fatalf("PARLEYPORT_PUBLIC_URL: %v", err)
	}
	if len(names) > 0 {
		r.Names = func(*http.Request) []string { return names }
	} else {
		log.Printf("neither PARLEYPORT_PUBLIC_URL nor PARLEYPORT_DOMAIN is set, so a hello is checked against the Host header it arrives with")
	}
	// The request path sweeps too, but only while traffic arrives. The timer
	// keeps the 61 minute retention the privacy notes promise on a
	// quiet relay.
	go func() {
		for range time.Tick(time.Minute) {
			r.SweepLimiter()
		}
	}()
	mux := http.NewServeMux()
	// Same shape as the app's GET /api/health, so one health check fits both.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": buildinfo.Version})
	})
	mux.Handle("GET /relay/connect", r)

	domain := ""
	if len(domains) > 0 {
		domain = domains[0]
		addr = setting("ADDR", ":443")
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: mux, ErrorLog: log.New(logOut, "", log.LstdFlags)}

	if domain != "" {
		m := &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			// Without a whitelist autocert requests a certificate for any
			// name a scanner puts in its handshake, and burns the rate limit.
			HostPolicy: autocert.HostWhitelist(domains...),
			Cache:      autocert.DirCache(setting("CERT_DIR", "/var/lib/parleyport/certs")),
		}
		tlsCfg := m.TLSConfig()
		// m.TLSConfig already lists acme.ALPNProto. Spelling it out keeps an
		// edit from dropping it, which would only surface months later when
		// renewal fails without port 80.
		tlsCfg.NextProtos = []string{"h2", "http/1.1", acme.ALPNProto}
		tlsCfg.MinVersion = tls.VersionTLS12
		srv.TLSConfig = tlsCfg
		listener = tls.NewListener(listener, tlsCfg)
	}

	serveErr := make(chan error, 1)
	go func() {
		scheme, ws := "http", "ws"
		if domain != "" {
			scheme, ws = "https", "wss"
		}
		log.Printf("ParleyPort listening on %s (%s, %s://%s/relay/connect)", addr, scheme, ws, hostOr(domain, addr))
		err := srv.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-stop:
		log.Printf("shutting down (%s)", sig)
	case err := <-serveErr:
		// The listener stopped without Shutdown, usually because the address
		// was already in use.
		if err != nil {
			log.Fatalf("serve: %v", err)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: not every connection closed within %s: %v", shutdownGrace, err)
	}
	cancel()
}

// parseArgs reads the command line and reports whether it only asked for the
// version, which it has then printed. The relay is configured through the
// environment, so any other flag or argument is refused rather than ignored
// on the way to opening a public listener.
func parseArgs(args []string, stdout, stderr io.Writer) (versionOnly bool, err error) {
	fs := flag.NewFlagSet("parleyport", flag.ContinueOnError)
	fs.SetOutput(stderr)
	version := fs.Bool("version", false, "print the version and commit, then exit")
	if err := fs.Parse(args); err != nil {
		return false, err
	}
	if fs.NArg() > 0 {
		err := fmt.Errorf("unexpected argument %q", fs.Arg(0))
		fmt.Fprintln(stderr, err)
		fs.Usage()
		return false, err
	}
	if *version {
		fmt.Fprintln(stdout, buildinfo.Describe("parleyport"))
	}
	return *version, nil
}

// splitNames turns the comma-separated PARLEYPORT_DOMAIN into the names the
// certificate may cover. Empty entries are dropped, since an empty name in the
// whitelist would admit handshakes without a server name.
func splitNames(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if name := strings.TrimSpace(part); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// relayNames is what a hello may name as this relay: the host of each address
// in the comma-separated PARLEYPORT_PUBLIC_URL, and each name in domains.
func relayNames(publicURL string, domains []string) ([]string, error) {
	var names []string
	for _, address := range splitNames(publicURL) {
		name := relay.RelayHost(address)
		if name == "" {
			return nil, fmt.Errorf("%q names no host", address)
		}
		names = append(names, name)
	}
	for _, d := range domains {
		names = append(names, relay.RelayHost(d))
	}
	return names, nil
}

// The widest trusted range for each family. Anybody inside a trusted range
// names their own bucket in X-Forwarded-For, so a range is for a few proxies
// and never for a network of callers.
const (
	maxProxyRangeV4 = 28
	maxProxyRangeV6 = 124
)

// trustedProxies reads the comma-separated addresses and CIDR ranges of the
// reverse proxies in front of the relay. Unset means loopback, where a proxy
// on the relay's own host sits; "none" trusts no proxy.
func trustedProxies(v string) ([]netip.Prefix, error) {
	switch strings.TrimSpace(v) {
	case "":
		return []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}, nil
	case "none":
		return nil, nil
	}
	var out []netip.Prefix
	for _, s := range splitNames(v) {
		p, err := trustedProxy(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// trustedProxy reads one entry: an IP address, which stands for itself, or a
// CIDR range no wider than the limit for its family. An IPv4 range written
// in IPv6 form is read as the IPv4 range it is, since that is how a caller's
// address is compared with it.
func trustedProxy(entry string) (netip.Prefix, error) {
	if !strings.Contains(entry, "/") {
		a, err := netip.ParseAddr(entry)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is neither an IP address nor a CIDR range such as 10.10.0.0/28", entry)
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(entry)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is neither an IP address nor a CIDR range such as 10.10.0.0/28", entry)
	}
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	widest := maxProxyRangeV6
	if p.Addr().Is4() {
		widest = maxProxyRangeV4
	}
	if p.Bits() < widest {
		return netip.Prefix{}, fmt.Errorf("%q is wider than a /%d; name the proxies themselves, or a range that holds nothing else", entry, widest)
	}
	return p.Masked(), nil
}

// setting reads PARLEYPORT_<name>, then KL_RELAY_<name>, which relays set up
// from the knightloader-relay image carry, so they can switch images without
// a new configuration.
func setting(name, def string) string {
	for _, k := range []string{"PARLEYPORT_" + name, "KL_RELAY_" + name} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return def
}

// hostOr returns the address the startup line shows: the domain when TLS is
// on, otherwise the bind address.
func hostOr(domain, addr string) string {
	if domain != "" {
		return domain
	}
	return addr
}

const (
	bannerName     = "ParleyPort"
	bannerSubtitle = "The relay for KnightLoader and BombVault. It passes on what it cannot read."
)

func printBanner() {
	fmt.Println()
	fmt.Println(strings.TrimRight(brandArt, "\n"))
	fmt.Println()
	fmt.Println("  " + bannerName + " · " + bannerSubtitle)
	fmt.Println()
}
