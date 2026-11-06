// Command devstack runs the forward proxy against fake local proxies and the
// sample data in dev/, so switching can be tried without touching the internet.
//
// The fakes answer plain requests themselves and only tunnel to the local
// sample HTTPS target, so no request can leave this machine.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/NoobforAl/proxyswitcher/internal/config"
	"github.com/NoobforAl/proxyswitcher/internal/forward"
	"github.com/NoobforAl/proxyswitcher/switcher"
)

// These ports must match the sample data in dev/. 18082 is left unused on
// purpose: it is the sample proxy with nothing listening.
const (
	blockingAddr = "127.0.0.1:18081"
	working1Addr = "127.0.0.1:18083"
	working2Addr = "127.0.0.1:18084"
	targetAddr   = "127.0.0.1:18443"

	readHeaderTimeout = 5 * time.Second
	smokeTimeout      = 10 * time.Second
)

// stack holds what every profile's run shares.
type stack struct {
	logger       *slog.Logger
	target       *httptest.Server
	blockingHits atomic.Int32
	workingHits  atomic.Int32
}

func main() {
	configPath := flag.String("config", "dev/proxyswitcher.yaml", "path to the sample config")
	profile := flag.String("profile", config.ProfileScraper, "profile to run interactively: scraper or scanner")
	once := flag.Bool("once", false, "run the sample requests for both profiles, print the results and exit")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, *configPath, *profile, *once)
	stop()
	if err != nil {
		slog.Error("devstack failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath, profile string, once bool) error {
	s := &stack{logger: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	target, err := startTarget(ctx)
	if err != nil {
		return err
	}
	defer target.Close()
	s.target = target

	for addr, handler := range map[string]http.Handler{
		blockingAddr: http.HandlerFunc(s.blockingProxy),
		working1Addr: s.workingProxy("working-1"),
		working2Addr: s.workingProxy("working-2"),
	} {
		if fakeErr := startFake(ctx, addr, handler); fakeErr != nil {
			return fakeErr
		}
	}

	if !once {
		return s.serve(ctx, configPath, profile, func(cfg *config.Config, _ *switcher.Pool) error {
			printInstructions(cfg)
			<-ctx.Done()
			return nil
		})
	}
	for _, each := range []struct {
		profile string
		check   func(context.Context, *config.Config, *switcher.Pool) error
	}{
		{config.ProfileScraper, s.checkScraper},
		{config.ProfileScanner, s.checkScanner},
	} {
		fmt.Printf("\n=== profile: %s\n", each.profile)
		runErr := s.serve(ctx, configPath, each.profile, func(cfg *config.Config, pool *switcher.Pool) error {
			checkErr := each.check(ctx, cfg, pool)
			printPool(pool)
			return checkErr
		})
		if runErr != nil {
			return fmt.Errorf("%s: %w", each.profile, runErr)
		}
	}
	fmt.Println("\nAll sample requests behaved as expected.")
	return nil
}

// serve runs the forward proxy for one profile while use runs.
func (s *stack) serve(ctx context.Context, configPath, profile string, use func(*config.Config, *switcher.Pool) error) error {
	cfg, err := config.LoadWithProfile(configPath, profile)
	if err != nil {
		return err
	}
	pool := switcher.NewPool(cfg.PoolConfig(s.logger), cfg.BuildSources()...)
	pool.Refresh(ctx)

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return err
	}
	serveCtx, cancelServe := context.WithCancel(ctx)
	defer cancelServe()
	server := forward.New(switcher.NewTransport(pool, cfg.TransportConfig(s.logger)), cfg.ForwardOptions(s.logger))
	served := make(chan error, 1)
	go func() { served <- server.Serve(serveCtx, ln) }()

	useErr := use(cfg, pool)
	cancelServe()
	return errors.Join(useErr, <-served)
}

// startTarget runs the sample HTTPS site on its fixed port.
func startTarget(ctx context.Context) (*httptest.Server, error) {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("sample target: %w", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "hello from the sample HTTPS target")
	}))
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.StartTLS()
	return srv, nil
}

// startFake serves a fake proxy until ctx is canceled.
func startFake(ctx context.Context, addr string, handler http.Handler) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("fake proxy: %w", err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: readHeaderTimeout}
	context.AfterFunc(ctx, func() { _ = srv.Close() })
	go func() { _ = srv.Serve(ln) }()
	return nil
}

func (s *stack) blockingProxy(w http.ResponseWriter, _ *http.Request) {
	s.blockingHits.Add(1)
	http.Error(w, "blocked by the sample proxy", http.StatusForbidden)
}

func (s *stack) workingProxy(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.workingHits.Add(1)
		if r.Method == http.MethodConnect {
			tunnel(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Sample-Proxy", name)
		_, _ = fmt.Fprintf(w, "sample response via %s, %d body bytes\n", name, len(body))
	})
}

// tunnel connects only to the sample target, which keeps the stack offline.
func tunnel(w http.ResponseWriter, r *http.Request) {
	if r.Host != targetAddr {
		http.Error(w, "the sample proxies only reach "+targetAddr, http.StatusBadGateway)
		return
	}
	upstream, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", targetAddr)
	if err != nil {
		http.Error(w, "sample target is down", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "hijacking is not supported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close() }()
	go func() { _, _ = io.Copy(client, upstream); _ = client.Close() }()
}

func (s *stack) client(listen string) (*http.Client, error) {
	base, ok := s.target.Client().Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("unexpected sample target transport")
	}
	return &http.Client{
		Timeout: smokeTimeout,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: listen}),
			TLSClientConfig: &tls.Config{RootCAs: base.TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12},
		},
	}, nil
}

// checkScraper expects switching on status codes.
func (s *stack) checkScraper(ctx context.Context, cfg *config.Config, pool *switcher.Pool) error {
	client, err := s.client(cfg.Listen)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()

	// HTTPS first: the blocking proxy still has the top score, so this request
	// has to fail over before anything else lowers it.
	result, err := sample(ctx, client, http.MethodGet, s.target.URL, "", http.StatusOK)
	if err != nil {
		return fmt.Errorf("https: %w", err)
	}
	fmt.Printf("HTTPS GET : %s", result)
	if s.blockedOn(pool) != 1 {
		return errors.New("https: the blocking proxy should have been blocked by this site")
	}

	before := s.blockingHits.Load()
	result, err = sample(ctx, client, http.MethodGet, "http://sample.test/page", "", http.StatusOK)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	fmt.Printf("HTTP GET  : %s", result)
	if s.blockingHits.Load() != before+1 {
		return errors.New("http get: the request should have tried the blocking proxy, then switched")
	}
	return nil
}

// checkScanner expects a target's answer to come back as is, exactly once, and
// a malformed request to reach the upstream unchanged.
func (s *stack) checkScanner(ctx context.Context, cfg *config.Config, _ *switcher.Pool) error {
	client, err := s.client(cfg.Listen)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()

	blockedBefore, workingBefore := s.blockingHits.Load(), s.workingHits.Load()
	result, err := sample(ctx, client, http.MethodPost, "http://sample.test/submit", "payload", http.StatusForbidden)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	fmt.Printf("HTTP POST : %s", result)
	if s.blockingHits.Load() != blockedBefore+1 || s.workingHits.Load() != workingBefore {
		return errors.New("http post: the payload should be delivered exactly once, with no switch")
	}

	raw, err := sendRaw(ctx, cfg.Listen, "GET http://sample.test/a%zzb HTTP/1.1\r\nHost: evil.test\r\nBad Header: x\r\nConnection: close\r\n\r\n")
	if err != nil {
		return fmt.Errorf("malformed request: %w", err)
	}
	if strings.Contains(raw, "Proxy-Status") {
		return fmt.Errorf("malformed request: the relay should pass it on, got %q", raw)
	}
	fmt.Println("Malformed : passed on to the upstream, not refused by the relay")

	result, err = sample(ctx, client, http.MethodGet, s.target.URL, "", http.StatusOK)
	if err != nil {
		return fmt.Errorf("https: %w", err)
	}
	fmt.Printf("HTTPS GET : %s", result)
	return nil
}

func (s *stack) blockedOn(pool *switcher.Pool) int {
	for _, e := range pool.Snapshot() {
		if e.URL.Host == blockingAddr {
			return e.BlockedSites
		}
	}
	return 0
}

func sendRaw(ctx context.Context, listen, request string) (string, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listen)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	if deadlineErr := conn.SetDeadline(time.Now().Add(smokeTimeout)); deadlineErr != nil {
		return "", deadlineErr
	}
	if _, writeErr := io.WriteString(conn, request); writeErr != nil {
		return "", writeErr
	}
	out, err := io.ReadAll(conn)
	return string(out), err
}

func sample(ctx context.Context, client *http.Client, method, target, body string, want int) (string, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != want {
		return "", fmt.Errorf("status %d, want %d: %s", resp.StatusCode, want, out)
	}
	return string(out), nil
}

func printPool(pool *switcher.Pool) {
	fmt.Println("Pool after the sample requests:")
	for _, e := range pool.Snapshot() {
		fmt.Printf("  %-26s tier=%-8s score=%-2d ok=%d failed=%d blocked_sites=%d\n",
			switcher.RedactURL(e.URL), e.Tier, e.Score, e.Successes, e.Failures, e.BlockedSites)
	}
}

func printInstructions(cfg *config.Config) {
	note := "The top proxy answers 403, so plain HTTP switches away from it."
	if cfg.Profile == config.ProfileScanner {
		note = "The top proxy answers 403, and scanner mode returns that 403 as is, without repeating the request."
	}
	fmt.Printf(`
Forward proxy on %[1]s, profile %[2]s, with sample data. %[3]s
Try these, and watch the log:

  curl -x http://%[1]s http://sample.test/page
  curl -x http://%[1]s -d payload http://sample.test/submit
  curl -k -x http://%[1]s https://%[4]s/

Press Ctrl+C to stop.
`, cfg.Listen, cfg.Profile, note, targetAddr)
}
