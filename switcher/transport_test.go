package switcher

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeProxy answers every request with a fixed status and echoes the request
// body, naming itself in X-Via so tests can see which route was taken.
type fakeProxy struct {
	*httptest.Server
	hits atomic.Int32
}

func newFakeProxy(t *testing.T, name string, status int) *fakeProxy {
	t.Helper()
	fp := &fakeProxy{}
	fp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp.hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Via", name)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(fp.Close)
	return fp
}

// result is a finished response whose body has already been read and closed.
type result struct {
	StatusCode int
	Header     http.Header
	Body       string
}

func get(t *testing.T, rt http.RoundTripper, target string) result {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return result{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(body)}
}

// roundTripErr is for requests expected to fail. It closes any response.
func roundTripErr(rt http.RoundTripper, req *http.Request) error {
	resp, err := rt.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}

// preferring gives the first proxy the top score, so tests control the order.
func preferring(t *testing.T, p *Pool, proxyURL string) {
	t.Helper()
	p.Report(mustURL(t, proxyURL), true)
}

func quiet(cfg TransportConfig) TransportConfig {
	cfg.Logger = discardLogger()
	return cfg
}

func TestTransport_SwitchesOnRetryableStatus(t *testing.T) {
	for _, status := range []int{403, 429, 500, 502, 503, 504} {
		bad := newFakeProxy(t, "bad", status)
		good := newFakeProxy(t, "good", http.StatusOK)
		p := newTestPool(t, PoolConfig{}, bad.URL, good.URL)
		preferring(t, p, bad.URL)

		resp := get(t, NewTransport(p, quiet(TransportConfig{})), "http://target.test/")
		if resp.Header.Get("X-Via") != "good" || bad.hits.Load() != 1 {
			t.Errorf("status %d: via %q, bad hits %d", status, resp.Header.Get("X-Via"), bad.hits.Load())
		}
		e := entryFor(t, p, bad.URL)
		if e.Failures != 0 || e.BlockedSites != 1 {
			t.Errorf("status %d: failures %d, blocked sites %d; want only a block by this site", status, e.Failures, e.BlockedSites)
		}
	}
}

func TestTransport_SwitchesOnConnectionRefused(t *testing.T) {
	dead := closedPortURL(t)
	good := newFakeProxy(t, "good", http.StatusOK)
	p := newTestPool(t, PoolConfig{}, dead, good.URL)
	preferring(t, p, dead)

	resp := get(t, NewTransport(p, quiet(TransportConfig{})), "http://target.test/")
	if resp.Header.Get("X-Via") != "good" {
		t.Fatalf("via %q", resp.Header.Get("X-Via"))
	}
	if entryFor(t, p, dead).Failures != 1 {
		t.Fatal("the dead proxy should be penalized")
	}
}

func TestTransport_SwitchesWhenProxyHangs(t *testing.T) {
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(hung.Close)
	t.Cleanup(func() { close(release) })
	good := newFakeProxy(t, "good", http.StatusOK)
	p := newTestPool(t, PoolConfig{}, hung.URL, good.URL)
	preferring(t, p, hung.URL)

	base := http.DefaultTransport.(*http.Transport).Clone()
	base.ResponseHeaderTimeout = 50 * time.Millisecond
	resp := get(t, NewTransport(p, quiet(TransportConfig{Base: base})), "http://target.test/")
	if resp.Header.Get("X-Via") != "good" {
		t.Fatalf("via %q", resp.Header.Get("X-Via"))
	}
}

func TestTransport_TargetErrorDoesNotPenalizeProxy(t *testing.T) {
	proxy := newFakeProxy(t, "p", http.StatusNotFound)
	p := newTestPool(t, PoolConfig{}, proxy.URL)

	resp := get(t, NewTransport(p, quiet(TransportConfig{})), "http://target.test/missing")
	if resp.StatusCode != http.StatusNotFound || proxy.hits.Load() != 1 {
		t.Fatalf("status %d, hits %d", resp.StatusCode, proxy.hits.Load())
	}
	e := entryFor(t, p, proxy.URL)
	if e.Failures != 0 || e.Successes != 1 {
		t.Fatalf("failures %d, successes %d", e.Failures, e.Successes)
	}
}

func TestTransport_NeverRetriesTheSameProxyAndReturnsLastResponse(t *testing.T) {
	a := newFakeProxy(t, "a", http.StatusForbidden)
	b := newFakeProxy(t, "b", http.StatusTooManyRequests)
	p := newTestPool(t, PoolConfig{}, a.URL, b.URL)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://target.test/", strings.NewReader("payload"))
	resp, err := NewTransport(p, quiet(TransportConfig{MaxAttempts: 5, RetryMethods: []string{http.MethodPost}})).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if a.hits.Load() != 1 || b.hits.Load() != 1 {
		t.Fatalf("hits a=%d b=%d, want one each", a.hits.Load(), b.hits.Load())
	}
	// The last real response comes back with a readable body.
	if body, _ := io.ReadAll(resp.Body); string(body) != "payload" {
		t.Fatalf("body = %q", body)
	}
}

func TestTransport_RespectsMaxAttempts(t *testing.T) {
	a := newFakeProxy(t, "a", http.StatusForbidden)
	b := newFakeProxy(t, "b", http.StatusForbidden)
	p := newTestPool(t, PoolConfig{}, a.URL, b.URL)

	get(t, NewTransport(p, quiet(TransportConfig{MaxAttempts: 1})), "http://target.test/")
	if total := a.hits.Load() + b.hits.Load(); total != 1 {
		t.Fatalf("total attempts = %d, want 1", total)
	}
}

func TestTransport_CustomRetryStatus(t *testing.T) {
	proxy := newFakeProxy(t, "p", http.StatusForbidden)
	p := newTestPool(t, PoolConfig{}, proxy.URL)
	get(t, NewTransport(p, quiet(TransportConfig{RetryStatus: []int{418}})), "http://target.test/")
	if entryFor(t, p, proxy.URL).Failures != 0 {
		t.Fatal("403 is not in this retry list, so it must not count as a failure")
	}
}

func TestTransport_FailsClosedWithNoProxy(t *testing.T) {
	target := newFakeProxy(t, "direct", http.StatusOK)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, target.URL, http.NoBody)
	err := roundTripErr(NewTransport(newTestPool(t, PoolConfig{}), quiet(TransportConfig{})), req)
	if !errors.Is(err, ErrNoProxy) {
		t.Fatalf("err = %v, want ErrNoProxy", err)
	}
	if target.hits.Load() != 0 {
		t.Fatal("the request went direct and exposed the real IP")
	}
}

func TestTransport_FailsClosedWhenAllOnCooldown(t *testing.T) {
	target := newFakeProxy(t, "direct", http.StatusOK)
	dead := closedPortURL(t)
	p := newTestPool(t, PoolConfig{CoolingRetryInterval: time.Hour}, dead)
	p.Report(mustURL(t, dead), false)
	p.Report(mustURL(t, dead), false)
	rt := NewTransport(p, quiet(TransportConfig{}))

	// The first request retries the cooling proxy, which is still dead.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, target.URL, http.NoBody)
	if err := roundTripErr(rt, req); err == nil || errors.Is(err, ErrNoProxy) {
		t.Fatalf("err = %v, want the proxy's failure", err)
	}
	// The next finds no retry due, and must not go direct.
	req, _ = http.NewRequestWithContext(t.Context(), http.MethodGet, target.URL, http.NoBody)
	if err := roundTripErr(rt, req); !errors.Is(err, ErrNoProxy) {
		t.Fatalf("err = %v, want ErrNoProxy", err)
	}
	if target.hits.Load() != 0 {
		t.Fatal("the request went direct and exposed the real IP")
	}
}

func TestTransport_FallbackDirectOptIn(t *testing.T) {
	target := newFakeProxy(t, "direct", http.StatusOK)
	resp := get(t, NewTransport(newTestPool(t, PoolConfig{}), quiet(TransportConfig{FallbackDirect: true})), target.URL)
	if resp.Header.Get("X-Via") != "direct" {
		t.Fatalf("via %q", resp.Header.Get("X-Via"))
	}
}

func TestTransport_ReplaysBodyOnRetry(t *testing.T) {
	bad := newFakeProxy(t, "bad", http.StatusServiceUnavailable)
	good := newFakeProxy(t, "good", http.StatusOK)
	p := newTestPool(t, PoolConfig{}, bad.URL, good.URL)
	preferring(t, p, bad.URL)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://target.test/", strings.NewReader("payload"))
	resp, err := NewTransport(p, quiet(TransportConfig{RetryMethods: []string{http.MethodPost}})).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.Header.Get("X-Via") != "good" || string(body) != "payload" {
		t.Fatalf("via %q, body %q", resp.Header.Get("X-Via"), body)
	}
}

func TestTransport_NonReplayableBodyGetsOneAttempt(t *testing.T) {
	bad := newFakeProxy(t, "bad", http.StatusServiceUnavailable)
	good := newFakeProxy(t, "good", http.StatusOK)
	p := newTestPool(t, PoolConfig{}, bad.URL, good.URL)
	preferring(t, p, bad.URL)

	// A plain io.Reader leaves GetBody nil.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://target.test/", io.MultiReader(strings.NewReader("payload")))
	resp, err := NewTransport(p, quiet(TransportConfig{})).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable || good.hits.Load() != 0 {
		t.Fatalf("status %d, good hits %d", resp.StatusCode, good.hits.Load())
	}
}

func TestTransport_CallerCancelIsNeutral(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	}))
	t.Cleanup(hung.Close)
	t.Cleanup(func() { close(release) })
	p := newTestPool(t, PoolConfig{}, hung.URL)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-entered
		cancel()
	}()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://target.test/", http.NoBody)
	if err := roundTripErr(NewTransport(p, quiet(TransportConfig{})), req); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if entryFor(t, p, hung.URL).Failures != 0 {
		t.Fatal("the caller canceling says nothing about the proxy")
	}
}

// The scraper's rotation set a proxy on a shared client and never cleared it,
// so "direct" attempts after any proxied request silently used that proxy.
func TestTransport_DirectFirstStaysDirectAfterProxiedRequests(t *testing.T) {
	var directHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		directHits.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(target.Close)
	proxy := newFakeProxy(t, "proxy", http.StatusOK)
	p := newTestPool(t, PoolConfig{}, proxy.URL)
	rt := NewTransport(p, quiet(TransportConfig{DirectFirst: true}))

	for i := int32(1); i <= 3; i++ {
		resp := get(t, rt, target.URL)
		if resp.Header.Get("X-Via") != "proxy" {
			t.Fatalf("round %d: via %q, want the retry to use the proxy", i, resp.Header.Get("X-Via"))
		}
		if directHits.Load() != i || proxy.hits.Load() != i {
			t.Fatalf("round %d: direct hits %d, proxy hits %d", i, directHits.Load(), proxy.hits.Load())
		}
	}
}

// Run with -race. Every request must see only a working proxy's answer, with
// exactly one bad-proxy attempt recorded per failure.
func TestTransport_ConcurrentRequests(t *testing.T) {
	good1 := newFakeProxy(t, "good", http.StatusOK)
	good2 := newFakeProxy(t, "good", http.StatusOK)
	bad := newFakeProxy(t, "bad", http.StatusForbidden)
	p := newTestPool(t, PoolConfig{}, good1.URL, good2.URL, bad.URL)
	rt := NewTransport(p, quiet(TransportConfig{}))

	const requests = 60
	var wg sync.WaitGroup
	var wrong atomic.Int32
	for range requests {
		wg.Go(func() {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://target.test/", http.NoBody)
			resp, err := rt.RoundTrip(req)
			if err != nil {
				wrong.Add(1)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.Header.Get("X-Via") != "good" {
				wrong.Add(1)
			}
		})
	}
	wg.Wait()
	if wrong.Load() != 0 {
		t.Fatalf("%d requests did not end on a working proxy", wrong.Load())
	}
	if got := good1.hits.Load() + good2.hits.Load(); got != requests {
		t.Fatalf("good proxy hits = %d, want %d", got, requests)
	}
}

func TestTransport_PasswordNeverInErrorsOrLogs(t *testing.T) {
	dead := strings.Replace(closedPortURL(t), "http://", "http://user:s3cret@", 1)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	p := NewPool(PoolConfig{Logger: logger}, StaticSource{Proxies: []string{dead}})
	p.Refresh(context.Background())

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://target.test/", http.NoBody)
	err := roundTripErr(NewTransport(p, TransportConfig{Logger: logger}), req)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("password in error: %v", err)
	}
	if strings.Contains(logs.String(), "s3cret") {
		t.Fatalf("password in logs: %s", logs.String())
	}
}

// fakeConnectProxy handles CONNECT like an HTTP proxy, either refusing with
// status or tunneling to the requested address.
func fakeConnectProxy(t *testing.T, status int, seenAuth *atomic.Value) (string, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if seenAuth != nil {
			seenAuth.Store(r.Header.Get("Proxy-Authorization"))
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		upstream, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", r.Host)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		client, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		_, _ = client.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close() }()
		go func() { _, _ = io.Copy(client, upstream); _ = client.Close() }()
	}))
	t.Cleanup(srv.Close)
	return srv.URL, hits
}

// echoServer writes back each line it receives.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func assertEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || line != "ping\n" {
		t.Fatalf("echo = %q, %v", line, err)
	}
}

func TestDialTunnel_SwitchesWhenProxyRefuses(t *testing.T) {
	refusing, refusedHits := fakeConnectProxy(t, http.StatusForbidden, nil)
	working, _ := fakeConnectProxy(t, http.StatusOK, nil)
	p := newTestPool(t, PoolConfig{}, refusing, working)
	preferring(t, p, refusing)

	conn, err := NewTransport(p, quiet(TransportConfig{})).DialTunnel(context.Background(), echoServer(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	assertEcho(t, conn)
	if refusedHits.Load() != 1 || entryFor(t, p, refusing).BlockedSites != 1 || entryFor(t, p, working).Successes != 1 {
		t.Fatalf("refused hits %d, entries %+v", refusedHits.Load(), p.Snapshot())
	}
}

func TestDialTunnel_SendsProxyAuth(t *testing.T) {
	var auth atomic.Value
	working, _ := fakeConnectProxy(t, http.StatusOK, &auth)
	withCreds := strings.Replace(working, "http://", "http://user:pass@", 1)
	p := newTestPool(t, PoolConfig{}, withCreds)

	conn, err := NewTransport(p, quiet(TransportConfig{})).DialTunnel(context.Background(), echoServer(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if auth.Load() != "Basic dXNlcjpwYXNz" {
		t.Fatalf("Proxy-Authorization = %v", auth.Load())
	}
}

func TestDialTunnel_FailsClosedAndReportsLastError(t *testing.T) {
	_, err := NewTransport(newTestPool(t, PoolConfig{}), quiet(TransportConfig{})).DialTunnel(context.Background(), "127.0.0.1:1")
	if !errors.Is(err, ErrNoProxy) {
		t.Fatalf("empty pool: err = %v", err)
	}

	refusing, _ := fakeConnectProxy(t, http.StatusForbidden, nil)
	p := newTestPool(t, PoolConfig{}, refusing)
	_, err = NewTransport(p, quiet(TransportConfig{})).DialTunnel(context.Background(), "127.0.0.1:1")
	if err == nil || errors.Is(err, ErrNoProxy) || !strings.Contains(err.Error(), "403") {
		t.Fatalf("exhausted pool: err = %v, want the real refusal", err)
	}
}

func TestDialTunnel_SwitchesWhenProxyHangsDuringConnect(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	// Accepts connections but never answers the CONNECT.
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	hung := "http://" + ln.Addr().String()
	working, _ := fakeConnectProxy(t, http.StatusOK, nil)
	p := newTestPool(t, PoolConfig{}, hung, working)
	preferring(t, p, hung)

	rt := NewTransport(p, quiet(TransportConfig{DialTimeout: 100 * time.Millisecond}))
	conn, err := rt.DialTunnel(context.Background(), echoServer(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	assertEcho(t, conn)
}

// fakeSOCKS5 implements the no-auth CONNECT subset of RFC 1928 for IPv4.
func fakeSOCKS5(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	handle := func(c net.Conn) {
		defer func() { _ = c.Close() }()
		head := make([]byte, 2)
		if _, err := io.ReadFull(c, head); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, c, int64(head[1])); err != nil {
			return
		}
		_, _ = c.Write([]byte{5, 0})
		req := make([]byte, 10) // version, command, reserved, type, IPv4, port
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		ip := net.IP(req[4:8])
		port := binary.BigEndian.Uint16(req[8:10])
		upstream, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
		if err != nil {
			return
		}
		defer func() { _ = upstream.Close() }()
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		go func() { _, _ = io.Copy(upstream, c) }()
		_, _ = io.Copy(c, upstream)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()
	return "socks5://" + ln.Addr().String()
}

func TestDialTunnel_ThroughSOCKS5(t *testing.T) {
	p := newTestPool(t, PoolConfig{}, fakeSOCKS5(t))
	conn, err := NewTransport(p, quiet(TransportConfig{})).DialTunnel(context.Background(), echoServer(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	assertEcho(t, conn)
}
