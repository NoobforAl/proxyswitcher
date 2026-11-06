package forward

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NoobforAl/proxyswitcher/switcher"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// upstream is a fake upstream proxy. Plain requests get status and an echo of
// the request; CONNECT is refused with status, or tunneled when status is 200.
type upstream struct {
	*httptest.Server
	hits       atomic.Int32
	lastHeader atomic.Value
}

func newUpstream(t *testing.T, name string, status int) *upstream {
	t.Helper()
	up := &upstream{}
	up.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.hits.Add(1)
		up.lastHeader.Store(r.Header.Clone())
		if r.Method == http.MethodConnect {
			tunnel(w, r, status)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Via", name)
		w.Header().Set("Keep-Alive", "timeout=5")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(up.Close)
	return up
}

func tunnel(w http.ResponseWriter, r *http.Request, status int) {
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	target, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	client, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		_ = target.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	go func() { _, _ = io.Copy(target, client); _ = target.Close() }()
	go func() { _, _ = io.Copy(client, target); _ = client.Close() }()
}

// startServer runs a forward proxy over the given upstreams, in preference
// order, and returns an HTTP client configured to use it.
func startServer(t *testing.T, upstreams ...string) (*http.Client, string) {
	t.Helper()
	pool := switcher.NewPool(switcher.PoolConfig{Logger: quietLogger()},
		switcher.StaticSource{Proxies: upstreams})
	pool.Refresh(context.Background())
	if len(upstreams) > 0 {
		first, err := url.Parse(upstreams[0])
		if err != nil {
			t.Fatal(err)
		}
		pool.Report(first, true)
	}
	tcfg := switcher.TransportConfig{Logger: quietLogger()}
	srv := httptest.NewServer(New(switcher.NewTransport(pool, tcfg), Options{SwitchOnStatus: true, Logger: quietLogger()}))
	t.Cleanup(srv.Close)
	proxyURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
		Timeout:   10 * time.Second,
	}
	return client, srv.URL
}

func newRequest(t *testing.T, method, target string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestHTTP_SwitchesOnBlockedStatus(t *testing.T) {
	bad := newUpstream(t, "bad", http.StatusForbidden)
	good := newUpstream(t, "good", http.StatusOK)
	client, _ := startServer(t, bad.URL, good.URL)

	resp, err := client.Do(newRequest(t, http.MethodGet, "http://target.test/", http.NoBody))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Via") != "good" || bad.hits.Load() != 1 {
		t.Fatalf("status %d, via %q, bad hits %d", resp.StatusCode, resp.Header.Get("X-Via"), bad.hits.Load())
	}
}

func TestHTTP_ReplaysSmallBodyAcrossProxies(t *testing.T) {
	// A closed port proves the target saw nothing, so even a POST may be resent.
	good := newUpstream(t, "good", http.StatusOK)
	client, _ := startServer(t, closedURL(t), good.URL)

	resp, err := client.Do(newRequest(t, http.MethodPost, "http://target.test/", strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if body, _ := io.ReadAll(resp.Body); string(body) != "payload" || resp.Header.Get("X-Via") != "good" {
		t.Fatalf("body %q, via %q", body, resp.Header.Get("X-Via"))
	}
}

func TestHTTP_LargeBodyGetsOneAttemptAndArrivesWhole(t *testing.T) {
	bad := newUpstream(t, "bad", http.StatusServiceUnavailable)
	good := newUpstream(t, "good", http.StatusOK)
	client, _ := startServer(t, bad.URL, good.URL)

	payload := bytes.Repeat([]byte("x"), maxBufferedBody+1024)
	// GET, because a POST is never repeated after delivery whatever its size.
	resp, err := client.Do(newRequest(t, http.MethodGet, "http://target.test/", bytes.NewReader(payload)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable || good.hits.Load() != 0 {
		t.Fatalf("status %d, good hits %d", resp.StatusCode, good.hits.Load())
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("body truncated: got %d bytes, want %d", len(body), len(payload))
	}
}

func TestHTTP_StripsHopByHopHeaders(t *testing.T) {
	up := newUpstream(t, "up", http.StatusOK)
	client, _ := startServer(t, up.URL)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://target.test/", http.NoBody)
	req.Header.Set("Connection", "X-Secret-Hop")
	req.Header.Set("X-Secret-Hop", "1")
	req.Header.Set("Proxy-Authorization", "Basic abc")
	req.Header.Set("X-Keep", "1")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	seen, _ := up.lastHeader.Load().(http.Header)
	if seen.Get("X-Secret-Hop") != "" || seen.Get("Proxy-Authorization") != "" {
		t.Fatalf("hop-by-hop headers were forwarded: %v", seen)
	}
	if seen.Get("X-Keep") != "1" {
		t.Fatalf("end-to-end header was dropped: %v", seen)
	}
	if resp.Header.Get("Keep-Alive") != "" {
		t.Fatal("hop-by-hop response header was passed to the client")
	}
}

func TestHTTP_NoProxyReturns503(t *testing.T) {
	client, _ := startServer(t)
	resp, err := client.Do(newRequest(t, http.MethodGet, "http://target.test/", http.NoBody))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestHTTP_AllAttemptsFailingReturns502WithoutPassword(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := strings.Replace(dead.URL, "http://", "http://user:s3cret@", 1)
	dead.Close()
	client, _ := startServer(t, deadURL)

	resp, err := client.Do(newRequest(t, http.MethodGet, "http://target.test/", http.NoBody))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(body), "s3cret") {
		t.Fatalf("status %d, body %q", resp.StatusCode, body)
	}
}

func TestHTTP_RejectsOriginFormRequests(t *testing.T) {
	_, proxyAddr := startServer(t)
	resp, err := http.DefaultClient.Do(newRequest(t, http.MethodGet, proxyAddr+"/not-a-proxy-request", http.NoBody))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestConnect_FailsOverAndReachesTLSTarget(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("secure hello"))
	}))
	t.Cleanup(target.Close)

	refusing := newUpstream(t, "refusing", http.StatusForbidden)
	working := newUpstream(t, "working", http.StatusOK)
	client, _ := startServer(t, refusing.URL, working.URL)
	tr := client.Transport.(*http.Transport)
	tr.TLSClientConfig = &tls.Config{RootCAs: target.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}

	resp, err := client.Do(newRequest(t, http.MethodGet, target.URL, http.NoBody))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "secure hello" {
		t.Fatalf("body %q", body)
	}
	if refusing.hits.Load() != 1 || working.hits.Load() != 1 {
		t.Fatalf("refusing hits %d, working hits %d", refusing.hits.Load(), working.hits.Load())
	}
}

func TestConnect_NoProxyReturns503(t *testing.T) {
	_, proxyAddr := startServer(t)
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", strings.TrimPrefix(proxyAddr, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	line := make([]byte, 12)
	if _, err := io.ReadFull(conn, line); err != nil {
		t.Fatal(err)
	}
	if string(line) != "HTTP/1.1 503" {
		t.Fatalf("response %q", line)
	}
}

func TestServe_StopsOnCancelAndClosesTunnels(t *testing.T) {
	echo, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		for {
			c, acceptErr := echo.Accept()
			if acceptErr != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()

	working := newUpstream(t, "working", http.StatusOK)
	pool := switcher.NewPool(switcher.PoolConfig{Logger: quietLogger()},
		switcher.StaticSource{Proxies: []string{working.URL}})
	pool.Refresh(context.Background())
	server := New(switcher.NewTransport(pool, switcher.TransportConfig{Logger: quietLogger()}), Options{SwitchOnStatus: true, Logger: quietLogger()})

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, ln) }()

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	addr := echo.Addr().String()
	if _, err := conn.Write([]byte("CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	const established = "HTTP/1.1 200 Connection Established\r\n\r\n"
	buf := make([]byte, len(established))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != established {
		t.Fatalf("handshake %q, %v", buf, err)
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop with a tunnel open")
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the tunnel should be closed after shutdown")
	}
}
