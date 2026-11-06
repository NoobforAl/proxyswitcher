package forward

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NoobforAl/proxyswitcher/switcher"
)

// recorder is a fake upstream that records exactly the bytes it receives and
// answers with a canned response, so tests can assert on the wire format.
type recorder struct {
	ln       net.Listener
	response string
	// echoAfterResponse keeps the connection open and echoes data, like a WebSocket.
	echoAfterResponse bool
	// closeWithoutResponse hangs up after reading the request.
	closeWithoutResponse bool

	mu    sync.Mutex
	heads []string
	body  bytes.Buffer
	hits  atomic.Int32
}

func newRecorder(t *testing.T, response string) *recorder {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{ln: ln, response: response}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go r.handle(conn)
		}
	}()
	return r
}

func (r *recorder) url() string { return "http://" + r.ln.Addr().String() }

func (r *recorder) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	var head strings.Builder
	contentLength := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		head.WriteString(line)
		lower := strings.ToLower(line)
		if value, ok := strings.CutPrefix(lower, "content-length:"); ok {
			contentLength, _ = strconv.Atoi(strings.TrimSpace(value))
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	body := make([]byte, contentLength)
	n, _ := io.ReadFull(br, body)

	r.mu.Lock()
	r.heads = append(r.heads, head.String())
	r.body.Write(body[:n])
	r.mu.Unlock()
	r.hits.Add(1)

	if r.closeWithoutResponse {
		return
	}
	_, _ = io.WriteString(conn, r.response)
	if r.echoAfterResponse {
		_, _ = io.Copy(conn, br)
	}
}

func (r *recorder) lastHead(t *testing.T) string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.heads) == 0 {
		t.Fatal("the upstream received nothing")
	}
	return r.heads[len(r.heads)-1]
}

func (r *recorder) bodyString() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body.String()
}

const okResponse = "HTTP/1.1 200 OK\r\nx-lower-case: 1\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 2\r\n\r\nok"

// rawConfig adjusts a relay under test.
type rawConfig struct {
	transport switcher.TransportConfig
	opts      Options
}

// startRelay runs the relay over the given proxies, in preference order. It
// returns the address to connect to and the pool.
func startRelay(t *testing.T, cfg rawConfig, proxies ...string) (string, *switcher.Pool) {
	t.Helper()
	pool := switcher.NewPool(switcher.PoolConfig{Logger: quietLogger()},
		switcher.StaticSource{Proxies: proxies})
	pool.Refresh(context.Background())
	if len(proxies) > 0 {
		pool.Report(mustParse(t, proxies[0]), true)
	}
	cfg.transport.Logger = quietLogger()
	cfg.opts.Logger = quietLogger()
	server := New(switcher.NewTransport(pool, cfg.transport), cfg.opts)

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	return ln.Addr().String(), pool
}

func sendRaw(t *testing.T, addr, request string) string {
	t.Helper()
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	// The relay keeps connections open between requests, so a quiet moment after
	// some data counts as the end of the response.
	var out bytes.Buffer
	buf := make([]byte, 64<<10)
	wait := 5 * time.Second
	for {
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		n, err := conn.Read(buf)
		out.Write(buf[:n])
		if err != nil {
			return out.String()
		}
		wait = 200 * time.Millisecond
	}
}

// The upstream must receive the tool's bytes unchanged, apart from Connection
// handling, which belongs to this hop.
func TestRelay_RequestsArriveUnchanged(t *testing.T) {
	tests := []struct {
		name, request, want string
		wantBody            string
	}{
		{
			name:    "invalid escape",
			request: "GET http://t.test/a%zzb?id=1 HTTP/1.1\r\nHost: t.test\r\n\r\n",
			want:    "GET http://t.test/a%zzb?id=1 HTTP/1.1\r\nHost: t.test\r\nConnection: close\r\n\r\n",
		},
		{
			name:    "traversal and raw query characters",
			request: "GET http://t.test/x/../../etc/passwd?q=<script>'\"%00 HTTP/1.1\r\nHost: t.test\r\n\r\n",
			want:    "GET http://t.test/x/../../etc/passwd?q=<script>'\"%00 HTTP/1.1\r\nHost: t.test\r\nConnection: close\r\n\r\n",
		},
		{
			name:    "host header differs from URL",
			request: "GET http://t.test/ HTTP/1.1\r\nHost: evil.test\r\n\r\n",
			want:    "GET http://t.test/ HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n",
		},
		{
			name:    "header case and order, duplicates",
			request: "GET http://t.test/ HTTP/1.1\r\nx-CuStOm-TeSt: 1\r\nZ-First: 1\r\nHost: t.test\r\nA-Second: 2\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n",
			want:    "GET http://t.test/ HTTP/1.1\r\nx-CuStOm-TeSt: 1\r\nZ-First: 1\r\nHost: t.test\r\nA-Second: 2\r\nCookie: a=1\r\nCookie: b=2\r\nConnection: close\r\n\r\n",
		},
		{
			name:    "custom method",
			request: "FOO http://t.test/ HTTP/1.1\r\nHost: t.test\r\n\r\n",
			want:    "FOO http://t.test/ HTTP/1.1\r\nHost: t.test\r\nConnection: close\r\n\r\n",
		},
		{
			name:    "header name with a space",
			request: "GET http://t.test/ HTTP/1.1\r\nHost: t.test\r\nBad Header: x\r\n\r\n",
			want:    "GET http://t.test/ HTTP/1.1\r\nHost: t.test\r\nBad Header: x\r\nConnection: close\r\n\r\n",
		},
		{
			name:     "conflicting content-length",
			request:  "POST http://t.test/ HTTP/1.1\r\nHost: t.test\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
			want:     "POST http://t.test/ HTTP/1.1\r\nHost: t.test\r\nContent-Length: 3\r\nContent-Length: 3\r\nConnection: close\r\n\r\n",
			wantBody: "abc",
		},
		{
			name:     "content-length with transfer-encoding",
			request:  "POST http://t.test/ HTTP/1.1\r\nHost: t.test\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
			want:     "POST http://t.test/ HTTP/1.1\r\nHost: t.test\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
			wantBody: "0\r\n\r\n",
		},
		{
			name:    "client connection header is replaced in place",
			request: "GET http://t.test/ HTTP/1.1\r\nconnection: keep-alive\r\nHost: t.test\r\n\r\n",
			want:    "GET http://t.test/ HTTP/1.1\r\nconnection: close\r\nHost: t.test\r\n\r\n",
		},
		{
			name:    "local proxy credentials are not forwarded",
			request: "GET http://t.test/ HTTP/1.1\r\nHost: t.test\r\nProxy-Authorization: Basic abc\r\nProxy-Connection: keep-alive\r\n\r\n",
			want:    "GET http://t.test/ HTTP/1.1\r\nHost: t.test\r\nConnection: close\r\n\r\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			up := newRecorder(t, okResponse)
			addr, _ := startRelay(t, rawConfig{}, up.url())
			if got := sendRaw(t, addr, tc.request); !strings.HasPrefix(got, "HTTP/1.1 200 OK") {
				t.Fatalf("response %q", got)
			}
			if got := up.lastHead(t); got != tc.want {
				t.Errorf("upstream saw %q\nwant %q", got, tc.want)
			}
			if got := up.bodyString(); got != tc.wantBody {
				t.Errorf("body %q, want %q", got, tc.wantBody)
			}
			if up.hits.Load() != 1 {
				t.Errorf("upstream hits = %d, want 1", up.hits.Load())
			}
		})
	}
}

func TestRelay_ResponseArrivesUnchanged(t *testing.T) {
	up := newRecorder(t, okResponse)
	addr, _ := startRelay(t, rawConfig{}, up.url())
	got := sendRaw(t, addr, "GET http://t.test/ HTTP/1.1\r\nHost: t.test\r\n\r\n")
	if got != okResponse {
		t.Fatalf("client got %q\nwant %q", got, okResponse)
	}
}

// The relay asks upstreams to close, so their `Connection: close` must not reach
// a client that never asked for it. ZAP reports a 500 with that header as a
// possible buffer overflow, so passing it on creates a false finding.
func TestRelay_InducedCloseDoesNotReachClient(t *testing.T) {
	up := newRecorder(t, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\nConnection: close\r\n\r\nerr")
	addr, _ := startRelay(t, rawConfig{}, up.url())
	got := sendRaw(t, addr, "GET http://t.test/ HTTP/1.1\r\nHost: t.test\r\n\r\n")
	want := "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\n\r\nerr"
	if got != want {
		t.Fatalf("client got %q\nwant %q", got, want)
	}
}

func TestRelay_ClientAskingToCloseIsTold(t *testing.T) {
	for _, tc := range []struct{ name, request string }{
		{"explicit", "GET http://t.test/ HTTP/1.1\r\nHost: t.test\r\nConnection: close\r\n\r\n"},
		{"HTTP/1.0", "GET http://t.test/ HTTP/1.0\r\nHost: t.test\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := newRecorder(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			addr, _ := startRelay(t, rawConfig{}, up.url())
			want := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
			if got := sendRaw(t, addr, tc.request); got != want {
				t.Fatalf("client got %q\nwant %q", got, want)
			}
		})
	}
}

// Clients reuse connections, and a POST on a closing connection cannot be safely
// retried, so the relay has to keep client connections open between requests.
func TestRelay_OneClientConnectionCarriesManyRequests(t *testing.T) {
	up := newRecorder(t, okResponse)
	addr, _ := startRelay(t, rawConfig{}, up.url())
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	for i := range 3 {
		request := "POST http://t.test/ HTTP/1.1\r\nHost: t.test\r\nContent-Length: 7\r\n\r\npayload"
		if _, err := io.WriteString(conn, request); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(okResponse))
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != okResponse {
			t.Fatalf("response %d: %q, %v", i, buf, err)
		}
	}
	if up.hits.Load() != 3 || up.bodyString() != "payloadpayloadpayload" {
		t.Fatalf("hits %d, body %q", up.hits.Load(), up.bodyString())
	}
}

func TestRelay_PipelinedRequestsStaySeparate(t *testing.T) {
	up := newRecorder(t, okResponse)
	addr, _ := startRelay(t, rawConfig{}, up.url())
	one := "POST http://t.test/one HTTP/1.1\r\nHost: t.test\r\nContent-Length: 3\r\n\r\nabc"
	two := "GET http://t.test/two HTTP/1.1\r\nHost: t.test\r\nConnection: close\r\n\r\n"
	got := sendRaw(t, addr, one+two)
	if strings.Count(got, "HTTP/1.1 200 OK") != 2 {
		t.Fatalf("response %q", got)
	}
	if up.hits.Load() != 2 || !strings.HasPrefix(up.lastHead(t), "GET http://t.test/two") || up.bodyString() != "abc" {
		t.Fatalf("hits %d, last %q, body %q", up.hits.Load(), up.lastHead(t), up.bodyString())
	}
}

func TestRelay_ChunkedPassesThroughByteForByte(t *testing.T) {
	const chunked = "5;ext=1\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked
	up := newChunkEcho(t, response)
	addr, _ := startRelay(t, rawConfig{}, up.url())
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	request := "POST http://t.test/ HTTP/1.1\r\nHost: t.test\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked
	for i := range 2 {
		if _, err := io.WriteString(conn, request); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(response))
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != response {
			t.Fatalf("response %d: %q, %v", i, buf, err)
		}
	}
	if got := up.received(); !strings.HasSuffix(got, chunked) || strings.Count(got, "hello") != 2 {
		t.Fatalf("upstream received %q", got)
	}
}

// With ambiguous framing the relay must not pick a side, so it stays out of the
// way and ends the connection after the response.
func TestRelay_AmbiguousFramingClosesAfterResponse(t *testing.T) {
	up := newRecorder(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	addr, _ := startRelay(t, rawConfig{}, up.url())
	got := sendRaw(t, addr, "POST http://t.test/ HTTP/1.1\r\nHost: t.test\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
	if got != "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok" {
		t.Fatalf("response %q", got)
	}
}

func TestRelay_ResponseWithoutLengthEndsAtClose(t *testing.T) {
	up := newRecorder(t, "HTTP/1.1 200 OK\r\n\r\nall of it")
	addr, _ := startRelay(t, rawConfig{}, up.url())
	got := sendRaw(t, addr, "GET http://t.test/ HTTP/1.1\r\nHost: t.test\r\n\r\n")
	if got != "HTTP/1.1 200 OK\r\n\r\nall of it" {
		t.Fatalf("response %q", got)
	}
}

func TestRelay_HeadResponseHasNoBody(t *testing.T) {
	up := newRecorder(t, "HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n")
	addr, _ := startRelay(t, rawConfig{}, up.url())
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	for range 2 {
		if _, err := io.WriteString(conn, "HEAD http://t.test/ HTTP/1.1\r\nHost: t.test\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		const want = "HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n"
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != want {
			t.Fatalf("response %q, %v", buf, err)
		}
	}
}

func TestChunkedReader_RejectsInvalidInput(t *testing.T) {
	reader := &chunkedReader{br: bufio.NewReader(strings.NewReader("zz\r\nhello\r\n"))}
	if _, err := io.ReadAll(reader); !errors.Is(err, errBadChunk) {
		t.Fatalf("err = %v", err)
	}
}

// chunkEcho reads a chunked request and answers with a canned response.
type chunkEcho struct {
	ln       net.Listener
	response string
	mu       sync.Mutex
	got      strings.Builder
}

func newChunkEcho(t *testing.T, response string) *chunkEcho {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	c := &chunkEcho{ln: ln, response: response}
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go c.handle(conn)
		}
	}()
	return c
}

func (c *chunkEcho) url() string { return "http://" + c.ln.Addr().String() }

func (c *chunkEcho) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	head, err := readHead(br)
	if err != nil {
		return
	}
	body, err := io.ReadAll(&chunkedReader{br: br})
	if err != nil {
		return
	}
	c.mu.Lock()
	c.got.Write(head)
	c.got.Write(body)
	c.mu.Unlock()
	_, _ = io.WriteString(conn, c.response)
}

func (c *chunkEcho) received() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.got.String()
}

func TestRelay_KeepAliveClientsKeepWorking(t *testing.T) {
	up := newRecorder(t, okResponse)
	addr, _ := startRelay(t, rawConfig{}, up.url())
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(mustParse(t, "http://"+addr))},
	}
	t.Cleanup(client.CloseIdleConnections)
	for i := range 20 {
		resp, err := client.Do(newRequest(t, http.MethodPost, "http://t.test/", strings.NewReader("payload")))
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if up.hits.Load() != 20 {
		t.Fatalf("upstream hits = %d, want 20", up.hits.Load())
	}
}

// A target's error may be the finding. It must come back as is, and the payload
// must never be sent again.
func TestRelay_TargetErrorsAreNeverRepeated(t *testing.T) {
	for _, status := range []string{"403 Forbidden", "429 Too Many Requests", "500 Internal Server Error", "503 Service Unavailable"} {
		t.Run(status, func(t *testing.T) {
			first := newRecorder(t, "HTTP/1.1 "+status+"\r\nContent-Length: 4\r\n\r\nbody")
			second := newRecorder(t, okResponse)
			addr, pool := startRelay(t, rawConfig{}, first.url(), second.url())

			got := sendRaw(t, addr, "POST http://t.test/ HTTP/1.1\r\nHost: t.test\r\nContent-Length: 7\r\n\r\npayload")
			if !strings.HasPrefix(got, "HTTP/1.1 "+status) || strings.Contains(got, "Proxy-Status") {
				t.Fatalf("response %q", got)
			}
			if first.hits.Load() != 1 || second.hits.Load() != 0 {
				t.Fatalf("hits first=%d second=%d, want exactly one delivery", first.hits.Load(), second.hits.Load())
			}
			for _, e := range pool.Snapshot() {
				if e.Failures != 0 {
					t.Fatalf("a target's answer penalized %s", switcher.RedactURL(e.URL))
				}
			}
		})
	}
}

func TestRelay_SwitchesWhenProxyIsUnreachable(t *testing.T) {
	dead := closedURL(t)
	good := newRecorder(t, okResponse)
	addr, pool := startRelay(t, rawConfig{}, dead, good.url())

	got := sendRaw(t, addr, "POST http://t.test/ HTTP/1.1\r\nHost: t.test\r\nContent-Length: 7\r\n\r\npayload")
	if !strings.HasPrefix(got, "HTTP/1.1 200") || good.hits.Load() != 1 || good.bodyString() != "payload" {
		t.Fatalf("response %q, hits %d, body %q", got, good.hits.Load(), good.bodyString())
	}
	for _, e := range pool.Snapshot() {
		if e.URL.String() == dead && e.Failures != 1 {
			t.Fatalf("dead proxy failures = %d, want 1", e.Failures)
		}
	}
}

func TestRelay_ProxyAuthRejectionSwitchesAndReplaysBody(t *testing.T) {
	rejecting := newRecorder(t, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n")
	good := newRecorder(t, okResponse)
	addr, _ := startRelay(t, rawConfig{}, rejecting.url(), good.url())

	got := sendRaw(t, addr, "POST http://t.test/ HTTP/1.1\r\nHost: t.test\r\nContent-Length: 7\r\n\r\npayload")
	if !strings.HasPrefix(got, "HTTP/1.1 200") {
		t.Fatalf("response %q", got)
	}
	if good.bodyString() != "payload" {
		t.Fatalf("the replacement proxy got body %q", good.bodyString())
	}
}

// A target's own 407 has no proof it came from the proxy, so it is not retried.
func TestRelay_407WithoutChallengeIsTheTargets(t *testing.T) {
	first := newRecorder(t, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
	second := newRecorder(t, okResponse)
	addr, _ := startRelay(t, rawConfig{}, first.url(), second.url())
	if got := sendRaw(t, addr, "GET http://t.test/ HTTP/1.1\r\nHost: t.test\r\n\r\n"); !strings.HasPrefix(got, "HTTP/1.1 407") {
		t.Fatalf("response %q", got)
	}
	if second.hits.Load() != 0 {
		t.Fatal("the request was repeated")
	}
}

func TestRelay_NoResponseIsReportedNotRepeated(t *testing.T) {
	first := newRecorder(t, "")
	first.closeWithoutResponse = true
	second := newRecorder(t, okResponse)
	addr, _ := startRelay(t, rawConfig{}, first.url(), second.url())

	got := sendRaw(t, addr, "POST http://t.test/ HTTP/1.1\r\nHost: t.test\r\nContent-Length: 7\r\n\r\npayload")
	if !strings.HasPrefix(got, "HTTP/1.1 502") || !strings.Contains(got, "Proxy-Status: proxyswitcher; error=destination_unavailable") {
		t.Fatalf("response %q", got)
	}
	if second.hits.Load() != 0 {
		t.Fatal("the request may have been delivered, so it must not be repeated")
	}
}

func TestRelay_WebSocketUpgrade(t *testing.T) {
	up := newRecorder(t, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	up.echoAfterResponse = true
	addr, _ := startRelay(t, rawConfig{}, up.url())

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	request := "GET http://t.test/ws HTTP/1.1\r\nHost: t.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	const want = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != want {
		t.Fatalf("handshake %q, %v", buf, err)
	}
	if _, err := io.WriteString(conn, "frame"); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 5)
	if _, err := io.ReadFull(conn, echo); err != nil || string(echo) != "frame" {
		t.Fatalf("echo %q, %v", echo, err)
	}
	if got := up.lastHead(t); got != "GET http://t.test/ws HTTP/1.1\r\nHost: t.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc\r\n\r\n" {
		t.Fatalf("upstream saw %q", got)
	}
}

func TestRelay_InjectsUpstreamCredentials(t *testing.T) {
	up := newRecorder(t, okResponse)
	withCreds := strings.Replace(up.url(), "http://", "http://user:pass@", 1)
	addr, _ := startRelay(t, rawConfig{}, withCreds)
	sendRaw(t, addr, "GET http://t.test/ HTTP/1.1\r\nHost: t.test\r\nProxy-Authorization: Basic local\r\n\r\n")
	got := up.lastHead(t)
	if !strings.Contains(got, "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n") || strings.Contains(got, "Basic local") {
		t.Fatalf("upstream saw %q", got)
	}
}

func TestRelay_DirectRouteUsesOriginForm(t *testing.T) {
	target := newRecorder(t, okResponse)
	addr, _ := startRelay(t, rawConfig{transport: switcher.TransportConfig{FallbackDirect: true}})
	host := target.ln.Addr().String()
	sendRaw(t, addr, "GET http://"+host+"/a%zzb?q=1 HTTP/1.1\r\nHost: evil.test\r\n\r\n")
	want := "GET /a%zzb?q=1 HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n"
	if got := target.lastHead(t); got != want {
		t.Fatalf("target saw %q\nwant %q", got, want)
	}
}

func TestRelay_ProxyGeneratedErrorsAreMarked(t *testing.T) {
	up := newRecorder(t, okResponse)
	addr, _ := startRelay(t, rawConfig{opts: Options{SelfAddrs: []string{"me.test:80"}}}, up.url())
	emptyAddr, _ := startRelay(t, rawConfig{})
	for _, tc := range []struct {
		name, addr, request, status, kind string
	}{
		{"origin form", addr, "GET / HTTP/1.1\r\nHost: t.test\r\n\r\n", "400", "http_request_error"},
		{"malformed line", addr, "NONSENSE\r\n\r\n", "400", "http_request_error"},
		{"bad CONNECT target", addr, "CONNECT nohost HTTP/1.1\r\n\r\n", "400", "http_request_error"},
		{"loop", addr, "GET http://me.test/ HTTP/1.1\r\nHost: me.test\r\n\r\n", "508", "proxy_loop_detected"},
		{"empty pool", emptyAddr, "GET http://t.test/ HTTP/1.1\r\nHost: t.test\r\n\r\n", "503", "destination_unavailable"},
		{"empty pool CONNECT", emptyAddr, "CONNECT t.test:443 HTTP/1.1\r\nHost: t.test:443\r\n\r\n", "503", "destination_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sendRaw(t, tc.addr, tc.request)
			if !strings.HasPrefix(got, "HTTP/1.1 "+tc.status) || !strings.Contains(got, "Proxy-Status: proxyswitcher; error="+tc.kind) {
				t.Fatalf("response %q", got)
			}
		})
	}
	if up.hits.Load() != 0 {
		t.Fatal("a refused request reached the upstream")
	}
}

func TestRelay_HeadTooLargeIsRefused(t *testing.T) {
	up := newRecorder(t, okResponse)
	addr, _ := startRelay(t, rawConfig{}, up.url())
	huge := "GET http://t.test/ HTTP/1.1\r\nX-Big: " + strings.Repeat("a", maxHeadBytes) + "\r\n\r\n"
	if got := sendRaw(t, addr, huge); !strings.HasPrefix(got, "HTTP/1.1 431") {
		t.Fatalf("response %q", got)
	}
}

func TestRelay_LargeBodyStreams(t *testing.T) {
	up := newRecorder(t, okResponse)
	addr, _ := startRelay(t, rawConfig{}, up.url())
	payload := strings.Repeat("x", maxReplayBytes+4096)
	request := "POST http://t.test/ HTTP/1.1\r\nHost: t.test\r\nContent-Length: " + strconv.Itoa(len(payload)) + "\r\n\r\n" + payload
	if got := sendRaw(t, addr, request); !strings.HasPrefix(got, "HTTP/1.1 200") {
		t.Fatalf("response %q", got)
	}
	if up.bodyString() != payload {
		t.Fatalf("body has %d bytes, want %d", len(up.bodyString()), len(payload))
	}
}

func TestRelay_StickyKeepsOneProxyPerSite(t *testing.T) {
	a := newRecorder(t, okResponse)
	b := newRecorder(t, okResponse)
	addr, _ := startRelay(t, rawConfig{transport: switcher.TransportConfig{StickyHosts: true}}, a.url(), b.url())
	for range 6 {
		sendRaw(t, addr, "GET http://t.test/ HTTP/1.1\r\nHost: t.test\r\n\r\n")
	}
	if a.hits.Load() != 6 || b.hits.Load() != 0 {
		t.Fatalf("hits a=%d b=%d, want every request on one proxy", a.hits.Load(), b.hits.Load())
	}
}

// fullConnectProxy tunnels CONNECT requests, for testing HTTPS end to end.
func fullConnectProxy(t *testing.T) string {
	t.Helper()
	up := newUpstream(t, "tunnel", http.StatusOK)
	return up.URL
}

func TestRelay_ConnectFailsOverAndTunnels(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("secure hello"))
	}))
	t.Cleanup(target.Close)
	refusing := newUpstream(t, "refusing", http.StatusForbidden)
	addr, _ := startRelay(t, rawConfig{}, refusing.URL, fullConnectProxy(t))

	client := target.Client()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected transport")
	}
	transport = transport.Clone()
	transport.Proxy = http.ProxyURL(mustParse(t, "http://"+addr))
	client = &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(client.CloseIdleConnections)

	resp, err := client.Do(newRequest(t, http.MethodGet, target.URL, http.NoBody))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "secure hello" || refusing.hits.Load() != 1 {
		t.Fatalf("body %q, refusing hits %d", body, refusing.hits.Load())
	}
}

func TestRelay_ServeStopsWithActiveConnections(t *testing.T) {
	up := newRecorder(t, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\n")
	up.echoAfterResponse = true
	pool := switcher.NewPool(switcher.PoolConfig{Logger: quietLogger()}, switcher.StaticSource{Proxies: []string{up.url()}})
	pool.Refresh(context.Background())
	server := New(switcher.NewTransport(pool, switcher.TransportConfig{Logger: quietLogger()}), Options{Logger: quietLogger()})
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
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.WriteString(conn, "GET http://t.test/ HTTP/1.1\r\nHost: t.test\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(shutdownTimeout + 5*time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestRelay_IdleTimeoutClosesSilentConnections(t *testing.T) {
	up := newRecorder(t, "")
	up.response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\n"
	up.echoAfterResponse = true
	addr, _ := startRelay(t, rawConfig{opts: Options{IdleTimeout: 100 * time.Millisecond}}, up.url())
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	start := time.Now()
	if _, err := io.WriteString(conn, "GET http://t.test/ HTTP/1.1\r\nHost: t.test\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(conn)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %v, the idle timeout did not close the connection", elapsed)
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func closedURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL
	srv.Close()
	return u
}
