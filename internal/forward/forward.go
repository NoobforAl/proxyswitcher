// Package forward implements a local forward proxy on top of
// switcher.Transport, so any application can use automatic proxy
// switching through its HTTP_PROXY setting.
//
// There are two ways to serve plain HTTP. The default is the raw relay in
// relay.go, for scanners: requests pass through as received and are not repeated
// once they may have reached the target. With Options.SwitchOnStatus, requests go
// through Transport instead, for scrapers: they switch on response status codes,
// at the cost of Go's HTTP parsing and normalization.
//
// HTTPS arrives as a CONNECT tunnel whose contents are encrypted, so in both
// modes it only switches when a proxy cannot be reached or refuses the tunnel.
package forward

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/netutil"

	"github.com/NoobforAl/proxyswitcher/switcher"
)

const (
	// maxBufferedBody is the largest request body kept in memory for replay.
	// A larger body is streamed and gets one attempt only.
	maxBufferedBody = 1 << 20

	readHeaderTimeout = 10 * time.Second
	shutdownTimeout   = 10 * time.Second
	// DefaultMaxConnections limits concurrent client connections. Past this
	// point new connections wait, rather than exhausting file descriptors.
	DefaultMaxConnections = 4096
	// halfCloseTimeout limits how long a tunnel lingers after one side has
	// finished, so a peer that never closes cannot pin it forever.
	halfCloseTimeout = time.Minute
)

// Options configures a Server.
type Options struct {
	// SwitchOnStatus serves plain HTTP through Transport instead of the raw relay.
	SwitchOnStatus bool
	// SelfAddrs lists host:port values that mean this proxy. A request for one
	// is refused rather than looping forever.
	SelfAddrs []string
	// IdleTimeout closes relayed connections after this long with no traffic.
	// Zero means never.
	IdleTimeout time.Duration
	// MaxConnections limits concurrent client connections. Zero uses
	// DefaultMaxConnections.
	MaxConnections int
	// Logger receives events. Nil uses slog.Default.
	Logger *slog.Logger
}

// Server is the forward proxy. It implements http.Handler.
type Server struct {
	transport      *switcher.Transport
	logger         *slog.Logger
	switchOnStatus bool
	self           map[string]bool
	idleTimeout    time.Duration
	maxConnections int

	tunnels sync.WaitGroup
	// stopTunnels closes active tunnels, which http.Server.Shutdown does not
	// track once they are hijacked.
	stopTunnels context.Context
	stop        context.CancelFunc
}

// New builds a Server.
func New(transport *switcher.Transport, opts Options) *Server {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	maxConnections := opts.MaxConnections
	if maxConnections <= 0 {
		maxConnections = DefaultMaxConnections
	}
	self := make(map[string]bool, len(opts.SelfAddrs))
	for _, addr := range opts.SelfAddrs {
		self[strings.ToLower(addr)] = true
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		transport:      transport,
		logger:         logger,
		switchOnStatus: opts.SwitchOnStatus,
		self:           self,
		idleTimeout:    opts.IdleTimeout,
		maxConnections: maxConnections,
		stopTunnels:    ctx,
		stop:           cancel,
	}
}

func (s *Server) isSelf(addr string) bool {
	return s.self[strings.ToLower(addr)]
}

// Serve accepts connections on ln until ctx is canceled, then shuts down
// gracefully: in-flight requests get shutdownTimeout to finish, and tunnels
// are closed.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	ln = netutil.LimitListener(ln, s.maxConnections)
	if !s.switchOnStatus {
		return s.serveRaw(ctx, ln)
	}
	srv := &http.Server{Handler: s, ReadHeaderTimeout: readHeaderTimeout}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case err := <-errCh:
		s.closeTunnels()
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	err := srv.Shutdown(shutdownCtx)
	s.closeTunnels()
	if srvErr := <-errCh; !errors.Is(srvErr, http.ErrServerClosed) {
		return srvErr
	}
	return err
}

func (s *Server) closeTunnels() {
	s.stop()
	s.tunnels.Wait()
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleHTTP(w, r)
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() || r.URL.Host == "" || r.URL.Scheme != "http" {
		writeProxyError(w, http.StatusBadRequest, "http_request_error", "this is a forward proxy: expected an absolute http:// URL")
		return
	}
	if s.isSelf(hostWithPort(r.URL.Host)) {
		writeProxyError(w, http.StatusLoopDetected, "proxy_loop_detected", "the request targets this proxy")
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	removeHopByHop(out.Header)
	// Without this, net/http would add its own User-Agent for clients that
	// deliberately sent none.
	if _, ok := out.Header["User-Agent"]; !ok {
		out.Header.Set("User-Agent", "")
	}
	if err := prepareBody(out); err != nil {
		writeProxyError(w, http.StatusBadRequest, "http_request_error", "reading request body failed")
		return
	}

	resp, err := s.transport.RoundTrip(out)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	removeHopByHop(resp.Header)
	maps.Copy(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	copyFlushing(w, resp.Body)
}

// prepareBody buffers a small body so Transport can replay it. A larger one
// stays a one-shot stream, which limits that request to a single attempt.
func prepareBody(r *http.Request) error {
	if r.Body == nil || r.Body == http.NoBody {
		r.Body = http.NoBody
		return nil
	}
	head, err := io.ReadAll(io.LimitReader(r.Body, maxBufferedBody+1))
	if err != nil {
		return err
	}
	if len(head) > maxBufferedBody {
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(head), r.Body), r.Body}
		r.GetBody = nil
		return nil
	}
	r.ContentLength = int64(len(head))
	r.TransferEncoding = nil
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(head)), nil
	}
	r.Body, _ = r.GetBody()
	return nil
}

// copyFlushing streams body to the client as it arrives, so long-polling and
// event-stream responses are not held back in a buffer.
func copyFlushing(w http.ResponseWriter, body io.Reader) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, readErr := body.Read(buf)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			_ = rc.Flush()
		}
		if readErr != nil {
			return
		}
	}
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	// The client went away; there is nobody to answer.
	if r.Context().Err() != nil {
		return
	}
	s.logger.Warn("request failed", "host", r.URL.Host, "error", switcher.RedactText(err.Error()))
	if errors.Is(err, switcher.ErrNoProxy) {
		writeProxyError(w, http.StatusServiceUnavailable, "destination_unavailable", "no proxy available")
		return
	}
	writeProxyError(w, http.StatusBadGateway, "destination_unavailable", "all upstream attempts failed")
}

// writeProxyError answers with an error marked as coming from this proxy.
func writeProxyError(w http.ResponseWriter, status int, kind, details string) {
	w.Header().Set("Proxy-Status", proxyStatus(kind, details))
	http.Error(w, details, status)
}

func hostWithPort(host string) string {
	if _, _, err := net.SplitHostPort(host); err != nil {
		return net.JoinHostPort(strings.Trim(host, "[]"), "80")
	}
	return host
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if _, _, err := net.SplitHostPort(r.Host); err != nil {
		writeProxyError(w, http.StatusBadRequest, "http_request_error", "CONNECT target must be host:port")
		return
	}
	if s.isSelf(r.Host) {
		writeProxyError(w, http.StatusLoopDetected, "proxy_loop_detected", "the request targets this proxy")
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeProxyError(w, http.StatusInternalServerError, "proxy_internal_error", "CONNECT is not supported on this connection")
		return
	}

	upstream, err := s.transport.DialTunnel(r.Context(), r.Host)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	client, rw, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		s.logger.Warn("hijack failed", "error", err)
		return
	}
	// Drop the header-read deadline the HTTP server left on the connection.
	_ = client.SetDeadline(time.Time{})
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}

	s.tunnels.Add(1)
	defer s.tunnels.Done()
	// rw.Reader, not client: it may already hold bytes the client sent early.
	s.pipe(client, rw.Reader, upstream)
}

// activityReader extends both connections' idle deadlines on every read.
type activityReader struct {
	src   io.Reader
	touch func()
}

func (r activityReader) Read(p []byte) (int, error) {
	r.touch()
	return r.src.Read(p)
}

// pipe copies both directions until both finish or the server stops.
func (s *Server) pipe(client net.Conn, clientReader io.Reader, upstream net.Conn) {
	closeBoth := func() {
		_ = client.Close()
		_ = upstream.Close()
	}
	defer closeBoth()
	stop := context.AfterFunc(s.stopTunnels, closeBoth)
	defer stop()

	var halfClosed atomic.Bool
	touch := func() {
		if s.idleTimeout > 0 && !halfClosed.Load() {
			deadline := time.Now().Add(s.idleTimeout)
			_ = client.SetDeadline(deadline)
			_ = upstream.SetDeadline(deadline)
		}
	}
	done := make(chan struct{}, 2)
	transfer := func(dst net.Conn, src io.Reader) {
		_, _ = io.Copy(dst, activityReader{src: src, touch: touch})
		closeWrite(dst)
		// One side finished; give the other a bounded time to follow.
		halfClosed.Store(true)
		deadline := time.Now().Add(halfCloseTimeout)
		_ = client.SetDeadline(deadline)
		_ = upstream.SetDeadline(deadline)
		done <- struct{}{}
	}
	go transfer(upstream, clientReader)
	go transfer(client, upstream)
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// removeHopByHop deletes headers that apply to a single connection, including
// any the Connection header names (RFC 9110, section 7.6.1).
func removeHopByHop(h http.Header) {
	for _, value := range h.Values("Connection") {
		for name := range strings.SplitSeq(value, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		h.Del(name)
	}
}
