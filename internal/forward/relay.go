package forward

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NoobforAl/proxyswitcher/switcher"
)

// The raw relay serves scanner mode. Go's HTTP server rejects or normalizes
// requests before a handler ever runs: an invalid escape gets a 400, the Host
// header is overwritten, and header case changes. Security tools send such
// requests on purpose, so this path reads just enough of each request to choose a
// route and find where it ends, and passes the bytes through as received.
//
// Each request gets its own upstream connection, while the client's connection
// stays open between requests. When a request's framing is deliberately
// ambiguous, as in request smuggling tests, the relay does not pick a side: it
// streams what the client sends and closes the connection after the response.

const (
	// maxHeadBytes limits a request or response head.
	maxHeadBytes = 64 << 10
	// maxReplayBytes is the most request data kept for a replay after a 407.
	maxReplayBytes = 1 << 20

	relayBufferSize = 32 << 10
)

var errHeadTooLarge = errors.New("head too large")

func (s *Server) serveRaw(ctx context.Context, ln net.Listener) error {
	acceptErr := make(chan error, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			s.tunnels.Go(func() {
				defer func() { _ = conn.Close() }()
				s.handleRaw(conn)
			})
		}
	}()

	select {
	case err := <-acceptErr:
		s.closeTunnels()
		return err
	case <-ctx.Done():
	}
	_ = ln.Close()
	<-acceptErr

	drained := make(chan struct{})
	go func() {
		s.tunnels.Wait()
		close(drained)
	}()
	timer := time.NewTimer(shutdownTimeout)
	defer timer.Stop()
	select {
	case <-drained:
	case <-timer.C:
	}
	s.closeTunnels()
	return nil
}

// handleRaw serves one client connection, one request at a time.
func (s *Server) handleRaw(client net.Conn) {
	stop := context.AfterFunc(s.stopTunnels, func() { _ = client.Close() })
	defer stop()

	br := bufio.NewReaderSize(client, relayBufferSize)
	wait := readHeaderTimeout
	for {
		_ = client.SetReadDeadline(time.Now().Add(wait))
		head, err := readHead(br)
		switch {
		case errors.Is(err, errHeadTooLarge):
			writeSynthetic(client, http.StatusRequestHeaderFieldsTooLarge, "http_request_error", "request head too large")
			return
		case err != nil:
			if len(head) > 0 {
				writeSynthetic(client, http.StatusBadRequest, "http_request_error", "incomplete request head")
			}
			return
		}
		_ = client.SetReadDeadline(time.Time{})

		req, err := parseRequestHead(head)
		if err != nil {
			writeSynthetic(client, http.StatusBadRequest, "http_request_error", err.Error())
			return
		}
		if s.isSelf(req.addr) {
			writeSynthetic(client, http.StatusLoopDetected, "proxy_loop_detected", "the request targets this proxy")
			return
		}
		if req.connect {
			s.rawConnect(client, br, req.addr)
			return
		}
		if !s.rawHTTP(client, br, req) {
			return
		}
		// Between requests, wait as long as any idle connection may last.
		wait = max(s.idleTimeout, readHeaderTimeout)
	}
}

func (s *Server) rawConnect(client net.Conn, br *bufio.Reader, addr string) {
	upstream, err := s.transport.DialTunnel(s.stopTunnels, addr)
	if err != nil {
		s.logger.Warn("tunnel failed", "host", addr, "error", switcher.RedactText(err.Error()))
		status := http.StatusBadGateway
		if errors.Is(err, switcher.ErrNoProxy) {
			status = http.StatusServiceUnavailable
		}
		writeSynthetic(client, status, "destination_unavailable", "could not open a tunnel through any proxy")
		return
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = upstream.Close()
		return
	}
	s.pipe(client, br, upstream)
}

// rawHTTP relays one request, and reports whether the client connection can take
// another. It tries another proxy only when the target cannot have received the
// request. Once it may have, any failure is reported instead, because repeating a
// payload could apply it twice or change a scan's results.
func (s *Server) rawHTTP(client net.Conn, br *bufio.Reader, req *requestHead) bool {
	attempts := s.transport.Begin(switcher.HostKey(req.addr), 0)
	body := req.bodyReader(br)
	var replay []byte
	for {
		via, err := attempts.Next()
		if err != nil {
			attempts.Finish()
			writeSynthetic(client, http.StatusServiceUnavailable, "destination_unavailable", "no proxy available")
			return false
		}
		upstream, err := s.dialRelay(via, req.addr)
		if err != nil {
			s.logger.Info("switching proxy after connection failure",
				"attempt", attempts.Number(), "error", switcher.RedactText(err.Error()))
			if switcher.IsProxyFault(err) {
				attempts.ProxyFault(via)
			} else {
				attempts.Ambiguous(via)
			}
			continue
		}
		copier := newBodyCopier(s, client, body, upstream, replay)
		outcome, reusable := s.exchange(client, br, upstream, req, via, copier)
		_ = upstream.Close()
		switch outcome {
		case outcomeDelivered:
			attempts.Success(via)
			return reusable
		case outcomeAuthRejected:
			attempts.ProxyFault(via)
			if copier.overflow {
				writeSynthetic(client, http.StatusBadGateway, "proxy_configuration_error",
					"the proxy rejected our credentials and the request is too large to send again")
				attempts.Finish()
				return false
			}
			replay = copier.captured
		case outcomeNoResponse:
			attempts.Ambiguous(via)
			attempts.Finish()
			writeSynthetic(client, http.StatusBadGateway, "destination_unavailable",
				"the upstream closed without responding; the request was not repeated because it may have been delivered")
			return false
		}
	}
}

// dialRelay connects to an HTTP proxy, which takes the request as is, or to the
// target through SOCKS or directly.
func (s *Server) dialRelay(via *url.URL, addr string) (net.Conn, error) {
	if via != nil && via.Scheme != "socks5" {
		return s.transport.DialProxy(s.stopTunnels, via)
	}
	return s.transport.DialThrough(s.stopTunnels, via, addr)
}

type relayOutcome int

const (
	outcomeDelivered relayOutcome = iota
	outcomeAuthRejected
	outcomeNoResponse
)

// exchange sends a request on one upstream connection and relays the response.
// The second result reports whether the client connection can take another
// request.
func (s *Server) exchange(client net.Conn, clientReader io.Reader, upstream net.Conn, req *requestHead, via *url.URL, copier *bodyCopier) (relayOutcome, bool) {
	stop := context.AfterFunc(s.stopTunnels, func() { _ = upstream.Close() })
	defer stop()

	out := req.rewrite(via)
	s.touch(upstream.SetWriteDeadline)
	if _, err := upstream.Write(append(out, copier.captured...)); err != nil {
		return outcomeNoResponse, false
	}
	copier.start()
	defer copier.stop()

	reader := bufio.NewReaderSize(upstream, relayBufferSize)
	proxied := via != nil && via.Scheme != "socks5"
	for first := true; ; first = false {
		s.touch(upstream.SetReadDeadline)
		head, err := readHead(reader)
		if len(head) == 0 {
			return outcomeNoResponse, false
		}
		// A partial or oversized head is not ours to judge: relay it unchanged.
		if err != nil {
			s.writeClient(client, head)
			s.copyResponse(client, upstream, reader)
			return outcomeDelivered, false
		}
		status := responseStatus(head)
		// Only an HTTP proxy's own auth challenge means the target saw nothing.
		if first && proxied && status == http.StatusProxyAuthRequired && headHasField(head, "proxy-authenticate") {
			return outcomeAuthRejected, false
		}
		switch {
		case status == http.StatusSwitchingProtocols:
			s.writeClient(client, head)
			copier.stop()
			s.upgradeTunnel(client, clientReader, reader, upstream)
			return outcomeDelivered, false
		case status >= 100 && status < 200:
			s.writeClient(client, head)
		default:
			s.writeClient(client, req.responseHead(head))
			framed, known := responseBody(reader, req.method, status, head)
			complete := s.copyResponse(client, upstream, framed)
			copier.stop()
			return outcomeDelivered, complete && known && copier.finished && !req.wantsClose()
		}
	}
}

// upgradeTunnel takes over a connection after 101 Switching Protocols, such as
// a WebSocket, first delivering anything already read from the upstream.
func (s *Server) upgradeTunnel(client net.Conn, clientReader io.Reader, reader *bufio.Reader, upstream net.Conn) {
	if n := reader.Buffered(); n > 0 {
		early, err := reader.Peek(n)
		if err != nil {
			return
		}
		s.writeClient(client, early)
		if _, err := reader.Discard(n); err != nil {
			return
		}
	}
	s.pipe(client, clientReader, upstream)
}

func (s *Server) writeClient(client net.Conn, data []byte) {
	s.touch(client.SetWriteDeadline)
	_, _ = client.Write(data)
}

// copyResponse streams a response body, and reports whether it reached its end.
func (s *Server) copyResponse(client, upstream net.Conn, reader io.Reader) bool {
	buf := make([]byte, relayBufferSize)
	for {
		s.touch(upstream.SetReadDeadline)
		n, readErr := reader.Read(buf)
		if n > 0 {
			s.touch(client.SetWriteDeadline)
			if _, err := client.Write(buf[:n]); err != nil {
				return false
			}
		}
		if readErr != nil {
			return errors.Is(readErr, io.EOF)
		}
	}
}

// touch extends an idle deadline. With no idle timeout it does nothing, so a
// slow target, as in a time-based test, is never cut off.
func (s *Server) touch(set func(time.Time) error) {
	if s.idleTimeout > 0 {
		_ = set(time.Now().Add(s.idleTimeout))
	}
}

// bodyCopier streams request data from the client to the upstream while the
// response is awaited, keeping what it sent in case a 407 allows a replay.
type bodyCopier struct {
	server   *Server
	client   net.Conn
	src      io.Reader
	dst      net.Conn
	captured []byte
	overflow bool
	// finished reports that the body was read to its end. Read it after stop.
	finished bool

	started bool
	done    chan struct{}
	mu      sync.Mutex
	stopped bool
}

func newBodyCopier(s *Server, client net.Conn, src io.Reader, dst net.Conn, replay []byte) *bodyCopier {
	return &bodyCopier{server: s, client: client, src: src, dst: dst, captured: replay, done: make(chan struct{})}
}

func (c *bodyCopier) start() {
	c.started = true
	go func() {
		defer close(c.done)
		buf := make([]byte, relayBufferSize)
		for {
			if !c.armRead() {
				return
			}
			n, err := c.src.Read(buf)
			if n > 0 {
				if len(c.captured)+n > maxReplayBytes {
					c.overflow = true
					c.captured = nil
				} else if !c.overflow {
					c.captured = append(c.captured, buf[:n]...)
				}
				c.server.touch(c.dst.SetWriteDeadline)
				if _, writeErr := c.dst.Write(buf[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				c.finished = errors.Is(err, io.EOF)
				return
			}
		}
	}()
}

// armRead sets the read deadline, unless stop already ran. The lock stops a late
// deadline from overwriting the one stop uses to interrupt the read.
func (c *bodyCopier) armRead() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return false
	}
	c.server.touch(c.client.SetReadDeadline)
	return true
}

// stop ends the copy and waits for it, leaving the client connection usable.
func (c *bodyCopier) stop() {
	c.mu.Lock()
	already := c.stopped
	c.stopped = true
	if !already && c.started {
		_ = c.client.SetReadDeadline(time.Unix(1, 0))
	}
	c.mu.Unlock()
	if already || !c.started {
		return
	}
	<-c.done
	_ = c.client.SetReadDeadline(time.Time{})
}

// requestHead is what the relay needs to know about a request. The rest of the
// bytes are never interpreted.
type requestHead struct {
	raw     []byte
	method  string
	target  string
	version string
	addr    string
	path    string
	connect bool
}

// parseRequestHead reads only the request line, and deliberately avoids
// url.Parse, which would reject the malformed paths scanners send on purpose.
func parseRequestHead(head []byte) (*requestHead, error) {
	line, _, _ := bytes.Cut(head, []byte("\n"))
	fields := strings.TrimRight(string(line), "\r")
	method, rest, ok := strings.Cut(fields, " ")
	if !ok {
		return nil, errors.New("malformed request line")
	}
	i := strings.LastIndexByte(rest, ' ')
	if i < 0 {
		return nil, errors.New("malformed request line")
	}
	req := &requestHead{raw: head, method: method, target: rest[:i], version: rest[i+1:]}

	if strings.EqualFold(method, http.MethodConnect) {
		if _, _, err := net.SplitHostPort(req.target); err != nil {
			return nil, errors.New("CONNECT target must be host:port")
		}
		req.connect = true
		req.addr = req.target
		return req, nil
	}

	scheme, after, ok := strings.Cut(req.target, "://")
	if !ok {
		return nil, errors.New("this is a forward proxy: expected an absolute URL")
	}
	authority := after
	req.path = "/"
	if j := strings.IndexAny(after, "/?#"); j >= 0 {
		authority = after[:j]
		req.path = after[j:]
		if req.path[0] != '/' {
			req.path = "/" + req.path
		}
	}
	if k := strings.LastIndexByte(authority, '@'); k >= 0 {
		authority = authority[k+1:]
	}
	if authority == "" {
		return nil, errors.New("the URL has no host")
	}
	if _, _, err := net.SplitHostPort(authority); err != nil {
		port := "80"
		if strings.EqualFold(scheme, "https") {
			port = "443"
		}
		authority = net.JoinHostPort(strings.Trim(authority, "[]"), port)
	}
	req.addr = authority
	return req, nil
}

// rewrite returns the bytes to send for a route. An HTTP proxy gets the request
// line unchanged; SOCKS and direct routes reach the target itself, which expects
// origin form. Connection handling and proxy credentials are the only headers
// touched, and those belong to this hop, not to the target.
func (r *requestHead) rewrite(via *url.URL) []byte {
	proxied := via != nil && via.Scheme != "socks5"
	lines := splitLines(r.raw)
	out := make([]byte, 0, len(r.raw)+64)
	if proxied {
		out = append(out, lines[0]...)
	} else {
		out = append(out, r.method+" "+r.path+" "+r.version+"\r\n"...)
	}
	upgrade := headHasField(r.raw, "upgrade")
	wroteConnection := false
	skippingFold := false
	for _, line := range lines[1:] {
		if isBlank(line) {
			if !upgrade && !wroteConnection {
				out = append(out, "Connection: close\r\n"...)
			}
			if auth := switcher.ProxyAuthorization(via); proxied && auth != "" {
				out = append(out, "Proxy-Authorization: "+auth+"\r\n"...)
			}
			out = append(out, line...)
			continue
		}
		// A folded line continues the header before it.
		if line[0] == ' ' || line[0] == '\t' {
			if !skippingFold {
				out = append(out, line...)
			}
			continue
		}
		skippingFold = false
		switch fieldName(line) {
		case "proxy-authorization", "proxy-connection":
			skippingFold = true
			continue
		case "connection":
			wroteConnection = true
			if !upgrade {
				name, _, _ := bytes.Cut(line, []byte(":"))
				out = append(out, name...)
				out = append(out, ": close\r\n"...)
				skippingFold = true
				continue
			}
		}
		out = append(out, line...)
	}
	return out
}

// responseHead prepares a response head for the client. The relay asks every
// upstream to close, so a `Connection: close` here says nothing about the target,
// yet scanners read meaning into it: ZAP reports a 500 with that header as a
// possible buffer overflow. So it is removed, unless the connection really will
// end here because of this request.
func (r *requestHead) responseHead(head []byte) []byte {
	if r.wantsClose() {
		if headHasField(head, "connection") {
			return head
		}
		out := make([]byte, 0, len(head)+19)
		for _, line := range splitLines(head) {
			if isBlank(line) {
				out = append(out, "Connection: close\r\n"...)
			}
			out = append(out, line...)
		}
		return out
	}
	out := make([]byte, 0, len(head))
	for _, line := range splitLines(head) {
		if fieldName(line) == "connection" && isCloseValue(line) {
			continue
		}
		out = append(out, line...)
	}
	return out
}

// wantsClose reports whether the client connection ends after this response:
// the client asked for that, by header or by using HTTP/1.0 without keep-alive,
// or the request's framing is ambiguous, so its end cannot be found.
func (r *requestHead) wantsClose() bool {
	if _, known := framingOf(r.raw); !known {
		return true
	}
	keepAlive := false
	for _, line := range splitLines(r.raw)[1:] {
		if fieldName(line) != "connection" {
			continue
		}
		if isCloseValue(line) {
			return true
		}
		keepAlive = keepAlive || bytes.Contains(bytes.ToLower(line), []byte("keep-alive"))
	}
	return r.version == "HTTP/1.0" && !keepAlive
}

func isCloseValue(line []byte) bool {
	_, value, _ := bytes.Cut(line, []byte(":"))
	return strings.EqualFold(string(bytes.TrimSpace(value)), "close")
}

// bodyKind says how a message's end is found.
type bodyKind struct {
	chunked bool
	length  int64
	// present is false when the head says nothing about a body.
	present bool
}

// framingOf reads a head's framing headers. The second result is false when they
// are ambiguous or invalid, as request smuggling tests make them on purpose: more
// than one length, a length with chunked encoding, or an encoding other than
// plain chunked.
func framingOf(head []byte) (bodyKind, bool) {
	var kind bodyKind
	lengths, encodings := 0, 0
	for _, line := range splitLines(head)[1:] {
		_, raw, _ := bytes.Cut(line, []byte(":"))
		value := strings.TrimSpace(string(raw))
		switch fieldName(line) {
		case "content-length":
			lengths++
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 {
				return kind, false
			}
			kind.length = n
			kind.present = true
		case "transfer-encoding":
			encodings++
			if !strings.EqualFold(value, "chunked") {
				return kind, false
			}
			kind.chunked = true
			kind.present = true
		}
		// A folded header could be hiding a framing value.
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			return kind, false
		}
	}
	if lengths > 1 || encodings > 1 || (lengths > 0 && encodings > 0) {
		return kind, false
	}
	return kind, true
}

// bodyReader returns a reader for this request's body, ending where the body
// ends so the next request stays unread. With ambiguous framing it streams
// whatever arrives.
func (r *requestHead) bodyReader(br *bufio.Reader) io.Reader {
	kind, known := framingOf(r.raw)
	if !known {
		return br
	}
	switch {
	case kind.chunked:
		return &chunkedReader{br: br}
	case kind.present:
		return io.LimitReader(br, kind.length)
	case headHasField(r.raw, "upgrade"):
		return br
	default:
		return strings.NewReader("")
	}
}

// responseBody returns a reader for a response's body. The second result is false
// when the only way to find its end is the connection closing, so the client
// connection cannot take another request.
func responseBody(reader *bufio.Reader, method string, status int, head []byte) (io.Reader, bool) {
	if strings.EqualFold(method, http.MethodHead) || status == http.StatusNoContent || status == http.StatusNotModified {
		return strings.NewReader(""), true
	}
	kind, known := framingOf(head)
	switch {
	case !known || !kind.present:
		return reader, false
	case kind.chunked:
		return &chunkedReader{br: reader}, true
	default:
		return io.LimitReader(reader, kind.length), true
	}
}

// chunkedReader passes a chunked body through byte for byte, including chunk
// sizes and trailers, and returns io.EOF after the final chunk. It stays unread
// past that point. Input that is not valid chunked encoding gets an error, which
// closes the connection rather than guessing where the message ends.
type chunkedReader struct {
	br        *bufio.Reader
	pending   []byte
	remaining int64
	trailers  bool
	done      bool
}

var errBadChunk = errors.New("invalid chunked encoding")

func (c *chunkedReader) Read(p []byte) (int, error) {
	for {
		if len(c.pending) > 0 {
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			return n, nil
		}
		if c.done {
			return 0, io.EOF
		}
		if c.remaining > 0 {
			limit := min(int64(len(p)), c.remaining)
			n, err := c.br.Read(p[:limit])
			c.remaining -= int64(n)
			if n > 0 {
				return n, nil
			}
			return 0, err
		}
		if err := c.nextLine(); err != nil {
			return 0, err
		}
	}
}

// nextLine reads one size or trailer line into pending.
func (c *chunkedReader) nextLine() error {
	line, err := c.br.ReadBytes('\n')
	if err != nil {
		return err
	}
	if len(line) > maxHeadBytes {
		return errBadChunk
	}
	c.pending = line
	text := strings.TrimRight(string(line), "\r\n")
	switch {
	case c.trailers:
		c.done = text == ""
	case text == "":
		// The line ending that follows a chunk's data.
	default:
		size, _, _ := strings.Cut(text, ";")
		n, parseErr := strconv.ParseInt(strings.TrimSpace(size), 16, 64)
		if parseErr != nil || n < 0 {
			return errBadChunk
		}
		c.remaining = n
		c.trailers = n == 0
	}
	return nil
}

// readHead reads up to and including the blank line ending a head. It returns
// whatever it has along with the error when the head is incomplete or too large.
func readHead(br *bufio.Reader) ([]byte, error) {
	var head []byte
	for {
		line, err := br.ReadSlice('\n')
		head = append(head, line...)
		if len(head) > maxHeadBytes {
			return head, errHeadTooLarge
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return head, err
		}
		if isBlank(line) && len(head) > len(line) {
			return head, nil
		}
		// Tolerate blank lines before the request line, as RFC 9112 advises.
		if isBlank(line) {
			head = head[:0]
		}
	}
}

func splitLines(head []byte) [][]byte {
	lines := bytes.SplitAfter(head, []byte("\n"))
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func isBlank(line []byte) bool {
	return len(bytes.TrimRight(line, "\r\n")) == 0
}

func fieldName(line []byte) string {
	name, _, _ := bytes.Cut(line, []byte(":"))
	return strings.ToLower(string(bytes.TrimSpace(name)))
}

func headHasField(head []byte, name string) bool {
	lines := splitLines(head)
	for _, line := range lines[1:] {
		if fieldName(line) == name {
			return true
		}
	}
	return false
}

// responseStatus returns a response head's status code, or 0 if it has none.
func responseStatus(head []byte) int {
	line, _, _ := bytes.Cut(head, []byte("\n"))
	fields := bytes.Fields(line)
	if len(fields) < 2 || !bytes.HasPrefix(fields[0], []byte("HTTP/")) {
		return 0
	}
	code, err := strconv.Atoi(string(fields[1]))
	if err != nil {
		return 0
	}
	return code
}

// proxyStatus builds an RFC 9209 Proxy-Status value, which marks a response as
// coming from this proxy so a tool cannot mistake it for the target's answer.
func proxyStatus(kind, details string) string {
	return fmt.Sprintf("proxyswitcher; error=%s; details=%q", kind, details)
}

func writeSynthetic(w io.Writer, status int, kind, details string) {
	body := details + "\n"
	_, _ = fmt.Fprintf(w,
		"HTTP/1.1 %d %s\r\nProxy-Status: %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), proxyStatus(kind, details), len(body), body)
}
