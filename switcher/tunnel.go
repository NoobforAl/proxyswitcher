package switcher

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// proxyFaultError marks a failure that can only be the proxy's: the target
// cannot have seen anything.
type proxyFaultError struct{ err error }

func (e *proxyFaultError) Error() string { return e.err.Error() }
func (e *proxyFaultError) Unwrap() error { return e.err }

// IsProxyFault reports whether err came from a proxy being unreachable or
// rejecting our credentials, as opposed to anything involving the target.
func IsProxyFault(err error) bool {
	var fault *proxyFaultError
	return errors.As(err, &fault)
}

// DialTunnel opens a raw connection to addr ("host:port") through the pool,
// switching to another proxy when one cannot be reached or refuses the tunnel.
// Nothing has been sent to the target at that point, so switching is always
// safe.
//
// Once the tunnel is up the bytes are opaque, so a target's 403 or 429 inside
// TLS cannot be seen here and does not trigger a switch. Use RoundTrip when
// switching on status codes matters.
func (t *Transport) DialTunnel(ctx context.Context, addr string) (net.Conn, error) {
	attempts := t.Begin(HostKey(addr), 0)
	var lastErr error
	for {
		via, err := attempts.Next()
		if err != nil {
			attempts.Finish()
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}
		conn, err := t.DialThrough(ctx, via, addr)
		if err == nil {
			attempts.Success(via)
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, redactErr(err)
		}
		lastErr = redactErr(err)
		t.logger.Info("switching proxy after tunnel failure",
			"failed_proxy", redactOrDirect(via), "attempt", attempts.Number(), "error", errText(err))
		if IsProxyFault(err) {
			attempts.ProxyFault(via)
			continue
		}
		attempts.Ambiguous(via)
		if !attempts.RetryAfterAmbiguous() {
			attempts.Finish()
			return nil, lastErr
		}
	}
}

// DialThrough opens one connection to addr through via, or directly when via is
// nil, limited by DialTimeout.
func (t *Transport) DialThrough(ctx context.Context, via *url.URL, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, t.cfg.DialTimeout)
	defer cancel()
	var dialer net.Dialer
	if via == nil {
		return dialer.DialContext(ctx, "tcp", addr)
	}
	switch via.Scheme {
	case "socks5":
		return dialSOCKS5(ctx, via, addr, &dialer)
	case "http", "https":
		return dialHTTPConnect(ctx, via, addr)
	default:
		return nil, &proxyFaultError{fmt.Errorf("unsupported proxy scheme %q", via.Scheme)}
	}
}

// DialProxy opens one connection to the HTTP or HTTPS proxy itself, limited by
// DialTimeout. Any failure is a proxy fault.
func (t *Transport) DialProxy(ctx context.Context, via *url.URL) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, t.cfg.DialTimeout)
	defer cancel()
	return dialProxy(ctx, via)
}

// ProxyAuthorization returns the Proxy-Authorization value for via's
// credentials, or "" when it has none.
func ProxyAuthorization(via *url.URL) string {
	if via == nil || via.User == nil {
		return ""
	}
	password, _ := via.User.Password()
	creds := via.User.Username() + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

func dialProxy(ctx context.Context, via *url.URL) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", via.Host)
	if err != nil {
		return nil, &proxyFaultError{err}
	}
	if via.Scheme != "https" {
		return conn, nil
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: via.Hostname(), MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, &proxyFaultError{err}
	}
	return tlsConn, nil
}

func dialSOCKS5(ctx context.Context, via *url.URL, addr string, dialer *net.Dialer) (net.Conn, error) {
	// Reach the proxy first, so an unreachable proxy is told apart from a target
	// the proxy cannot reach. The SOCKS dialer then uses this connection.
	first, err := dialer.DialContext(ctx, "tcp", via.Host)
	if err != nil {
		return nil, &proxyFaultError{err}
	}
	var auth *proxy.Auth
	if via.User != nil {
		password, _ := via.User.Password()
		auth = &proxy.Auth{User: via.User.Username(), Password: password}
	}
	d, err := proxy.SOCKS5("tcp", via.Host, auth, onceDialer{conn: first})
	if err != nil {
		_ = first.Close()
		return nil, &proxyFaultError{err}
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		_ = first.Close()
		return nil, &proxyFaultError{errors.New("socks5 dialer does not support contexts")}
	}
	conn, err := cd.DialContext(ctx, "tcp", addr)
	if err != nil {
		_ = first.Close()
		return nil, err
	}
	return conn, nil
}

// onceDialer hands the SOCKS dialer a connection that is already open.
type onceDialer struct{ conn net.Conn }

func (d onceDialer) Dial(string, string) (net.Conn, error) { return d.conn, nil }

func dialHTTPConnect(ctx context.Context, via *url.URL, addr string) (net.Conn, error) {
	c, err := dialProxy(ctx, via)
	if err != nil {
		return nil, err
	}
	// The dialer only honors ctx while connecting, so apply it to the CONNECT
	// exchange by hand.
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		// An empty value tells Request.Write not to add a Go User-Agent.
		Header: http.Header{"User-Agent": {""}},
	}
	if auth := ProxyAuthorization(via); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	if writeErr := req.Write(c); writeErr != nil {
		_ = c.Close()
		return nil, writeErr
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = c.Close()
		refused := fmt.Errorf("proxy refused CONNECT with status %d", resp.StatusCode)
		if resp.StatusCode == http.StatusProxyAuthRequired {
			return nil, &proxyFaultError{refused}
		}
		return nil, refused
	}
	// Disarm the cancel hook before clearing the deadline, or a late firing
	// could kill the live tunnel.
	if !stop() {
		_ = c.Close()
		return nil, ctx.Err()
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		_ = c.Close()
		return nil, err
	}
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: c, r: br}, nil
	}
	return c, nil
}

// bufferedConn serves bytes the proxy sent right after its CONNECT response,
// which the response reader may already have consumed.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// CloseWrite forwards half-close, which embedding the interface would hide.
func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}
