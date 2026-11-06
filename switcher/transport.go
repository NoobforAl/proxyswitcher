package switcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultMaxAttempts is how many times one request is tried in total.
const DefaultMaxAttempts = 5

// DefaultResponseHeaderTimeout bounds the wait for a response. Without it, a
// proxy that accepts a connection and then hangs would stall the request
// forever instead of triggering a switch.
const DefaultResponseHeaderTimeout = 30 * time.Second

// DefaultDialTimeout bounds establishing one connection or tunnel, handshake
// included.
const DefaultDialTimeout = 15 * time.Second

// defaultMaxIdleConnsPerProxy replaces net/http's default of 2, which forces
// constant reconnecting at scanning and scraping volumes.
const defaultMaxIdleConnsPerProxy = 32

// maxDrainBytes limits how much of a discarded response is read to make its
// connection reusable. Anything larger is cheaper to close.
const maxDrainBytes = 64 << 10

// maxCachedTransports bounds the per-proxy transport cache, which public lists
// could otherwise grow without limit as proxies come and go.
const maxCachedTransports = 1024

// DefaultRetryStatus lists the responses that make Transport switch proxies.
func DefaultRetryStatus() []int {
	return []int{
		http.StatusForbidden,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	}
}

// DefaultRetryMethods lists the methods that are repeated after the request may
// have reached the target. Repeating anything else could apply its effect twice.
func DefaultRetryMethods() []string {
	return []string{http.MethodGet, http.MethodHead, http.MethodOptions}
}

// TransportConfig configures a Transport.
type TransportConfig struct {
	// MaxAttempts is the total tries per request, including a direct first
	// attempt. Zero uses DefaultMaxAttempts.
	MaxAttempts int
	// RetryStatus lists the status codes that trigger a switch. Nil uses
	// DefaultRetryStatus. An empty list never switches on a status.
	RetryStatus []int
	// RetryMethods lists the methods sent again after the request may have
	// reached the target. Nil uses DefaultRetryMethods. A failure that proves
	// the target saw nothing is retried for every method.
	RetryMethods []string
	// DirectFirst sends the first attempt without a proxy. Public proxy IPs are
	// widely blocklisted, so this suits traffic that only needs a proxy when
	// the real IP gets blocked. It exposes the real IP to the target.
	DirectFirst bool
	// FallbackDirect goes direct when no proxy is available instead of failing
	// with ErrNoProxy. It exposes the real IP to the target.
	FallbackDirect bool
	// StickyHosts keeps using the proxy that last worked for a site until it
	// fails, so logins and sessions keep the same exit IP.
	StickyHosts bool
	// StickyTTL is how long an unused pin lasts. Zero uses DefaultStickyTTL.
	StickyTTL time.Duration
	// TargetBackoff is how long a site that failed through several proxies gets
	// one attempt per request. Zero uses DefaultTargetBackoff; negative disables.
	TargetBackoff time.Duration
	// RequestTimeout limits the time spent across all attempts until a response
	// arrives. It does not limit reading the response body. Zero means no limit.
	RequestTimeout time.Duration
	// DialTimeout bounds establishing one connection or tunnel. Zero uses
	// DefaultDialTimeout.
	DialTimeout time.Duration
	// Base builds each underlying transport. Nil uses a clone of
	// http.DefaultTransport with DefaultResponseHeaderTimeout. Its Proxy field
	// is always overwritten.
	Base *http.Transport
	// Logger receives switch events. Nil uses slog.Default.
	Logger *slog.Logger
}

// Transport is an http.RoundTripper that tries a request through the pool's
// best proxy and switches to another on a network error or a retryable status.
// Each proxy gets its own http.Transport, so concurrent requests can never use
// each other's proxy. It is safe for concurrent use.
type Transport struct {
	pool         *Pool
	cfg          TransportConfig
	retry        map[int]bool
	retryMethods map[string]bool
	base         *http.Transport
	logger       *slog.Logger

	mu         sync.Mutex
	transports map[string]*http.Transport
	direct     *http.Transport
	pins       map[string]sitePin
	backoffs   map[string]time.Time
}

// NewTransport builds a Transport drawing from pool.
func NewTransport(pool *Pool, cfg TransportConfig) *Transport {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultMaxAttempts
	}
	if cfg.RetryStatus == nil {
		cfg.RetryStatus = DefaultRetryStatus()
	}
	if cfg.RetryMethods == nil {
		cfg.RetryMethods = DefaultRetryMethods()
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.StickyTTL <= 0 {
		cfg.StickyTTL = DefaultStickyTTL
	}
	if cfg.TargetBackoff == 0 {
		cfg.TargetBackoff = DefaultTargetBackoff
	}
	base := cfg.Base
	if base == nil {
		if std, ok := http.DefaultTransport.(*http.Transport); ok {
			base = std.Clone()
		} else {
			base = &http.Transport{}
		}
		base.ResponseHeaderTimeout = DefaultResponseHeaderTimeout
		base.MaxIdleConnsPerHost = defaultMaxIdleConnsPerProxy
	}
	retry := make(map[int]bool, len(cfg.RetryStatus))
	for _, code := range cfg.RetryStatus {
		retry[code] = true
	}
	retryMethods := make(map[string]bool, len(cfg.RetryMethods))
	for _, method := range cfg.RetryMethods {
		retryMethods[strings.ToUpper(method)] = true
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	direct := base.Clone()
	direct.Proxy = nil
	return &Transport{
		pool:         pool,
		cfg:          cfg,
		retry:        retry,
		retryMethods: retryMethods,
		base:         base,
		logger:       logger,
		transports:   make(map[string]*http.Transport),
		direct:       direct,
		pins:         make(map[string]sitePin),
		backoffs:     make(map[string]time.Time),
	}
}

func (t *Transport) transportFor(proxy *url.URL) *http.Transport {
	if proxy == nil {
		return t.direct
	}
	key := proxy.String()
	t.mu.Lock()
	defer t.mu.Unlock()
	tr, ok := t.transports[key]
	if !ok {
		if len(t.transports) >= maxCachedTransports {
			// In-flight requests keep working on the dropped transports; their
			// connections expire through IdleConnTimeout once they finish.
			for _, old := range t.transports {
				old.CloseIdleConnections()
			}
			clear(t.transports)
		}
		tr = t.base.Clone()
		tr.Proxy = http.ProxyURL(proxy)
		t.transports[key] = tr
	}
	return tr
}

// CloseIdleConnections closes idle connections on every underlying transport.
// http.Client.CloseIdleConnections calls it.
func (t *Transport) CloseIdleConnections() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.direct.CloseIdleConnections()
	for _, tr := range t.transports {
		tr.CloseIdleConnections()
	}
}

// RoundTrip implements http.RoundTripper. When attempts run out it returns the
// last response if there was one, otherwise the last error, so callers see the
// real upstream status.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// A body that cannot be rewound can only be sent once.
	maxAttempts := t.cfg.MaxAttempts
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		maxAttempts = 1
	}
	ctx, release := t.requestContext(req.Context())
	mayRepeat := t.retryMethods[strings.ToUpper(req.Method)]
	attempts := t.Begin(HostKey(req.URL.Host), maxAttempts)

	var lastResp *http.Response
	var lastErr error
loop:
	for {
		proxy, err := attempts.Next()
		if err != nil {
			// Out of proxies partway through: what we already have beats
			// ErrNoProxy, because it reflects a real upstream answer.
			if lastResp != nil || lastErr != nil {
				break
			}
			closeRequestBody(req)
			release(false)
			return nil, err
		}
		if lastResp != nil {
			discard(lastResp)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			closeRequestBody(req)
			release(false)
			return nil, ctxErr
		}

		out, err := attemptRequest(ctx, req, attempts.Number())
		if err != nil {
			release(false)
			return nil, err
		}

		resp, err := t.transportFor(proxy).RoundTrip(out)
		lastResp, lastErr = resp, redactErr(err)

		switch {
		case err != nil && ctx.Err() != nil:
			// The caller or the time limit ended this; that says nothing about
			// the proxy, so nothing is recorded.
			release(false)
			return nil, redactErr(err)
		case err != nil && isProxyFault(err):
			attempts.ProxyFault(proxy)
		case err != nil:
			attempts.Ambiguous(proxy)
			if !mayRepeat || !attempts.RetryAfterAmbiguous() {
				break loop
			}
		case resp.StatusCode == http.StatusProxyAuthRequired:
			attempts.ProxyFault(proxy)
		case t.retry[resp.StatusCode] && mayRepeat:
			attempts.Ambiguous(proxy)
			if !attempts.RetryAfterAmbiguous() {
				break loop
			}
		case t.retry[resp.StatusCode]:
			// Unsafe to repeat. The answer may be the site's, so it neither
			// helps nor hurts the proxy.
			attempts.Finish()
			return release2(resp, release), nil
		default:
			// Includes target errors like 404: the proxy did its job.
			attempts.Success(proxy)
			return release2(resp, release), nil
		}
		t.logger.Info("switching proxy after failure",
			"failed_proxy", redactOrDirect(proxy),
			"attempt", attempts.Number(),
			"status", statusOf(resp),
			"error", errText(err))
	}
	attempts.Finish()
	if lastResp != nil {
		return release2(lastResp, release), nil
	}
	release(false)
	return nil, lastErr
}

// requestContext applies RequestTimeout. The returned function stops the timer,
// and cancels the context unless the caller still needs it for a response body.
func (t *Transport) requestContext(parent context.Context) (context.Context, func(keep bool)) {
	if t.cfg.RequestTimeout <= 0 {
		return parent, func(bool) {}
	}
	ctx, cancel := context.WithCancel(parent)
	timer := time.AfterFunc(t.cfg.RequestTimeout, cancel)
	return ctx, func(keep bool) {
		timer.Stop()
		if !keep {
			cancel()
		}
	}
}

// release2 stops the time limit and ties the context to the response body, so
// slow body downloads are not cut off and the context is still freed.
func release2(resp *http.Response, release func(keep bool)) *http.Response {
	release(true)
	resp.Body = &releaseOnClose{ReadCloser: resp.Body, release: func() { release(false) }}
	return resp
}

type releaseOnClose struct {
	io.ReadCloser
	release func()
}

func (b *releaseOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.release()
	return err
}

// isProxyFault reports whether err proves the proxy failed before the target
// could have seen anything.
func isProxyFault(err error) bool {
	if IsProxyFault(err) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "proxyconnect" {
		return true
	}
	// net/http turns a refused CONNECT into an error holding the status text.
	return strings.Contains(err.Error(), http.StatusText(http.StatusProxyAuthRequired))
}

// attemptRequest prepares req for one attempt. RoundTrippers must not modify
// the caller's request, and each retry needs a fresh body.
func attemptRequest(ctx context.Context, req *http.Request, attempt int) (*http.Request, error) {
	out := req.Clone(ctx)
	if attempt > 1 && req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("proxyswitcher: rewinding request body: %w", err)
		}
		out.Body = body
	}
	return out, nil
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

func discard(resp *http.Response) {
	_, _ = io.CopyN(io.Discard, resp.Body, maxDrainBytes)
	_ = resp.Body.Close()
}

func redactOrDirect(u *url.URL) string {
	if u == nil {
		return "direct"
	}
	return RedactURL(u)
}

func statusOf(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return RedactText(err.Error())
}
