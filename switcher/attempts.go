package switcher

import (
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultTargetBackoff is how long a site that failed through several
	// proxies gets one attempt per request, so a dead site does not multiply
	// traffic.
	DefaultTargetBackoff = 30 * time.Second
	// DefaultStickyTTL is how long an unused per-site proxy pin lasts.
	DefaultStickyTTL = 30 * time.Minute

	// maxTrackedHosts bounds the pin and backoff maps.
	maxTrackedHosts = 16384

	// directKey marks the direct route in a request's tried set. It cannot
	// collide with a proxy key, because those are always full URLs.
	directKey = "direct"
)

// Attempts tracks one request's journey through the pool, and decides what each
// outcome means once the whole request is over. A failure such as a 500 can mean
// a blocked proxy or a broken site. Only the end result separates them: if
// another proxy then gets through, the earlier proxies were blocked by that site.
// If every proxy fails, the site is the likely problem and no proxy is penalized.
//
// Call Next for each try, one outcome method per try, and Finish if the request
// ends without a Success. It is not safe for concurrent use.
type Attempts struct {
	t       *Transport
	host    string
	max     int
	count   int
	tried   map[string]bool
	held    []*url.URL
	backoff bool
}

// Begin starts tracking a request to host. Use HostKey to derive host.
func (t *Transport) Begin(host string, maxAttempts int) *Attempts {
	if maxAttempts <= 0 || maxAttempts > t.cfg.MaxAttempts {
		maxAttempts = t.cfg.MaxAttempts
	}
	return &Attempts{
		t:       t,
		host:    host,
		max:     maxAttempts,
		tried:   make(map[string]bool, maxAttempts),
		backoff: t.inBackoff(host),
	}
}

// HostKey normalizes a host or host:port into the key used for per-site state.
func HostKey(hostport string) string {
	host := hostport
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.HasSuffix(host, "]") {
		host = host[:i]
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

// Next returns the route for the next try: a proxy, or nil to go direct. It
// returns ErrNoProxy when no route remains.
func (a *Attempts) Next() (*url.URL, error) {
	if a.count >= a.max {
		return nil, ErrNoProxy
	}
	a.count++
	return a.t.pick(a.count, a.host, a.tried)
}

// Number returns how many tries have started.
func (a *Attempts) Number() int { return a.count }

// RetryAfterAmbiguous reports whether another try is worthwhile after an
// ambiguous failure. It is false while the site is in backoff.
func (a *Attempts) RetryAfterAmbiguous() bool { return !a.backoff }

// Success records that via worked. Proxies that failed earlier in this request
// are recorded as blocked by this site.
func (a *Attempts) Success(via *url.URL) {
	for _, held := range a.held {
		a.t.pool.ReportBlocked(held, a.host)
	}
	a.held = nil
	a.t.clearBackoff(a.host)
	if via != nil {
		a.t.pool.Report(via, true)
		a.t.pin(a.host, via)
	}
}

// ProxyFault records a failure that can only be the proxy's: it could not be
// reached, or it rejected our credentials. The target saw nothing, so any request
// may safely be sent again.
func (a *Attempts) ProxyFault(via *url.URL) {
	a.markTried(via)
	if via != nil {
		a.t.unpin(a.host, via)
		a.t.pool.Report(via, false)
	}
}

// Ambiguous records a failure that could be the proxy's or the site's. Its
// meaning is decided by what happens next.
func (a *Attempts) Ambiguous(via *url.URL) {
	a.markTried(via)
	if via != nil {
		a.t.unpin(a.host, via)
		a.held = append(a.held, via)
	}
}

// Finish ends a request that never succeeded. When several proxies failed the
// same way, the site goes into backoff.
func (a *Attempts) Finish() {
	for _, held := range a.held {
		a.t.pool.ReportInconclusive(held, a.host)
	}
	if len(a.held) >= 2 {
		a.t.startBackoff(a.host)
		a.t.logger.Warn("site failed through several proxies; limiting retries",
			"host", a.host, "proxies_tried", len(a.held), "backoff", a.t.cfg.TargetBackoff)
	}
	a.held = nil
}

func (a *Attempts) markTried(via *url.URL) {
	if via == nil {
		a.tried[directKey] = true
		return
	}
	a.tried[via.String()] = true
}

// pick chooses the route for a try. A nil proxy with a nil error means direct.
func (t *Transport) pick(attempt int, host string, tried map[string]bool) (*url.URL, error) {
	if attempt == 1 && t.cfg.DirectFirst {
		return nil, nil
	}
	if pinned := t.pinned(host); pinned != nil && !tried[pinned.String()] && t.pool.Usable(pinned, host) {
		return pinned, nil
	}
	if proxy := t.pool.NextFor(host, tried); proxy != nil {
		return proxy, nil
	}
	if proxy := t.pool.NextCooling(host, tried); proxy != nil {
		t.logger.Info("no proxy available; retrying one on cooldown", "proxy", RedactURL(proxy))
		return proxy, nil
	}
	if t.cfg.FallbackDirect && !tried[directKey] {
		tried[directKey] = true
		return nil, nil
	}
	return nil, ErrNoProxy
}

type sitePin struct {
	proxy *url.URL
	until time.Time
}

func (t *Transport) pinned(host string) *url.URL {
	if !t.cfg.StickyHosts {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	pin, ok := t.pins[host]
	if !ok || !pin.until.After(time.Now()) {
		return nil
	}
	return pin.proxy
}

// pin keeps an existing valid pin, so concurrent first requests that took
// different proxies cannot make a site's exit IP flip back and forth.
func (t *Transport) pin(host string, via *url.URL) {
	if !t.cfg.StickyHosts {
		return
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if pin, ok := t.pins[host]; ok && pin.until.After(now) && pin.proxy.String() != via.String() {
		return
	}
	if _, ok := t.pins[host]; !ok && len(t.pins) >= maxTrackedHosts {
		for key, pin := range t.pins {
			if !pin.until.After(now) {
				delete(t.pins, key)
			}
		}
		if len(t.pins) >= maxTrackedHosts {
			clear(t.pins)
		}
	}
	t.pins[host] = sitePin{proxy: via, until: now.Add(t.cfg.StickyTTL)}
}

func (t *Transport) unpin(host string, via *url.URL) {
	if !t.cfg.StickyHosts {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if pin, ok := t.pins[host]; ok && pin.proxy.String() == via.String() {
		delete(t.pins, host)
	}
}

func (t *Transport) inBackoff(host string) bool {
	if t.cfg.TargetBackoff <= 0 {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.backoffs[host].After(time.Now())
}

func (t *Transport) startBackoff(host string) {
	if t.cfg.TargetBackoff <= 0 {
		return
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.backoffs) >= maxTrackedHosts {
		for key, until := range t.backoffs {
			if !until.After(now) {
				delete(t.backoffs, key)
			}
		}
		if len(t.backoffs) >= maxTrackedHosts {
			clear(t.backoffs)
		}
	}
	t.backoffs[host] = now.Add(t.cfg.TargetBackoff)
}

func (t *Transport) clearBackoff(host string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.backoffs, host)
}
