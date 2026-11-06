package switcher

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultHealthCheckDelay paces the sweep so it never fires a burst.
	DefaultHealthCheckDelay = 500 * time.Millisecond
	// DefaultHealthCheckTimeout bounds a single probe.
	DefaultHealthCheckTimeout = 8 * time.Second
	// DefaultHealthCheckTargetURL is an IANA-reserved test domain, so no real
	// site absorbs the sweep's traffic.
	DefaultHealthCheckTargetURL = "http://example.com/"
	// DefaultHealthCheckHTTPSTargetURL proves a proxy can open CONNECT tunnels,
	// which is how scanners and browsers send all HTTPS traffic.
	DefaultHealthCheckHTTPSTargetURL = "https://example.com/"

	maxProbeBodyBytes = 64 << 10
)

// HealthCheckConfig controls proxy probing.
type HealthCheckConfig struct {
	Enabled bool
	Delay   time.Duration
	Timeout time.Duration
	// TargetURL is fetched through each proxy over plain HTTP.
	TargetURL string
	// HTTPSTargetURL is fetched through each proxy over a CONNECT tunnel, with
	// full certificate verification, so a proxy that intercepts TLS fails.
	HTTPSTargetURL string
	// SkipHTTPS disables the HTTPS probe.
	SkipHTTPS bool
	// ExpectBody, when set, must appear in each probe's response, so a proxy
	// that injects its own page fails. Without it, any status under 500 passes.
	ExpectBody string
}

func (c HealthCheckConfig) withDefaults() HealthCheckConfig {
	if c.Delay <= 0 {
		c.Delay = DefaultHealthCheckDelay
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultHealthCheckTimeout
	}
	if c.TargetURL == "" {
		c.TargetURL = DefaultHealthCheckTargetURL
	}
	if c.HTTPSTargetURL == "" {
		c.HTTPSTargetURL = DefaultHealthCheckHTTPSTargetURL
	}
	return c
}

// ProbeResult is the outcome of probing one proxy. Alive means every enabled
// probe passed.
type ProbeResult struct {
	URL          *url.URL
	Alive        bool
	HTTP         bool
	HTTPS        bool
	HTTPSChecked bool
	Latency      time.Duration
}

// Probe sends one GET through proxyURL to targetURL. Any response under 500
// counts as alive: many free proxies inject their own error pages, so this only
// screens out proxies that do not forward traffic at all. Use ProbeBody to catch
// those too.
func Probe(ctx context.Context, proxyURL *url.URL, targetURL string, timeout time.Duration) ProbeResult {
	return ProbeBody(ctx, proxyURL, targetURL, "", timeout)
}

// ProbeBody is Probe, additionally requiring expectBody in the response when it
// is not empty.
func ProbeBody(ctx context.Context, proxyURL *url.URL, targetURL, expectBody string, timeout time.Duration) ProbeResult {
	start := time.Now()
	result := ProbeResult{URL: proxyURL}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		return result
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	resp, err := transport.RoundTrip(req)
	result.Latency = time.Since(start)
	if err != nil {
		return result
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBodyBytes))
	if err != nil {
		return result
	}
	result.Alive = resp.StatusCode < http.StatusInternalServerError &&
		(expectBody == "" || strings.Contains(string(body), expectBody))
	return result
}

// probeEntry runs every enabled probe against one proxy.
func (p *Pool) probeEntry(ctx context.Context, u *url.URL) ProbeResult {
	hc := p.cfg.HealthCheck
	plain := ProbeBody(ctx, u, hc.TargetURL, hc.ExpectBody, hc.Timeout)
	result := ProbeResult{URL: u, HTTP: plain.Alive, Latency: plain.Latency}
	if hc.SkipHTTPS {
		result.Alive = result.HTTP
		return result
	}
	secure := ProbeBody(ctx, u, hc.HTTPSTargetURL, hc.ExpectBody, hc.Timeout)
	result.HTTPSChecked = true
	result.HTTPS = secure.Alive
	result.Alive = result.HTTP && result.HTTPS
	return result
}

// Sweep probes every entry once, one at a time and paced by HealthCheck.Delay,
// and returns the results in pool order. It does not change the pool. onResult
// may be nil.
func (p *Pool) Sweep(ctx context.Context, onResult func(ProbeResult)) []ProbeResult {
	entries := p.Snapshot()
	results := make([]ProbeResult, 0, len(entries))
	for i, e := range entries {
		if ctx.Err() != nil {
			break
		}
		r := p.probeEntry(ctx, e.URL)
		results = append(results, r)
		if onResult != nil {
			onResult(r)
		}
		if i < len(entries)-1 {
			select {
			case <-time.After(p.cfg.HealthCheck.Delay):
			case <-ctx.Done():
			}
		}
	}
	return results
}

// Check probes every entry with up to concurrency probes at once, calling
// onResult as each finishes, and returns the results in finishing order. It stops
// early when ctx is canceled and does not change the pool. onResult may be nil;
// calls to it are never concurrent.
func (p *Pool) Check(ctx context.Context, concurrency int, onResult func(ProbeResult)) []ProbeResult {
	if concurrency < 1 {
		concurrency = 1
	}
	entries := p.Snapshot()
	work := make(chan *url.URL)
	var mu sync.Mutex
	results := make([]ProbeResult, 0, len(entries))
	var wg sync.WaitGroup
	for range concurrency {
		wg.Go(func() {
			for u := range work {
				r := p.probeEntry(ctx, u)
				// A probe cut short by cancellation says nothing about the proxy.
				if ctx.Err() != nil {
					continue
				}
				mu.Lock()
				results = append(results, r)
				if onResult != nil {
					onResult(r)
				}
				mu.Unlock()
			}
		})
	}
feed:
	for _, e := range entries {
		select {
		case work <- e.URL:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	return results
}

// RunHealthCheck sweeps the pool and removes every proxy that fails its probe.
// It does nothing unless HealthCheck.Enabled is set. A large pool can take a
// while, so call it in a goroutine rather than blocking startup.
func (p *Pool) RunHealthCheck(ctx context.Context) {
	if !p.cfg.HealthCheck.Enabled {
		return
	}
	alive, dead := 0, 0
	p.Sweep(ctx, func(r ProbeResult) {
		// A probe cut short by shutdown says nothing about the proxy.
		if ctx.Err() != nil {
			return
		}
		if r.Alive {
			alive++
			return
		}
		dead++
		p.remove(r.URL)
	})
	p.logger.Info("health check complete", "alive", alive, "dead", dead)
}
