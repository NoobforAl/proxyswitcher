package switcher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// targetProxy answers according to the requested site, like a proxy that works
// but is blocked by some sites or sits in front of a dead one.
func targetProxy(t *testing.T, status func(host string) int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(status(r.Host))
	}))
	t.Cleanup(srv.Close)
	return srv, hits
}

func always(status int) func(string) int { return func(string) int { return status } }

func getStatus(t *testing.T, rt http.RoundTripper, target string) int {
	t.Helper()
	return get(t, rt, target).StatusCode
}

// A dead site must not cost working proxies their score or their place in the pool.
func TestSite_DeadSitePenalizesNoProxy(t *testing.T) {
	var urls []string
	for range 5 {
		srv, _ := targetProxy(t, always(http.StatusBadGateway))
		urls = append(urls, srv.URL)
	}
	p := newTestPool(t, PoolConfig{}, urls...)
	rt := NewTransport(p, quiet(TransportConfig{TargetBackoff: -1}))

	for range 120 {
		if got := getStatus(t, rt, "http://dead.test/"); got != http.StatusBadGateway {
			t.Fatalf("status %d, want the site's own 502", got)
		}
	}
	entries := p.Snapshot()
	if len(entries) != 5 {
		t.Fatalf("%d proxies left, want 5: none should be evicted", len(entries))
	}
	for _, e := range entries {
		if e.Failures != 0 || e.Score != publicStartScore {
			t.Errorf("%s: failures %d, score %d", e.URL, e.Failures, e.Score)
		}
	}
	if p.UsableCount() != 5 {
		t.Fatalf("usable = %d", p.UsableCount())
	}
}

// A short outage of every proxy must not leave the pool refusing requests for a
// whole cooldown after they return.
func TestCooling_RecoversAsSoonAsAProxyReturns(t *testing.T) {
	good, _ := targetProxy(t, always(http.StatusOK))
	p := newTestPool(t, PoolConfig{Cooldown: time.Hour}, good.URL)
	u := mustURL(t, good.URL)
	p.Report(u, false)
	p.Report(u, false)
	if p.Next() != nil {
		t.Fatal("expected the proxy to be on cooldown")
	}

	if got := getStatus(t, NewTransport(p, quiet(TransportConfig{})), "http://site.test/"); got != http.StatusOK {
		t.Fatalf("status %d", got)
	}
	if p.Next() == nil {
		t.Fatal("a successful retry should end the cooldown")
	}
}

func TestCooling_RetriesAreRateLimited(t *testing.T) {
	p := newTestPool(t, PoolConfig{CoolingRetryInterval: time.Minute}, "http://a:1")
	now := time.Now()
	p.now = func() time.Time { return now }
	u := mustURL(t, "http://a:1")
	p.Report(u, false)
	p.Report(u, false)
	if p.NextCooling("", nil) == nil {
		t.Fatal("the first retry should be allowed")
	}
	if p.NextCooling("", nil) != nil {
		t.Fatal("a second retry within the interval should not be")
	}
	now = now.Add(2 * time.Minute)
	if p.NextCooling("", nil) == nil {
		t.Fatal("a retry should be allowed after the interval")
	}
}

// Failed retries during a long outage must not evict anything, or the pool would
// be empty until a restart once the proxies came back.
func TestCooling_LongOutageEvictsNothing(t *testing.T) {
	p := newTestPool(t, PoolConfig{CoolingRetryInterval: time.Minute}, "http://a:1")
	now := time.Now()
	p.now = func() time.Time { return now }
	u := mustURL(t, "http://a:1")
	p.Report(u, false)
	p.Report(u, false)
	for range 500 {
		now = now.Add(2 * time.Minute)
		if retry := p.NextCooling("", nil); retry != nil {
			p.Report(retry, false)
		}
	}
	entries := p.Snapshot()
	if len(entries) != 1 || entries[0].Failures != 2 {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestSite_BackoffLimitsAttemptsAfterSiteFails(t *testing.T) {
	a, aHits := targetProxy(t, always(http.StatusBadGateway))
	b, bHits := targetProxy(t, always(http.StatusBadGateway))
	p := newTestPool(t, PoolConfig{}, a.URL, b.URL)
	rt := NewTransport(p, quiet(TransportConfig{TargetBackoff: time.Hour}))

	getStatus(t, rt, "http://dead.test/")
	if total := aHits.Load() + bHits.Load(); total != 2 {
		t.Fatalf("first request made %d attempts, want 2", total)
	}
	for range 5 {
		getStatus(t, rt, "http://dead.test/")
	}
	if total := aHits.Load() + bHits.Load(); total != 7 {
		t.Fatalf("total attempts %d, want one per request during backoff", total)
	}
	// Another site is unaffected.
	aHits.Store(0)
	bHits.Store(0)
	getStatus(t, rt, "http://other.test/")
	if total := aHits.Load() + bHits.Load(); total != 2 {
		t.Fatalf("other site made %d attempts, want 2", total)
	}
}

func TestSite_RecoveredSiteLeavesBackoff(t *testing.T) {
	var healthy atomic.Bool
	flaky := func(string) int {
		if healthy.Load() {
			return http.StatusOK
		}
		return http.StatusBadGateway
	}
	a, _ := targetProxy(t, flaky)
	b, _ := targetProxy(t, flaky)
	p := newTestPool(t, PoolConfig{}, a.URL, b.URL)
	rt := NewTransport(p, quiet(TransportConfig{TargetBackoff: time.Hour}))

	getStatus(t, rt, "http://site.test/")
	if !rt.inBackoff("site.test") {
		t.Fatal("expected backoff")
	}
	healthy.Store(true)
	if got := getStatus(t, rt, "http://site.test/"); got != http.StatusOK {
		t.Fatalf("status %d", got)
	}
	if rt.inBackoff("site.test") {
		t.Fatal("a success should end the backoff")
	}
}

// A proxy blocked by one site must stay usable everywhere else.
func TestSite_BlockedProxyStaysUsableElsewhere(t *testing.T) {
	blockedOnOne, hits := targetProxy(t, func(host string) int {
		if host == "strict.test" {
			return http.StatusForbidden
		}
		return http.StatusOK
	})
	other, _ := targetProxy(t, always(http.StatusOK))
	p := newTestPool(t, PoolConfig{}, blockedOnOne.URL, other.URL)
	preferring(t, p, blockedOnOne.URL)
	rt := NewTransport(p, quiet(TransportConfig{}))

	if got := getStatus(t, rt, "http://strict.test/"); got != http.StatusOK {
		t.Fatalf("status %d, want the other proxy's success", got)
	}
	e := entryFor(t, p, blockedOnOne.URL)
	if e.Failures != 0 || e.BlockedSites != 1 {
		t.Fatalf("failures %d, blocked sites %d", e.Failures, e.BlockedSites)
	}

	// It is skipped for that site from now on.
	hits.Store(0)
	getStatus(t, rt, "http://strict.test/")
	if hits.Load() != 0 {
		t.Fatal("a proxy blocked by this site was tried again")
	}
	// But still available for others.
	u := mustURL(t, blockedOnOne.URL)
	if p.Usable(u, "strict.test") || !p.Usable(u, "relaxed.test") {
		t.Fatal("the block must apply to that site only")
	}
}

func TestSite_SiteBlockExpires(t *testing.T) {
	p := newTestPool(t, PoolConfig{SiteCooldown: time.Minute}, "http://a:1")
	now := time.Now()
	p.now = func() time.Time { return now }
	u := mustURL(t, "http://a:1")
	p.ReportBlocked(u, "strict.test")
	if p.NextFor("strict.test", nil) != nil {
		t.Fatal("expected the block to apply")
	}
	if p.NextFor("other.test", nil) == nil {
		t.Fatal("the block must only apply to that site")
	}
	now = now.Add(2 * time.Minute)
	if p.NextFor("strict.test", nil) == nil {
		t.Fatal("expected the block to expire")
	}
}

// A proxy that fails on every site is broken, even though each failure alone
// looks like a site's decision. It must still leave the pool eventually.
func TestSite_ProxyFailingOnManySitesIsEvicted(t *testing.T) {
	p := newTestPool(t, PoolConfig{}, "http://a:1")
	u := mustURL(t, "http://a:1")
	for i := range DefaultEvictAfterFailures + DefaultGlobalFailureAfterSites + 1 {
		p.ReportBlocked(u, fmt.Sprintf("site-%d.test", i))
	}
	if len(p.Snapshot()) != 0 {
		t.Fatalf("still in the pool: %+v", p.Snapshot())
	}
}

func TestSite_FailingEverywhereThroughAllProxiesIsEvicted(t *testing.T) {
	p := newTestPool(t, PoolConfig{}, "http://a:1")
	u := mustURL(t, "http://a:1")
	for i := range DefaultEvictAfterFailures + DefaultGlobalFailureAfterSites + 1 {
		p.ReportInconclusive(u, fmt.Sprintf("site-%d.test", i))
	}
	if len(p.Snapshot()) != 0 {
		t.Fatal("a proxy that fails on every site must not stay forever")
	}
}

func TestSite_FewSitesDoNotCountGlobally(t *testing.T) {
	p := newTestPool(t, PoolConfig{}, "http://a:1")
	u := mustURL(t, "http://a:1")
	for i := range DefaultGlobalFailureAfterSites - 1 {
		p.ReportBlocked(u, fmt.Sprintf("site-%d.test", i))
	}
	// Repeats of the same site never count again.
	for range 50 {
		p.ReportBlocked(u, "site-0.test")
	}
	if e := entryFor(t, p, "http://a:1"); e.Failures != 0 {
		t.Fatalf("failures = %d", e.Failures)
	}
}

func TestSite_ClosedProxyIsPenalizedImmediately(t *testing.T) {
	dead := closedPortURL(t)
	good, _ := targetProxy(t, always(http.StatusOK))
	p := newTestPool(t, PoolConfig{}, dead, good.URL)
	preferring(t, p, dead)
	getStatus(t, NewTransport(p, quiet(TransportConfig{})), "http://site.test/")
	if e := entryFor(t, p, dead); e.Failures != 1 {
		t.Fatalf("failures = %d, want 1", e.Failures)
	}
}

func TestTransport_UnsafeMethodIsNotRepeatedAfterDelivery(t *testing.T) {
	first, _ := targetProxy(t, always(http.StatusInternalServerError))
	second, secondHits := targetProxy(t, always(http.StatusOK))
	p := newTestPool(t, PoolConfig{}, first.URL, second.URL)
	preferring(t, p, first.URL)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://site.test/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := NewTransport(p, quiet(TransportConfig{})).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError || secondHits.Load() != 0 {
		t.Fatalf("status %d, second hits %d", resp.StatusCode, secondHits.Load())
	}
	if e := entryFor(t, p, first.URL); e.Failures != 0 {
		t.Fatalf("failures = %d", e.Failures)
	}
}

func TestTransport_UnsafeMethodSwitchesWhenTargetSawNothing(t *testing.T) {
	dead := closedPortURL(t)
	good, goodHits := targetProxy(t, always(http.StatusOK))
	p := newTestPool(t, PoolConfig{}, dead, good.URL)
	preferring(t, p, dead)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://site.test/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := NewTransport(p, quiet(TransportConfig{})).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || goodHits.Load() != 1 {
		t.Fatalf("status %d, good hits %d", resp.StatusCode, goodHits.Load())
	}
}

func TestTransport_ProxyAuthRejectionSwitches(t *testing.T) {
	rejecting, _ := targetProxy(t, always(http.StatusProxyAuthRequired))
	good, _ := targetProxy(t, always(http.StatusOK))
	p := newTestPool(t, PoolConfig{}, rejecting.URL, good.URL)
	preferring(t, p, rejecting.URL)
	if got := getStatus(t, NewTransport(p, quiet(TransportConfig{})), "http://site.test/"); got != http.StatusOK {
		t.Fatalf("status %d", got)
	}
	if e := entryFor(t, p, rejecting.URL); e.Failures != 1 {
		t.Fatalf("failures = %d, want an immediate penalty", e.Failures)
	}
}

func TestTransport_StickyPinsUntilFailure(t *testing.T) {
	var firstBroken atomic.Bool
	first, firstHits := targetProxy(t, func(string) int {
		if firstBroken.Load() {
			return http.StatusForbidden
		}
		return http.StatusOK
	})
	second, secondHits := targetProxy(t, always(http.StatusOK))
	p := newTestPool(t, PoolConfig{}, first.URL, second.URL)
	preferring(t, p, first.URL)
	rt := NewTransport(p, quiet(TransportConfig{StickyHosts: true}))

	for range 5 {
		getStatus(t, rt, "http://site.test/")
	}
	if firstHits.Load() != 5 || secondHits.Load() != 0 {
		t.Fatalf("hits %d and %d, want all on the first", firstHits.Load(), secondHits.Load())
	}
	firstBroken.Store(true)
	for range 5 {
		getStatus(t, rt, "http://site.test/")
	}
	if firstHits.Load() != 6 || secondHits.Load() != 5 {
		t.Fatalf("hits %d and %d, want a move to the second after one failure", firstHits.Load(), secondHits.Load())
	}
}

func TestTransport_WithoutStickyRotates(t *testing.T) {
	a, aHits := targetProxy(t, always(http.StatusOK))
	b, bHits := targetProxy(t, always(http.StatusOK))
	p := newTestPool(t, PoolConfig{MaxScore: 1}, a.URL, b.URL)
	rt := NewTransport(p, quiet(TransportConfig{}))
	for range 10 {
		getStatus(t, rt, "http://site.test/")
	}
	if aHits.Load() == 0 || bHits.Load() == 0 {
		t.Fatalf("hits %d and %d, want rotation", aHits.Load(), bHits.Load())
	}
}

func TestTransport_RequestTimeoutLimitsAttemptsButNotBodies(t *testing.T) {
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(hung.Close)
	t.Cleanup(func() { close(release) })
	p := newTestPool(t, PoolConfig{}, hung.URL)
	start := time.Now()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://site.test/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	rt := NewTransport(p, quiet(TransportConfig{RequestTimeout: 100 * time.Millisecond}))
	if timeoutErr := roundTripErr(rt, req); timeoutErr == nil {
		t.Fatal("expected a timeout")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %v", elapsed)
	}

	// A slow body is not cut off once the response has started.
	slowBody := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("a"))
		w.(http.Flusher).Flush()
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("b"))
	}))
	t.Cleanup(slowBody.Close)
	p2 := newTestPool(t, PoolConfig{}, slowBody.URL)
	req2, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://site.test/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := NewTransport(p2, quiet(TransportConfig{RequestTimeout: 100 * time.Millisecond})).RoundTrip(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "ab" {
		t.Fatalf("body %q, %v", body, err)
	}
}

func TestPool_ExcludeHostsRefusesSelf(t *testing.T) {
	p := NewPool(PoolConfig{Logger: discardLogger(), ExcludeHosts: []string{"127.0.0.1:8899"}},
		StaticSource{Proxies: []string{"http://127.0.0.1:8899", "http://a:1"}})
	p.Refresh(context.Background())
	if entries := p.Snapshot(); len(entries) != 1 || entries[0].URL.Host != "a:1" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestSourceClient_IgnoresProxyEnvironment(t *testing.T) {
	transport, ok := newSourceClient().Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatal("source fetches must not follow HTTP_PROXY, or a shell using this proxy makes it call itself")
	}
}

func TestPool_Check(t *testing.T) {
	alive := fakeForwardProxy(t, http.StatusOK)
	dead := closedPortURL(t)
	p := newTestPool(t, PoolConfig{HealthCheck: HealthCheckConfig{
		SkipHTTPS: true, Timeout: 2 * time.Second, TargetURL: "http://target.test/",
	}}, alive.URL, dead)
	calls := 0
	results := p.Check(context.Background(), 4, func(ProbeResult) { calls++ })
	if len(results) != 2 || calls != 2 {
		t.Fatalf("results %d, calls %d", len(results), calls)
	}
	if len(p.Snapshot()) != 2 {
		t.Fatal("Check must not change the pool")
	}
}

func TestPool_CheckStopsWhenCanceled(t *testing.T) {
	p := newTestPool(t, PoolConfig{HealthCheck: HealthCheckConfig{SkipHTTPS: true}}, closedPortURL(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := p.Check(ctx, 2, nil); len(got) != 0 {
		t.Fatalf("results = %d", len(got))
	}
}

func TestProbeBody_ExpectBodyCatchesInjectedPages(t *testing.T) {
	injecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("buy our ads"))
	}))
	t.Cleanup(injecting.Close)
	u := mustURL(t, injecting.URL)
	if got := ProbeBody(context.Background(), u, "http://target.test/", "Example Domain", 2*time.Second); got.Alive {
		t.Fatal("an injected page should fail the probe")
	}
	if got := ProbeBody(context.Background(), u, "http://target.test/", "ads", 2*time.Second); !got.Alive {
		t.Fatal("the expected text should pass")
	}
}

func TestProbeHTTPS_RejectsInterceptedTLS(t *testing.T) {
	// A CONNECT proxy reaching a server whose certificate is not trusted, as
	// happens when a proxy intercepts TLS.
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(untrusted.Close)
	working, _ := fakeConnectProxy(t, http.StatusOK, nil)
	if got := Probe(context.Background(), mustURL(t, working), untrusted.URL, 3*time.Second); got.Alive {
		t.Fatal("an untrusted certificate must fail the probe")
	}
}

func BenchmarkPool_Next(b *testing.B) {
	proxies := make([]string, 5000)
	for i := range proxies {
		proxies[i] = fmt.Sprintf("http://10.0.%d.%d:8080", i/250, i%250+1)
	}
	p := NewPool(PoolConfig{Logger: discardLogger()}, StaticSource{Proxies: proxies})
	p.Refresh(context.Background())
	for b.Loop() {
		if p.NextFor("site.test", nil) == nil {
			b.Fatal("no proxy")
		}
	}
}
