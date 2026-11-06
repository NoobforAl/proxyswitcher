// Package switcher routes HTTP traffic through a scored, self-healing
// pool of proxies and switches to another proxy automatically when one fails.
//
// Scoring: personal proxies start at score 3 and public proxies at 1. A
// success adds one (capped at PoolConfig.MaxScore) and a failure subtracts
// one. Once the score drops below PoolConfig.BlacklistThreshold the proxy
// goes on cooldown. A proxy with a chronically bad lifetime record is evicted
// and banned until the process restarts. Next prefers the highest surviving
// score and round-robins among ties.
package switcher

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	personalStartScore = 3
	publicStartScore   = 1

	// DefaultMaxScore caps how high repeated successes can push a score.
	DefaultMaxScore = 5
	// DefaultBlacklistThreshold puts a proxy on cooldown once its score
	// drops below this value.
	DefaultBlacklistThreshold = 0
	// DefaultCooldown is how long a blacklisted proxy is skipped.
	DefaultCooldown = 30 * time.Minute
	// DefaultRefreshInterval is how often Run reloads every source.
	DefaultRefreshInterval = time.Hour
	// DefaultEvictAfterFailures is the attempt count the eviction rules
	// start applying at.
	DefaultEvictAfterFailures = 10
	// DefaultEvictMaxSuccesses is the most lifetime successes a chronically
	// failing proxy may have and still be evicted.
	DefaultEvictMaxSuccesses = 1
	// DefaultEvictMaxSuccessRate evicts a proxy whose lifetime success rate
	// is at or below this fraction.
	DefaultEvictMaxSuccessRate = 0.1
	// DefaultGlobalFailureAfterSites is how many distinct sites must reject a
	// proxy before that starts counting against its global score. One strict
	// site must not cost a proxy its place in the pool.
	DefaultGlobalFailureAfterSites = 3

	// maxTrackedSites bounds the per-proxy site records.
	maxTrackedSites = 256
	// siteRecordTTL is how long a site with no active block stays counted.
	siteRecordTTL = time.Hour
	// DefaultCoolingRetryInterval is how often a proxy on cooldown may be retried
	// when no other proxy is available.
	DefaultCoolingRetryInterval = 5 * time.Second
)

// ErrNoProxy is returned when no proxy is available for a request and direct
// connections are not allowed. Failing closed is deliberate: silently going
// direct would expose the caller's real IP.
var ErrNoProxy = errors.New("proxyswitcher: no proxy available")

// Tier distinguishes operator-trusted proxies from ones pulled from public
// lists. It only sets the starting score; afterwards both are treated alike.
type Tier string

// Proxy tiers.
const (
	TierPersonal Tier = "personal"
	TierPublic   Tier = "public"
)

// PoolConfig configures a Pool. Zero values fall back to the Default*
// constants, except BlacklistThreshold, whose zero value is its default.
type PoolConfig struct {
	MaxScore            int
	BlacklistThreshold  int
	Cooldown            time.Duration
	RefreshInterval     time.Duration
	EvictAfterFailures  int
	EvictMaxSuccesses   int
	EvictMaxSuccessRate float64
	// SiteCooldown is how long a proxy blocked by one site is skipped for that
	// site. Zero uses Cooldown.
	SiteCooldown time.Duration
	// GlobalFailureAfterSites is how many distinct sites must reject a proxy
	// before each further one counts as a global failure. Zero uses
	// DefaultGlobalFailureAfterSites.
	GlobalFailureAfterSites int
	// CoolingRetryInterval is how often a proxy on cooldown may be retried when
	// no other proxy is available, so a short outage cannot leave the pool unusable
	// for a whole Cooldown. Zero uses DefaultCoolingRetryInterval.
	CoolingRetryInterval time.Duration
	// ExcludeHosts lists host:port values that may never join the pool. The
	// forward proxy lists itself here, so it can never chain to itself.
	ExcludeHosts []string
	HealthCheck  HealthCheckConfig
	// Logger receives pool events. Nil uses slog.Default.
	Logger *slog.Logger
}

// Entry is a point-in-time view of one proxy, returned by Pool.Snapshot.
type Entry struct {
	URL           *url.URL
	Tier          Tier
	Score         int
	CooldownUntil time.Time
	Failures      int
	Successes     int
	// BlockedSites counts sites currently refusing this proxy.
	BlockedSites int
}

// siteRecord remembers one site's rejection of a proxy. A zero blockedUntil
// means the site failed through every proxy, so the proxy is not skipped for it.
type siteRecord struct {
	blockedUntil time.Time
	noted        time.Time
}

type scoredProxy struct {
	url           *url.URL
	key           string
	tier          Tier
	score         int
	cooldownUntil time.Time
	// sources records which sources currently list this proxy, so a failed
	// source cannot cause its entries to be dropped.
	sources map[int]bool
	// failures and successes are lifetime counts: cooldown expiry does not
	// reset them, and the eviction check reads them.
	failures  int
	successes int
	// badSites records per-site rejections, which are separate from the global
	// score so a block by one site leaves the proxy usable everywhere else.
	badSites map[string]siteRecord
	// retrying marks a proxy handed out by NextCooling, whose next result decides
	// whether it recovers. lastRetry limits how often that happens.
	retrying  bool
	lastRetry time.Time
}

// Pool is a scored, self-healing proxy pool, safe for concurrent use.
// Construct it with NewPool and populate it with Refresh.
type Pool struct {
	mu      sync.Mutex
	entries map[string]*scoredProxy
	// ordered holds the entries sorted by key.
	ordered []*scoredProxy
	// banned holds evicted proxies so a later refresh cannot re-add them
	// with a clean score. A restart clears it.
	banned  map[string]bool
	idx     atomic.Uint64
	cfg     PoolConfig
	sources []Source
	logger  *slog.Logger
	now     func() time.Time // injectable for deterministic tests
}

// NewPool builds an empty pool that loads from sources. Call Refresh to
// populate it.
func NewPool(cfg PoolConfig, sources ...Source) *Pool {
	if cfg.MaxScore <= 0 {
		cfg.MaxScore = DefaultMaxScore
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = DefaultCooldown
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = DefaultRefreshInterval
	}
	if cfg.EvictAfterFailures <= 0 {
		cfg.EvictAfterFailures = DefaultEvictAfterFailures
	}
	if cfg.EvictMaxSuccesses <= 0 {
		cfg.EvictMaxSuccesses = DefaultEvictMaxSuccesses
	}
	if cfg.EvictMaxSuccessRate <= 0 {
		cfg.EvictMaxSuccessRate = DefaultEvictMaxSuccessRate
	}
	if cfg.CoolingRetryInterval <= 0 {
		cfg.CoolingRetryInterval = DefaultCoolingRetryInterval
	}
	if cfg.SiteCooldown <= 0 {
		cfg.SiteCooldown = cfg.Cooldown
	}
	if cfg.GlobalFailureAfterSites <= 0 {
		cfg.GlobalFailureAfterSites = DefaultGlobalFailureAfterSites
	}
	cfg.HealthCheck = cfg.HealthCheck.withDefaults()
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Pool{
		entries: make(map[string]*scoredProxy),
		banned:  make(map[string]bool),
		cfg:     cfg,
		sources: sources,
		logger:  logger,
		now:     time.Now,
	}
}

// Next returns the best-scored proxy that is not on cooldown, round-robining
// among ties. It returns nil when nothing is available.
func (p *Pool) Next() *url.URL {
	return p.NextExcluding(nil)
}

// NextExcluding is Next, skipping any proxy whose URL string is in exclude.
// Transport uses it so one request never retries a proxy it already tried.
func (p *Pool) NextExcluding(exclude map[string]bool) *url.URL {
	return p.NextFor("", exclude)
}

// NextFor is NextExcluding for a request to host: it also skips any proxy that
// host is currently blocking.
func (p *Pool) NextFor(host string, exclude map[string]bool) *url.URL {
	p.mu.Lock()
	defer p.mu.Unlock()

	// This runs under the lock for every request, so with thousands of proxies
	// it must not sort or allocate. p.ordered is already sorted, which keeps the
	// rotation among ties stable.
	now := p.now()
	bestScore, ties := 0, 0
	eligible := func(e *scoredProxy) bool {
		return !e.cooldownUntil.After(now) && !exclude[e.key] && !e.blockedFor(host, now)
	}
	for _, e := range p.ordered {
		if !eligible(e) {
			continue
		}
		switch {
		case ties == 0 || e.score > bestScore:
			bestScore, ties = e.score, 1
		case e.score == bestScore:
			ties++
		}
	}
	if ties == 0 {
		return nil
	}
	want := (p.idx.Add(1) - 1) % uint64(ties)
	for _, e := range p.ordered {
		if !eligible(e) || e.score != bestScore {
			continue
		}
		if want == 0 {
			chosen := *e.url
			return &chosen
		}
		want--
	}
	return nil
}

// NextCooling returns the proxy on cooldown that is closest to coming back, for
// when NextFor finds nothing. Each proxy is retried at most once per
// CoolingRetryInterval, and nil means none is due. Without this, a brief outage of
// every proxy would leave the pool refusing requests for a whole Cooldown, long
// after the proxies returned.
func (p *Pool) NextCooling(host string, exclude map[string]bool) *url.URL {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	var best *scoredProxy
	for _, e := range p.ordered {
		if !e.cooldownUntil.After(now) || exclude[e.key] || e.blockedFor(host, now) ||
			now.Sub(e.lastRetry) < p.cfg.CoolingRetryInterval {
			continue
		}
		if best == nil || e.cooldownUntil.Before(best.cooldownUntil) {
			best = e
		}
	}
	if best == nil {
		return nil
	}
	best.retrying = true
	best.lastRetry = now
	chosen := *best.url
	return &chosen
}

// rebuildOrderLocked refreshes p.ordered after entries change. The caller must
// hold p.mu.
func (p *Pool) rebuildOrderLocked() {
	p.ordered = p.ordered[:0]
	for _, e := range p.entries {
		p.ordered = append(p.ordered, e)
	}
	sort.Slice(p.ordered, func(i, j int) bool { return p.ordered[i].key < p.ordered[j].key })
}

// Report records the outcome of a request made through u. Proxies no longer
// in the pool are ignored.
func (p *Pool) Report(u *url.URL, success bool) {
	if u == nil {
		return
	}
	key := u.String()
	p.mu.Lock()
	defer p.mu.Unlock()

	e, ok := p.entries[key]
	if !ok {
		return
	}
	retrying := e.retrying
	e.retrying = false
	if success {
		e.successes++
		// It works, so there is nothing left to wait for.
		e.cooldownUntil = time.Time{}
		if e.score < p.cfg.MaxScore {
			e.score++
		}
		return
	}
	// A failed retry only extends the cooldown. Counting it would evict every
	// proxy during a long outage, and leave the pool empty until a restart.
	if retrying {
		e.cooldownUntil = p.now().Add(p.cfg.Cooldown)
		return
	}
	p.failLocked(key, e)
}

// ReportBlocked records that host rejected u while another proxy got through.
// The proxy is skipped for host only. Rejection by several distinct sites
// counts against its global score, so one that fails everywhere is still
// evicted.
func (p *Pool) ReportBlocked(u *url.URL, host string) {
	p.noteSite(u, host, true)
}

// ReportInconclusive records that a request to host failed through every proxy
// tried, which points at the site rather than the proxy. It changes nothing
// unless the proxy keeps failing on many distinct sites.
func (p *Pool) ReportInconclusive(u *url.URL, host string) {
	p.noteSite(u, host, false)
}

func (p *Pool) noteSite(u *url.URL, host string, block bool) {
	if u == nil {
		return
	}
	key := u.String()
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[key]
	if !ok {
		return
	}
	e.retrying = false
	now := p.now()
	if e.badSites == nil {
		e.badSites = make(map[string]siteRecord)
	}
	_, known := e.badSites[host]
	if !known && len(e.badSites) >= maxTrackedSites {
		e.sweepSites(now)
		if len(e.badSites) >= maxTrackedSites {
			return
		}
	}
	record := siteRecord{noted: now}
	if block {
		record.blockedUntil = now.Add(p.cfg.SiteCooldown)
	}
	e.badSites[host] = record
	if !known && len(e.badSites) >= p.cfg.GlobalFailureAfterSites {
		p.failLocked(key, e)
	}
}

func (e *scoredProxy) blockedFor(host string, now time.Time) bool {
	if host == "" {
		return false
	}
	record, ok := e.badSites[host]
	return ok && record.blockedUntil.After(now)
}

func (e *scoredProxy) sweepSites(now time.Time) {
	for host, record := range e.badSites {
		if !record.blockedUntil.After(now) && now.Sub(record.noted) >= siteRecordTTL {
			delete(e.badSites, host)
		}
	}
}

// Usable reports whether u is in the pool, off cooldown and not blocked by host.
func (p *Pool) Usable(u *url.URL, host string) bool {
	if u == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[u.String()]
	now := p.now()
	return ok && !e.cooldownUntil.After(now) && !e.blockedFor(host, now)
}

// UsableCount returns how many proxies are off cooldown.
func (p *Pool) UsableCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	count := 0
	for _, e := range p.entries {
		if !e.cooldownUntil.After(now) {
			count++
		}
	}
	return count
}

// failLocked applies one global failure. The caller must hold p.mu.
func (p *Pool) failLocked(key string, e *scoredProxy) {
	u := e.url
	e.failures++
	e.score--
	if p.shouldEvict(e.failures, e.successes) {
		delete(p.entries, key)
		p.rebuildOrderLocked()
		p.banned[key] = true
		p.logger.Warn("evicting chronically failing proxy",
			"proxy", RedactURL(u), "tier", e.tier,
			"failures", e.failures, "successes", e.successes)
		return
	}
	if e.score < p.cfg.BlacklistThreshold {
		e.cooldownUntil = p.now().Add(p.cfg.Cooldown)
		p.logger.Warn("putting proxy on cooldown",
			"proxy", RedactURL(u), "tier", e.tier,
			"score", e.score, "cooldown", p.cfg.Cooldown)
	}
}

// shouldEvict applies two independent rules. The absolute rule catches a
// proxy that is essentially always dead, even at low volume. The rate rule
// catches a high-volume bad proxy the absolute rule misses, such as 10
// successes out of 100 attempts.
func (p *Pool) shouldEvict(failures, successes int) bool {
	if failures > p.cfg.EvictAfterFailures && successes <= p.cfg.EvictMaxSuccesses {
		return true
	}
	total := failures + successes
	return total > p.cfg.EvictAfterFailures &&
		float64(successes)/float64(total) <= p.cfg.EvictMaxSuccessRate
}

// Refresh reloads every source and merges the results. Existing entries keep
// their score and cooldown. An entry is dropped only when every source that
// listed it refreshed successfully and no longer does, so a source outage
// never wipes the proxies it supplied. Sources are read before the pool lock
// is taken, so a slow source never blocks Next or Report.
func (p *Pool) Refresh(ctx context.Context) {
	type result struct {
		proxies []string
		err     error
	}
	results := make([]result, len(p.sources))
	for i, s := range p.sources {
		proxies, err := s.Fetch(ctx)
		results[i] = result{proxies: proxies, err: err}
		if err != nil {
			p.logger.Warn("proxy source failed; keeping its existing proxies",
				"source", s.Name(), "error", RedactText(err.Error()))
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	for _, e := range p.entries {
		e.sweepSites(now)
	}
	for i, s := range p.sources {
		if results[i].err != nil {
			continue
		}
		seen := make(map[string]bool, len(results[i].proxies))
		for _, raw := range results[i].proxies {
			if key := p.mergeLocked(raw, s.Tier(), i); key != "" {
				seen[key] = true
			}
		}
		for key, e := range p.entries {
			if e.sources[i] && !seen[key] {
				delete(e.sources, i)
				if len(e.sources) == 0 {
					delete(p.entries, key)
				}
			}
		}
	}
	p.rebuildOrderLocked()
	p.logger.Info("proxy pool refreshed", "total", len(p.entries))
}

// mergeLocked adds raw as an entry from the given source and returns its key,
// or "" when raw is invalid or banned. The caller must hold p.mu.
func (p *Pool) mergeLocked(raw string, tier Tier, source int) string {
	raw = strings.TrimSpace(raw)
	// Public lists hand back bare "host:port", which url.Parse rejects, so a
	// missing scheme is assumed to be plain HTTP.
	if raw != "" && !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		// The parse error quotes the raw URL, password included.
		p.logger.Warn("skipping invalid proxy url", "tier", tier, "error", RedactText(err.Error()))
		return ""
	}
	if u.Host == "" {
		p.logger.Warn("skipping proxy url without a host", "tier", tier)
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" {
		p.logger.Warn("skipping proxy url with unsupported scheme", "tier", tier, "scheme", u.Scheme)
		return ""
	}
	key := u.String()
	if slices.Contains(p.cfg.ExcludeHosts, u.Host) {
		p.logger.Warn("skipping proxy that points at this proxyswitcher", "proxy", RedactURL(u))
		return ""
	}
	if p.banned[key] {
		return ""
	}
	if e, ok := p.entries[key]; ok {
		// A personal listing outranks a public one, whichever came first.
		if tier == TierPersonal {
			e.tier = tier
		}
		e.sources[source] = true
		return key
	}
	score := publicStartScore
	if tier == TierPersonal {
		score = personalStartScore
	}
	p.entries[key] = &scoredProxy{url: u, key: key, tier: tier, score: score, sources: map[int]bool{source: true}}
	return key
}

// Run refreshes the pool every RefreshInterval until ctx is canceled. It
// blocks, so call it in a goroutine.
func (p *Pool) Run(ctx context.Context) {
	ticker := time.NewTicker(p.cfg.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.Refresh(ctx)
		}
	}
}

// Snapshot returns the current entries sorted by URL.
func (p *Pool) Snapshot() []Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	out := make([]Entry, 0, len(p.entries))
	for _, e := range p.entries {
		u := *e.url
		blocked := 0
		for _, record := range e.badSites {
			if record.blockedUntil.After(now) {
				blocked++
			}
		}
		out = append(out, Entry{
			URL: &u, Tier: e.tier, Score: e.score, CooldownUntil: e.cooldownUntil,
			Failures: e.failures, Successes: e.successes, BlockedSites: blocked,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL.String() < out[j].URL.String() })
	return out
}

// remove drops u outright, unlike Report, which only cools a proxy down.
func (p *Pool) remove(u *url.URL) {
	p.mu.Lock()
	delete(p.entries, u.String())
	p.rebuildOrderLocked()
	p.mu.Unlock()
}
