package switcher

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// newTestPool returns a populated pool of public proxies.
func newTestPool(t *testing.T, cfg PoolConfig, proxies ...string) *Pool {
	t.Helper()
	cfg.Logger = discardLogger()
	p := NewPool(cfg, StaticSource{Proxies: proxies})
	p.Refresh(context.Background())
	return p
}

func entryFor(t *testing.T, p *Pool, raw string) Entry {
	t.Helper()
	for _, e := range p.Snapshot() {
		if e.URL.String() == raw {
			return e
		}
	}
	t.Fatalf("%s is not in the pool", raw)
	return Entry{}
}

func TestPool_ScoreIncrementsOnSuccessCappedAtMax(t *testing.T) {
	p := newTestPool(t, PoolConfig{MaxScore: 3}, "http://a:1")
	u := mustURL(t, "http://a:1")
	for range 10 {
		p.Report(u, true)
	}
	if got := entryFor(t, p, "http://a:1").Score; got != 3 {
		t.Fatalf("score = %d, want 3", got)
	}
}

func TestPool_FailureCoolsDownBelowThreshold(t *testing.T) {
	p := newTestPool(t, PoolConfig{}, "http://a:1")
	u := mustURL(t, "http://a:1")

	p.Report(u, false) // 1 -> 0: at the threshold, still usable
	if p.Next() == nil {
		t.Fatal("proxy at the threshold should still be usable")
	}
	p.Report(u, false) // 0 -> -1: below it
	if got := p.Next(); got != nil {
		t.Fatalf("Next = %v, want nil during cooldown", got)
	}
}

func TestPool_CooldownExpiryReAdmits(t *testing.T) {
	p := newTestPool(t, PoolConfig{Cooldown: time.Minute}, "http://a:1")
	now := time.Now()
	p.now = func() time.Time { return now }
	u := mustURL(t, "http://a:1")
	p.Report(u, false)
	p.Report(u, false)
	if p.Next() != nil {
		t.Fatal("expected cooldown")
	}
	now = now.Add(2 * time.Minute)
	if p.Next() == nil {
		t.Fatal("expected the proxy back after cooldown")
	}
}

func TestPool_EvictsChronicallyFailingProxyAndKeepsItBanned(t *testing.T) {
	src := StaticSource{Proxies: []string{"http://a:1"}}
	p := NewPool(PoolConfig{Logger: discardLogger()}, src)
	p.Refresh(context.Background())
	u := mustURL(t, "http://a:1")
	for range DefaultEvictAfterFailures + 1 {
		p.Report(u, false)
	}
	if len(p.Snapshot()) != 0 {
		t.Fatal("expected eviction")
	}
	p.Refresh(context.Background())
	if len(p.Snapshot()) != 0 {
		t.Fatal("a banned proxy must not come back on refresh")
	}
}

func TestPool_DoesNotEvictBelowFailureThreshold(t *testing.T) {
	p := newTestPool(t, PoolConfig{}, "http://a:1")
	u := mustURL(t, "http://a:1")
	for range DefaultEvictAfterFailures {
		p.Report(u, false)
	}
	if len(p.Snapshot()) != 1 {
		t.Fatal("proxy was evicted too early")
	}
}

func TestPool_DoesNotEvictProxyWithEnoughSuccesses(t *testing.T) {
	p := newTestPool(t, PoolConfig{}, "http://a:1")
	u := mustURL(t, "http://a:1")
	for range 5 {
		p.Report(u, true)
	}
	for range DefaultEvictAfterFailures + 1 {
		p.Report(u, false)
	}
	if len(p.Snapshot()) != 1 {
		t.Fatal("a proxy with a 31% success rate should stay on cooldown, not be evicted")
	}
}

func TestPool_EvictsHighVolumeBadSuccessRate(t *testing.T) {
	p := newTestPool(t, PoolConfig{}, "http://a:1")
	u := mustURL(t, "http://a:1")
	for range 10 {
		p.Report(u, true)
	}
	for range 90 {
		p.Report(u, false)
	}
	if len(p.Snapshot()) != 0 {
		t.Fatal("a proxy with a 10% success rate should be evicted")
	}
}

func TestPool_ConfigurableEviction(t *testing.T) {
	p := newTestPool(t, PoolConfig{EvictAfterFailures: 2}, "http://a:1")
	u := mustURL(t, "http://a:1")
	for range 3 {
		p.Report(u, false)
	}
	if len(p.Snapshot()) != 0 {
		t.Fatal("expected eviction at the configured threshold")
	}
}

func TestPool_ReportIgnoresUnknownProxy(t *testing.T) {
	p := newTestPool(t, PoolConfig{})
	p.Report(mustURL(t, "http://nope:1"), false)
	p.Report(nil, true)
}

func TestPool_NextPrefersHighestScoreAndPersonalTier(t *testing.T) {
	p := NewPool(PoolConfig{Logger: discardLogger()},
		StaticSource{Proxies: []string{"http://public:1"}},
		StaticSource{Proxies: []string{"http://personal:1"}, ProxyTier: TierPersonal})
	p.Refresh(context.Background())
	for range 5 {
		if got := p.Next().String(); got != "http://personal:1" {
			t.Fatalf("Next = %s, want the personal proxy", got)
		}
	}
}

func TestPool_NextRoundRobinsWithinTie(t *testing.T) {
	p := newTestPool(t, PoolConfig{}, "http://a:1", "http://b:1")
	seen := map[string]int{}
	for range 4 {
		seen[p.Next().String()]++
	}
	if seen["http://a:1"] != 2 || seen["http://b:1"] != 2 {
		t.Fatalf("uneven rotation: %v", seen)
	}
}

func TestPool_NextExcludingSkipsTriedProxies(t *testing.T) {
	p := newTestPool(t, PoolConfig{}, "http://a:1", "http://b:1")
	got := p.NextExcluding(map[string]bool{"http://a:1": true})
	if got == nil || got.String() != "http://b:1" {
		t.Fatalf("got %v, want b", got)
	}
	if got := p.NextExcluding(map[string]bool{"http://a:1": true, "http://b:1": true}); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

func TestPool_NextEmptyReturnsNil(t *testing.T) {
	if got := newTestPool(t, PoolConfig{}).Next(); got != nil {
		t.Fatalf("Next = %v, want nil", got)
	}
}

// switchableSource returns whatever the test last set, or fails on demand.
type switchableSource struct {
	proxies []string
	err     error
}

func (s *switchableSource) Name() string { return "switchable" }
func (s *switchableSource) Tier() Tier   { return TierPublic }
func (s *switchableSource) Fetch(context.Context) ([]string, error) {
	return s.proxies, s.err
}

func TestPool_RefreshPreservesScoreAndDropsGone(t *testing.T) {
	src := &switchableSource{proxies: []string{"http://a:1", "http://b:1"}}
	p := NewPool(PoolConfig{Logger: discardLogger()}, src)
	p.Refresh(context.Background())
	p.Report(mustURL(t, "http://a:1"), true)

	src.proxies = []string{"http://a:1"}
	p.Refresh(context.Background())

	entries := p.Snapshot()
	if len(entries) != 1 || entries[0].Score != publicStartScore+1 {
		t.Fatalf("entries = %+v, want only a with its score kept", entries)
	}
}

func TestPool_RefreshKeepsEntriesWhenSourceFails(t *testing.T) {
	src := &switchableSource{proxies: []string{"http://a:1"}}
	p := NewPool(PoolConfig{Logger: discardLogger()}, src)
	p.Refresh(context.Background())
	p.Report(mustURL(t, "http://a:1"), true)

	src.proxies, src.err = nil, errors.New("source is down")
	p.Refresh(context.Background())

	if got := entryFor(t, p, "http://a:1").Score; got != publicStartScore+1 {
		t.Fatalf("score = %d, want it kept through the outage", got)
	}
}

func TestPool_ProxyListedByTwoSourcesSurvivesOneDroppingIt(t *testing.T) {
	first := &switchableSource{proxies: []string{"http://a:1"}}
	second := &switchableSource{proxies: []string{"http://a:1"}}
	p := NewPool(PoolConfig{Logger: discardLogger()}, first, second)
	p.Refresh(context.Background())

	first.proxies = nil
	p.Refresh(context.Background())
	if len(p.Snapshot()) != 1 {
		t.Fatal("still listed by the second source, so it must stay")
	}

	second.proxies = nil
	p.Refresh(context.Background())
	if len(p.Snapshot()) != 0 {
		t.Fatal("no source lists it any more, so it must go")
	}
}

func TestPool_RefreshNormalizesBareHostPortAndSkipsBadEntries(t *testing.T) {
	p := newTestPool(t, PoolConfig{}, "1.2.3.4:8080", "ftp://x:1", "http://", "socks5://s:1080")
	entries := p.Snapshot()
	if len(entries) != 2 || entries[0].URL.String() != "http://1.2.3.4:8080" || entries[1].URL.String() != "socks5://s:1080" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestPool_InvalidURLDoesNotLogPassword(t *testing.T) {
	var logs bytes.Buffer
	p := NewPool(PoolConfig{Logger: slog.New(slog.NewTextHandler(&logs, nil))},
		StaticSource{Proxies: []string{"http://user:s3cret%zz@host:1"}})
	p.Refresh(context.Background())
	if len(p.Snapshot()) != 0 {
		t.Fatal("the invalid url should be skipped")
	}
	if strings.Contains(logs.String(), "s3cret") {
		t.Fatalf("password leaked into logs: %s", logs.String())
	}
}

func TestRedact(t *testing.T) {
	if got := RedactURL(mustURL(t, "http://user:s3cret@host:1")); got != "http://host:1" {
		t.Errorf("RedactURL = %s", got)
	}
	got := RedactText(`parse "http://user:s3cret%zz@host:1": invalid escape`)
	if strings.Contains(got, "s3cret") || !strings.Contains(got, "http://host:1") {
		t.Errorf("RedactText = %s", got)
	}
	sentinel := errors.New("boom http://u:p@h")
	wrapped := redactErr(sentinel)
	if !errors.Is(wrapped, sentinel) || strings.Contains(wrapped.Error(), "u:p") {
		t.Errorf("redactErr = %v", wrapped)
	}
	if redactErr(nil) != nil {
		t.Error("redactErr(nil) should be nil")
	}
}
