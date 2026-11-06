package config

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestProfile_DefaultIsScannerSafe(t *testing.T) {
	cfg, err := Load(writeConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != ProfileScanner {
		t.Fatalf("profile = %q", cfg.Profile)
	}
	transport := cfg.TransportConfig(nil)
	if transport.RetryStatus == nil || len(transport.RetryStatus) != 0 {
		t.Errorf("retry status = %v, want an explicit empty list", transport.RetryStatus)
	}
	if !transport.StickyHosts {
		t.Error("scanner mode should keep one exit IP per site")
	}
	if transport.RequestTimeout != 0 || transport.Base.ResponseHeaderTimeout != 0 {
		t.Error("scanner mode must not cut off slow answers, which time-based tests rely on")
	}
	if !*cfg.RequireProxies {
		t.Error("scanner mode should refuse to start with an empty pool")
	}
	if opts := cfg.ForwardOptions(nil); opts.SwitchOnStatus {
		t.Error("scanner mode should use the raw relay")
	}
}

func TestProfile_Scraper(t *testing.T) {
	cfg, err := Load(writeConfig(t, "profile: scraper\n"))
	if err != nil {
		t.Fatal(err)
	}
	transport := cfg.TransportConfig(nil)
	if transport.RetryStatus != nil {
		t.Errorf("retry status = %v, want the library default", transport.RetryStatus)
	}
	if transport.StickyHosts {
		t.Error("scraper mode should rotate")
	}
	if transport.RequestTimeout == 0 || transport.Base.ResponseHeaderTimeout == 0 {
		t.Error("scraper mode should have time limits")
	}
	if *cfg.RequireProxies {
		t.Error("scraper mode should only warn about an empty pool")
	}
	if opts := cfg.ForwardOptions(nil); !opts.SwitchOnStatus {
		t.Error("scraper mode should switch on status")
	}
}

func TestProfile_SettingsOverrideProfile(t *testing.T) {
	cfg, err := Load(writeConfig(t, "sticky: false\nrequire_proxies: false\nretry_status: [418]\nretry_methods: [POST]\nidle_timeout: 5s\n"))
	if err != nil {
		t.Fatal(err)
	}
	transport := cfg.TransportConfig(nil)
	if transport.StickyHosts || *cfg.RequireProxies {
		t.Error("explicit settings should win over the profile")
	}
	if !slices.Equal(transport.RetryStatus, []int{418}) || !slices.Equal(transport.RetryMethods, []string{http.MethodPost}) {
		t.Errorf("retry settings = %v, %v", transport.RetryStatus, transport.RetryMethods)
	}
	if got := cfg.ForwardOptions(nil).IdleTimeout; got != 5*time.Second {
		t.Errorf("idle timeout = %v", got)
	}
}

func TestProfile_NegativeTimeoutsDisableLimits(t *testing.T) {
	cfg, err := Load(writeConfig(t, "profile: scraper\nresponse_timeout: -1s\nrequest_timeout: -1s\nidle_timeout: -1s\n"))
	if err != nil {
		t.Fatal(err)
	}
	transport := cfg.TransportConfig(nil)
	if transport.RequestTimeout != 0 || transport.Base.ResponseHeaderTimeout != 0 || cfg.ForwardOptions(nil).IdleTimeout != 0 {
		t.Error("a negative value should remove the limit")
	}
}

func TestProfile_UnknownIsAnError(t *testing.T) {
	_, err := Load(writeConfig(t, "profile: stealth\n"))
	if err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("err = %v", err)
	}
}

func TestProfile_EnvOverride(t *testing.T) {
	t.Setenv("PROXYSWITCHER_PROFILE", "scraper")
	cfg, err := Load(writeConfig(t, "profile: scanner\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != ProfileScraper {
		t.Fatalf("profile = %q", cfg.Profile)
	}
}

func TestLoadWithProfile_Forces(t *testing.T) {
	t.Setenv("PROXYSWITCHER_PROFILE", "scanner")
	cfg, err := LoadWithProfile(writeConfig(t, ""), ProfileScraper)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != ProfileScraper || !cfg.ForwardOptions(nil).SwitchOnStatus {
		t.Fatalf("profile = %q", cfg.Profile)
	}
}

func TestAdminListen_RefusesRemoteUnlessAllowed(t *testing.T) {
	if _, err := Load(writeConfig(t, "admin_listen: \"0.0.0.0:8898\"\n")); err == nil {
		t.Fatal("expected the admin address to be refused")
	}
	if _, err := Load(writeConfig(t, "allow_remote: true\nadmin_listen: \"0.0.0.0:8898\"\n")); err != nil {
		t.Fatal(err)
	}
}

func TestSelfAddrs_CoverLoopbackNames(t *testing.T) {
	cfg, err := Load(writeConfig(t, "listen: \"127.0.0.1:9000\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	addrs := cfg.SelfAddrs()
	for _, want := range []string{"127.0.0.1:9000", "localhost:9000", "[::1]:9000"} {
		if !slices.Contains(addrs, want) {
			t.Errorf("%s is missing from %v", want, addrs)
		}
	}
	// A proxy that points back at this listener must not join the pool.
	if got := cfg.PoolConfig(nil).ExcludeHosts; !slices.Contains(got, "localhost:9000") {
		t.Errorf("exclude hosts = %v", got)
	}
}

func TestDialTimeout(t *testing.T) {
	cfg, err := Load(writeConfig(t, "dial_timeout: 3s\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.TransportConfig(nil).DialTimeout; got != 3*time.Second {
		t.Fatalf("dial timeout = %v", got)
	}
}

func TestLogLevel(t *testing.T) {
	if _, err := Load(writeConfig(t, "log_level: chatty\n")); err == nil {
		t.Fatal("expected an error")
	}
	cfg, err := Load(writeConfig(t, "log_level: warn\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SlogLevel().String() != "WARN" {
		t.Fatalf("level = %v", cfg.SlogLevel())
	}
}
