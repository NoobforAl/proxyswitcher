// Package config loads the proxyswitcher YAML file, applies environment
// overrides, and validates the result.
package config

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/NoobforAl/proxyswitcher/internal/forward"
	"github.com/NoobforAl/proxyswitcher/switcher"
)

// DefaultListen is the local address the forward proxy binds to.
const DefaultListen = "127.0.0.1:8899"

// The two ways to run. ProfileScanner is the default because it cannot corrupt
// a scan: forgetting to set a profile only means fewer retries.
const (
	ProfileScanner = "scanner"
	ProfileScraper = "scraper"
)

const (
	defaultIdleTimeout     = 10 * time.Minute
	defaultRequestTimeout  = time.Minute
	defaultResponseTimeout = switcher.DefaultResponseHeaderTimeout
)

// Config mirrors proxyswitcher.example.yaml, which documents each field.
type Config struct {
	Profile        string        `yaml:"profile"`
	Listen         string        `yaml:"listen"`
	AllowRemote    bool          `yaml:"allow_remote"`
	AdminListen    string        `yaml:"admin_listen"`
	LogLevel       string        `yaml:"log_level"`
	DirectFirst    bool          `yaml:"direct_first"`
	FallbackDirect bool          `yaml:"fallback_direct"`
	MaxAttempts    int           `yaml:"max_attempts"`
	MaxConnections int           `yaml:"max_connections"`
	RetryStatus    []int         `yaml:"retry_status"`
	RetryMethods   []string      `yaml:"retry_methods"`
	Sticky         *bool         `yaml:"sticky"`
	RequireProxies *bool         `yaml:"require_proxies"`
	TargetBackoff  time.Duration `yaml:"target_backoff"`
	DialTimeout    time.Duration `yaml:"dial_timeout"`
	// IdleTimeout, ResponseTimeout and RequestTimeout accept 0 for the profile's
	// default and a negative value for no limit.
	IdleTimeout     time.Duration `yaml:"idle_timeout"`
	ResponseTimeout time.Duration `yaml:"response_timeout"`
	RequestTimeout  time.Duration `yaml:"request_timeout"`

	Pool        Pool        `yaml:"pool"`
	Sources     Sources     `yaml:"sources"`
	HealthCheck HealthCheck `yaml:"health_check"`
}

// Pool holds scoring and eviction settings.
type Pool struct {
	Cooldown                time.Duration `yaml:"cooldown"`
	SiteCooldown            time.Duration `yaml:"site_cooldown"`
	GlobalFailureAfterSites int           `yaml:"global_failure_after_sites"`
	MaxScore                int           `yaml:"max_score"`
	BlacklistThreshold      int           `yaml:"blacklist_threshold"`
	RefreshInterval         time.Duration `yaml:"refresh_interval"`
	EvictAfterFailures      int           `yaml:"evict_after_failures"`
	EvictMaxSuccesses       int           `yaml:"evict_max_successes"`
	EvictMaxSuccessRate     float64       `yaml:"evict_max_success_rate"`
}

// Sources selects where proxies come from.
type Sources struct {
	PersonalFile       string  `yaml:"personal_file"`
	ListFile           string  `yaml:"list_file"`
	ProxyScrapeEnabled bool    `yaml:"proxyscrape_enabled"`
	Databay            Databay `yaml:"databay"`
}

// Databay configures the Databay source. Its API key comes only from the
// DATABAY_API_KEY environment variable, so it can never end up in a file.
type Databay struct {
	Enabled bool   `yaml:"enabled"`
	BaseURL string `yaml:"base_url"`
	APIKey  string `yaml:"-"`
}

// HealthCheck configures proxy probing.
type HealthCheck struct {
	Enabled        bool          `yaml:"enabled"`
	Delay          time.Duration `yaml:"delay"`
	Timeout        time.Duration `yaml:"timeout"`
	TargetURL      string        `yaml:"target_url"`
	HTTPSTargetURL string        `yaml:"https_target_url"`
	SkipHTTPS      bool          `yaml:"skip_https"`
	ExpectBody     string        `yaml:"expect_body"`
}

// Load reads path, applies environment overrides, and validates the result.
// Unknown YAML keys are errors, so a typo cannot silently disable a setting.
func Load(path string) (*Config, error) {
	return LoadWithProfile(path, "")
}

// LoadWithProfile is Load with the profile forced, when profile is not empty.
func LoadWithProfile(path, profile string) (*Config, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	defer func() { _ = f.Close() }()

	cfg := &Config{}
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if decodeErr := dec.Decode(cfg); decodeErr != nil && !errors.Is(decodeErr, io.EOF) {
		return nil, fmt.Errorf("config: parse %s: %s", path, switcher.RedactText(decodeErr.Error()))
	}
	if envErr := cfg.applyEnv(); envErr != nil {
		return nil, envErr
	}
	if profile != "" {
		cfg.Profile = profile
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyDefaults fills in everything the file and environment left unset.
func (c *Config) applyDefaults() {
	if c.Profile == "" {
		c.Profile = ProfileScanner
	}
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Sources.Databay.BaseURL == "" {
		c.Sources.Databay.BaseURL = switcher.DefaultDatabayBaseURL
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = defaultIdleTimeout
	}
	scanner := c.Profile == ProfileScanner
	if c.Sticky == nil {
		c.Sticky = &scanner
	}
	if c.RequireProxies == nil {
		c.RequireProxies = &scanner
	}
	if scanner && c.RetryStatus == nil {
		c.RetryStatus = []int{}
	}
	if !scanner && c.ResponseTimeout == 0 {
		c.ResponseTimeout = defaultResponseTimeout
	}
	if !scanner && c.RequestTimeout == 0 {
		c.RequestTimeout = defaultRequestTimeout
	}
}

func (c *Config) applyEnv() error {
	var errs []error
	str := func(name string, dst *string) {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			*dst = v
		}
	}
	boolean := func(name string, dst *bool) {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("config: %s: %w", name, err))
				return
			}
			*dst = b
		}
	}
	integer := func(name string, dst *int) {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("config: %s: %w", name, err))
				return
			}
			*dst = n
		}
	}
	duration := func(name string, dst *time.Duration) {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("config: %s: %w", name, err))
				return
			}
			*dst = d
		}
	}

	str("PROXYSWITCHER_PROFILE", &c.Profile)
	str("PROXYSWITCHER_LISTEN", &c.Listen)
	boolean("PROXYSWITCHER_ALLOW_REMOTE", &c.AllowRemote)
	str("PROXYSWITCHER_ADMIN_LISTEN", &c.AdminListen)
	str("PROXYSWITCHER_LOG_LEVEL", &c.LogLevel)
	boolean("PROXYSWITCHER_DIRECT_FIRST", &c.DirectFirst)
	boolean("PROXYSWITCHER_FALLBACK_DIRECT", &c.FallbackDirect)
	integer("PROXYSWITCHER_MAX_ATTEMPTS", &c.MaxAttempts)
	integer("PROXYSWITCHER_MAX_CONNECTIONS", &c.MaxConnections)
	duration("PROXYSWITCHER_DIAL_TIMEOUT", &c.DialTimeout)
	duration("PROXYSWITCHER_IDLE_TIMEOUT", &c.IdleTimeout)
	duration("PROXYSWITCHER_RESPONSE_TIMEOUT", &c.ResponseTimeout)
	duration("PROXYSWITCHER_REQUEST_TIMEOUT", &c.RequestTimeout)
	duration("PROXYSWITCHER_COOLDOWN", &c.Pool.Cooldown)
	duration("PROXYSWITCHER_REFRESH_INTERVAL", &c.Pool.RefreshInterval)
	str("PROXYSWITCHER_PERSONAL_FILE", &c.Sources.PersonalFile)
	str("PROXYSWITCHER_LIST_FILE", &c.Sources.ListFile)
	boolean("PROXYSWITCHER_PROXYSCRAPE_ENABLED", &c.Sources.ProxyScrapeEnabled)
	boolean("PROXYSWITCHER_DATABAY_ENABLED", &c.Sources.Databay.Enabled)
	str("PROXYSWITCHER_DATABAY_BASE_URL", &c.Sources.Databay.BaseURL)
	boolean("PROXYSWITCHER_HEALTHCHECK_ENABLED", &c.HealthCheck.Enabled)
	duration("PROXYSWITCHER_HEALTHCHECK_DELAY", &c.HealthCheck.Delay)
	duration("PROXYSWITCHER_HEALTHCHECK_TIMEOUT", &c.HealthCheck.Timeout)
	str("PROXYSWITCHER_HEALTHCHECK_TARGET_URL", &c.HealthCheck.TargetURL)
	c.Sources.Databay.APIKey = strings.TrimSpace(os.Getenv("DATABAY_API_KEY"))
	return errors.Join(errs...)
}

// Validate reports settings that cannot work or are unsafe.
func (c *Config) Validate() error {
	if c.Profile != ProfileScanner && c.Profile != ProfileScraper {
		return fmt.Errorf("config: profile %q: use %q or %q", c.Profile, ProfileScanner, ProfileScraper)
	}
	if err := c.validateAddr("listen", c.Listen); err != nil {
		return err
	}
	if c.AdminListen != "" {
		if err := c.validateAddr("admin_listen", c.AdminListen); err != nil {
			return err
		}
	}
	if c.MaxAttempts < 0 {
		return errors.New("config: max_attempts must not be negative")
	}
	if c.MaxConnections < 0 {
		return errors.New("config: max_connections must not be negative")
	}
	for _, code := range c.RetryStatus {
		if code < 100 || code > 599 {
			return fmt.Errorf("config: retry_status: %d is not an HTTP status code", code)
		}
	}
	if rate := c.Pool.EvictMaxSuccessRate; rate < 0 || rate > 1 {
		return errors.New("config: pool.evict_max_success_rate must be between 0 and 1")
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return fmt.Errorf("config: log_level: %w", err)
	}
	return nil
}

func (c *Config) validateAddr(name, addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("config: %s %q: %w", name, addr, err)
	}
	if !c.AllowRemote && !isLoopback(host) {
		return fmt.Errorf("config: %s %q is not a loopback address: it has no authentication, "+
			"so this would expose it to the network (an open proxy, for listen); "+
			"set allow_remote: true to accept that", name, addr)
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// SlogLevel returns the configured log level.
func (c *Config) SlogLevel() slog.Level {
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return slog.LevelInfo
	}
	return level
}

// SelfAddrs returns the host:port values that reach this proxy, so it can refuse
// to chain to itself. A wildcard listen address adds the loopback names.
func (c *Config) SelfAddrs() []string {
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return nil
	}
	addrs := []string{c.Listen}
	ip := net.ParseIP(host)
	if host == "" || host == "localhost" || (ip != nil && (ip.IsLoopback() || ip.IsUnspecified())) {
		for _, name := range []string{"127.0.0.1", "localhost", "::1"} {
			addrs = append(addrs, net.JoinHostPort(name, port))
		}
	}
	return addrs
}

// PoolConfig returns the library pool settings.
func (c *Config) PoolConfig(logger *slog.Logger) switcher.PoolConfig {
	return switcher.PoolConfig{
		MaxScore:                c.Pool.MaxScore,
		BlacklistThreshold:      c.Pool.BlacklistThreshold,
		Cooldown:                c.Pool.Cooldown,
		SiteCooldown:            c.Pool.SiteCooldown,
		GlobalFailureAfterSites: c.Pool.GlobalFailureAfterSites,
		RefreshInterval:         c.Pool.RefreshInterval,
		EvictAfterFailures:      c.Pool.EvictAfterFailures,
		EvictMaxSuccesses:       c.Pool.EvictMaxSuccesses,
		EvictMaxSuccessRate:     c.Pool.EvictMaxSuccessRate,
		ExcludeHosts:            c.SelfAddrs(),
		HealthCheck: switcher.HealthCheckConfig{
			Enabled:        c.HealthCheck.Enabled,
			Delay:          c.HealthCheck.Delay,
			Timeout:        c.HealthCheck.Timeout,
			TargetURL:      c.HealthCheck.TargetURL,
			HTTPSTargetURL: c.HealthCheck.HTTPSTargetURL,
			SkipHTTPS:      c.HealthCheck.SkipHTTPS,
			ExpectBody:     c.HealthCheck.ExpectBody,
		},
		Logger: logger,
	}
}

// BuildSources returns the enabled proxy sources.
func (c *Config) BuildSources() []switcher.Source {
	var out []switcher.Source
	if c.Sources.PersonalFile != "" {
		out = append(out, switcher.PersonalFileSource{Path: c.Sources.PersonalFile})
	}
	if c.Sources.ListFile != "" {
		out = append(out, switcher.ListFileSource{Path: c.Sources.ListFile})
	}
	if c.Sources.ProxyScrapeEnabled {
		out = append(out, switcher.ProxyScrapeSource{})
	}
	if c.Sources.Databay.Enabled {
		out = append(out, switcher.DatabaySource{
			BaseURL: c.Sources.Databay.BaseURL,
			APIKey:  c.Sources.Databay.APIKey,
		})
	}
	return out
}

// TransportConfig returns forward-proxy transport settings. Compression stays
// off so the client's own Accept-Encoding and the response bytes pass through
// unchanged.
func (c *Config) TransportConfig(logger *slog.Logger) switcher.TransportConfig {
	base := &http.Transport{}
	if std, ok := http.DefaultTransport.(*http.Transport); ok {
		base = std.Clone()
	}
	base.DisableCompression = true
	base.MaxIdleConnsPerHost = 32
	base.ResponseHeaderTimeout = max(c.ResponseTimeout, 0)
	return switcher.TransportConfig{
		MaxAttempts:    c.MaxAttempts,
		RetryStatus:    c.RetryStatus,
		RetryMethods:   c.RetryMethods,
		DirectFirst:    c.DirectFirst,
		FallbackDirect: c.FallbackDirect,
		StickyHosts:    c.Sticky != nil && *c.Sticky,
		TargetBackoff:  c.TargetBackoff,
		DialTimeout:    c.DialTimeout,
		RequestTimeout: max(c.RequestTimeout, 0),
		Base:           base,
		Logger:         logger,
	}
}

// ForwardOptions returns the forward proxy settings.
func (c *Config) ForwardOptions(logger *slog.Logger) forward.Options {
	return forward.Options{
		SwitchOnStatus: c.Profile == ProfileScraper,
		SelfAddrs:      c.SelfAddrs(),
		IdleTimeout:    max(c.IdleTimeout, 0),
		MaxConnections: c.MaxConnections,
		Logger:         logger,
	}
}
