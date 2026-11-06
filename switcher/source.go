package switcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	maxSourceBodyBytes = 16 << 20
	sourceFetchTimeout = 15 * time.Second
	// maxDatabayPages bounds pagination so an API that never returns an
	// empty page cannot make a refresh run forever.
	maxDatabayPages = 20
	databayPageSize = 500
	proxyScrapeURL  = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&proxy_format=ipport&format=text"

	// DefaultDatabayBaseURL is the Databay proxy-list endpoint.
	DefaultDatabayBaseURL = "https://databay.com/api/v1/proxy-list"
)

// Source supplies proxy URLs to a Pool. Entries may be full URLs or bare
// "host:port", which is assumed to be plain HTTP.
//
// A source that has nothing to offer, such as an unset path or a missing
// file, returns an empty list and a nil error. A non-nil error means the
// source could not be read, and its existing proxies stay in the pool.
type Source interface {
	Name() string
	Tier() Tier
	Fetch(ctx context.Context) ([]string, error)
}

// StaticSource is a fixed list of proxies.
type StaticSource struct {
	Proxies []string
	// ProxyTier defaults to TierPublic.
	ProxyTier Tier
}

// Name implements Source.
func (s StaticSource) Name() string { return "static" }

// Tier implements Source.
func (s StaticSource) Tier() Tier {
	if s.ProxyTier == "" {
		return TierPublic
	}
	return s.ProxyTier
}

// Fetch implements Source.
func (s StaticSource) Fetch(context.Context) ([]string, error) { return s.Proxies, nil }

// PersonalFileSource reads operator-owned proxies from a YAML file:
//
//	personal_proxies:
//	  - url: "http://user:pass@1.2.3.4:8080"
//	    score: 3 # informational only
//
// An empty path or a missing file yields no proxies.
type PersonalFileSource struct{ Path string }

// Name implements Source.
func (s PersonalFileSource) Name() string { return "personal_file" }

// Tier implements Source.
func (s PersonalFileSource) Tier() Tier { return TierPersonal }

// Fetch implements Source.
func (s PersonalFileSource) Fetch(context.Context) ([]string, error) {
	raw, err := readOptionalFile(s.Path)
	if err != nil || raw == nil {
		return nil, err
	}
	var file struct {
		PersonalProxies []struct {
			URL string `yaml:"url"`
		} `yaml:"personal_proxies"`
	}
	if err := yaml.Unmarshal(raw, &file); err != nil {
		// yaml errors can quote the offending line, which may hold a password.
		return nil, redactErr(fmt.Errorf("parse %s: %w", s.Path, err))
	}
	out := make([]string, 0, len(file.PersonalProxies))
	for _, e := range file.PersonalProxies {
		if u := strings.TrimSpace(e.URL); u != "" {
			out = append(out, u)
		}
	}
	return out, nil
}

// ListFileSource reads a plain-text list with one proxy per line. Blank lines
// and lines starting with "#" are skipped. An empty path or a missing file
// yields no proxies.
type ListFileSource struct{ Path string }

// Name implements Source.
func (s ListFileSource) Name() string { return "list_file" }

// Tier implements Source.
func (s ListFileSource) Tier() Tier { return TierPublic }

// Fetch implements Source.
func (s ListFileSource) Fetch(context.Context) ([]string, error) {
	raw, err := readOptionalFile(s.Path)
	if err != nil || raw == nil {
		return nil, err
	}
	return parseProxyLines(string(raw)), nil
}

func readOptionalFile(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return raw, err
}

// ProxyScrapeSource reads host:port pairs from the ProxyScrape free-list API.
// A response with no proxies in it is an error rather than an empty list, so a
// format change cannot wipe the proxies this source already supplied.
type ProxyScrapeSource struct {
	// URL overrides the API address. Empty uses the public API.
	URL string
}

// Name implements Source.
func (s ProxyScrapeSource) Name() string { return "proxyscrape" }

// Tier implements Source.
func (s ProxyScrapeSource) Tier() Tier { return TierPublic }

// Fetch implements Source.
func (s ProxyScrapeSource) Fetch(ctx context.Context) ([]string, error) {
	target := s.URL
	if target == "" {
		target = proxyScrapeURL
	}
	body, err := fetchBody(ctx, newSourceClient(), target, "")
	if err != nil {
		return nil, fmt.Errorf("proxyscrape: %w", err)
	}
	proxies := parseHostPortPairs(body)
	if len(proxies) == 0 {
		return nil, errors.New("proxyscrape: response contained no proxies")
	}
	return proxies, nil
}

// DatabaySource pages through the Databay proxy-list endpoint until a page
// comes back empty or maxDatabayPages is reached.
type DatabaySource struct {
	BaseURL string
	// APIKey, when set, is sent as a Bearer token. The endpoint answered 401
	// without one when last tested live, in November 2026.
	APIKey string
}

// Name implements Source.
func (s DatabaySource) Name() string { return "databay" }

// Tier implements Source.
func (s DatabaySource) Tier() Tier { return TierPublic }

// Fetch implements Source. A failure partway through returns an error, not a
// partial list, so the pool keeps what it already has for this source.
func (s DatabaySource) Fetch(ctx context.Context) ([]string, error) {
	base := strings.TrimSpace(s.BaseURL)
	if base == "" {
		return nil, nil
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	client := newSourceClient()
	var out []string
	for page := 1; page <= maxDatabayPages; page++ {
		target := fmt.Sprintf("%s%sformat=txt&protocol=http&limit=%d&page=%d", base, sep, databayPageSize, page)
		body, err := fetchBody(ctx, client, target, s.APIKey)
		if err != nil {
			return nil, fmt.Errorf("databay page %d: %w", page, err)
		}
		lines := parseProxyLines(body)
		if len(lines) == 0 {
			break
		}
		out = append(out, lines...)
	}
	return out, nil
}

// newSourceClient ignores the proxy environment variables. A shell configured to
// use this proxyswitcher through HTTP_PROXY would otherwise make it call itself
// for its own proxy lists during startup, before it can serve anything.
func newSourceClient() *http.Client {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Client{Timeout: sourceFetchTimeout, Transport: &http.Transport{}}
	}
	transport := base.Clone()
	transport.Proxy = nil
	return &http.Client{Timeout: sourceFetchTimeout, Transport: transport}
}

func fetchBody(ctx context.Context, client *http.Client, target, bearer string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return "", err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSourceBodyBytes))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func parseProxyLines(text string) []string {
	var out []string
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// parseHostPortPairs scans free-form text for "ipv4:port" tokens. It does not
// know the page's structure in advance, so it matches the pattern rather than
// parsing the DOM.
func parseHostPortPairs(body string) []string {
	var out []string
	notHostPort := func(r rune) bool { return r != '.' && r != ':' && (r < '0' || r > '9') }
	for _, tok := range strings.FieldsFunc(body, notHostPort) {
		host, port, ok := strings.Cut(tok, ":")
		if ok && isIPv4(host) && isPort(port) {
			out = append(out, "http://"+tok)
		}
	}
	return out
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if n, err := strconv.Atoi(p); err != nil || n < 0 || n > 255 || len(p) > 3 {
			return false
		}
	}
	return true
}

func isPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n > 0 && n <= 65535
}
