package switcher

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDatabay_PaginatesUntilEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if page, _ := strconv.Atoi(r.URL.Query().Get("page")); page <= 2 {
			_, _ = fmt.Fprintf(w, "# comment\n10.0.0.%d:80\n", page)
		}
	}))
	defer srv.Close()

	got, err := DatabaySource{BaseURL: srv.URL}.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"10.0.0.1:80", "10.0.0.2:80"}) {
		t.Fatalf("got %v", got)
	}
}

func TestDatabay_StopsAtMaxPages(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprintln(w, "10.0.0.1:80")
	}))
	defer srv.Close()

	if _, err := (DatabaySource{BaseURL: srv.URL}).Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != maxDatabayPages {
		t.Fatalf("calls = %d, want %d", calls.Load(), maxDatabayPages)
	}
}

func TestDatabay_FailureIsAnErrorNotAPartialList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			_, _ = fmt.Fprintln(w, "10.0.0.1:80")
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	if got, err := (DatabaySource{BaseURL: srv.URL}).Fetch(context.Background()); err == nil || got != nil {
		t.Fatalf("got %v, %v; want nil and an error", got, err)
	}
}

func TestDatabay_EmptyBaseURLIsNotAnError(t *testing.T) {
	got, err := DatabaySource{}.Fetch(context.Background())
	if err != nil || got != nil {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestDatabay_SendsBearerToken(t *testing.T) {
	var auth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
	}))
	defer srv.Close()

	if _, err := (DatabaySource{BaseURL: srv.URL, APIKey: "key"}).Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if auth.Load() != "Bearer key" {
		t.Fatalf("Authorization = %v", auth.Load())
	}
}

func TestProxyScrape_ParsesPairsFromHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<td>1.2.3.4:8080</td> <td>999.1.1.1:80</td> <td>5.6.7.8:99999</td> v1.2:3`)
	}))
	defer srv.Close()

	got, err := ProxyScrapeSource{URL: srv.URL}.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"http://1.2.3.4:8080"}) {
		t.Fatalf("got %v", got)
	}
}

func TestProxyScrape_EmptyResponseIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "<html>the list moved</html>")
	}))
	defer srv.Close()

	// An empty success would make Pool.Refresh drop everything this source supplied.
	if got, err := (ProxyScrapeSource{URL: srv.URL}).Fetch(context.Background()); err == nil {
		t.Fatalf("got %v, want an error", got)
	}
}

func TestListFile(t *testing.T) {
	got, err := ListFileSource{Path: writeTemp(t, "# note\n\n1.2.3.4:80\r\n http://5.6.7.8:80 \n")}.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"1.2.3.4:80", "http://5.6.7.8:80"}) {
		t.Fatalf("got %v", got)
	}
}

func TestFileSources_MissingOrEmptyPathIsNotAnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	for _, s := range []Source{
		ListFileSource{}, ListFileSource{Path: missing},
		PersonalFileSource{}, PersonalFileSource{Path: missing},
	} {
		if got, err := s.Fetch(context.Background()); err != nil || got != nil {
			t.Errorf("%s: got %v, %v", s.Name(), got, err)
		}
	}
}

func TestPersonalFile(t *testing.T) {
	path := writeTemp(t, "personal_proxies:\n  - url: \"http://u:p@1.2.3.4:80\"\n    score: 3\n  - url: \"\"\n")
	src := PersonalFileSource{Path: path}
	got, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"http://u:p@1.2.3.4:80"}) || src.Tier() != TierPersonal {
		t.Fatalf("got %v, tier %s", got, src.Tier())
	}
}

func TestPersonalFile_MalformedIsAnError(t *testing.T) {
	if _, err := (PersonalFileSource{Path: writeTemp(t, "personal_proxies: [")}).Fetch(context.Background()); err == nil {
		t.Fatal("expected a parse error")
	}
}

// fakeForwardProxy answers absolute-form requests like an HTTP proxy would.
func fakeForwardProxy(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func closedPortURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL
	srv.Close()
	return u
}

func TestProbe(t *testing.T) {
	alive := fakeForwardProxy(t, http.StatusOK)
	blocked := fakeForwardProxy(t, http.StatusForbidden)
	broken := fakeForwardProxy(t, http.StatusBadGateway)
	for _, tc := range []struct {
		name, proxy string
		want        bool
	}{
		{"responds", alive.URL, true},
		{"injects its own 4xx page", blocked.URL, true},
		{"5xx", broken.URL, false},
		{"unreachable", closedPortURL(t), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Probe(context.Background(), mustURL(t, tc.proxy), "http://target.test/", 2*time.Second)
			if got.Alive != tc.want {
				t.Fatalf("Alive = %v, want %v", got.Alive, tc.want)
			}
		})
	}
}

func TestRunHealthCheck_DisabledIsNoOp(t *testing.T) {
	p := newTestPool(t, PoolConfig{}, closedPortURL(t))
	p.RunHealthCheck(context.Background())
	if len(p.Snapshot()) != 1 {
		t.Fatal("a disabled health check must not remove anything")
	}
}

func TestRunHealthCheck_RemovesDeadKeepsAlive(t *testing.T) {
	alive := fakeForwardProxy(t, http.StatusOK)
	p := newTestPool(t, PoolConfig{HealthCheck: HealthCheckConfig{
		Enabled: true, Delay: time.Millisecond, Timeout: 2 * time.Second, TargetURL: "http://target.test/", SkipHTTPS: true,
	}}, alive.URL, closedPortURL(t))
	p.RunHealthCheck(context.Background())
	entries := p.Snapshot()
	if len(entries) != 1 || entries[0].URL.String() != alive.URL {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestRunHealthCheck_CancelledSweepRemovesNothing(t *testing.T) {
	p := newTestPool(t, PoolConfig{HealthCheck: HealthCheckConfig{Enabled: true}}, closedPortURL(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.RunHealthCheck(ctx)
	if len(p.Snapshot()) != 1 {
		t.Fatal("a canceled sweep says nothing about the proxies")
	}
}

func TestSweep_PacesWithDelay(t *testing.T) {
	alive := fakeForwardProxy(t, http.StatusOK)
	second := fakeForwardProxy(t, http.StatusOK)
	const delay = 50 * time.Millisecond
	p := newTestPool(t, PoolConfig{HealthCheck: HealthCheckConfig{Delay: delay, TargetURL: "http://target.test/", SkipHTTPS: true}}, alive.URL, second.URL)
	start := time.Now()
	if got := p.Sweep(context.Background(), nil); len(got) != 2 {
		t.Fatalf("results = %d", len(got))
	}
	if elapsed := time.Since(start); elapsed < delay {
		t.Fatalf("elapsed %v, want at least %v", elapsed, delay)
	}
}
