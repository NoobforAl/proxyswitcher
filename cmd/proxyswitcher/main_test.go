package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeCheckConfig(t *testing.T, proxies ...string) string {
	t.Helper()
	dir := t.TempDir()
	list := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(list, []byte(strings.Join(proxies, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "config.yaml")
	content := "sources:\n  list_file: " + filepath.ToSlash(list) +
		"\nhealth_check:\n  delay: 1ms\n  timeout: 2s\n  skip_https: true\n  target_url: \"http://target.test/\"\n"
	if err := os.WriteFile(config, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return config
}

func closedPort(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL
	srv.Close()
	return u
}

func TestCheck_PrintsTableAndRedactsCredentials(t *testing.T) {
	alive := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer alive.Close()
	withCreds := strings.Replace(alive.URL, "http://", "http://user:s3cret@", 1)

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"check", "-config", writeCheckConfig(t, withCreds, closedPort(t))}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "1 of 2 proxies alive") || !strings.Contains(out, "ok") || !strings.Contains(out, "fail") || !strings.Contains(out, "skip") {
		t.Fatalf("output: %s", out)
	}
	if strings.Contains(out+stderr.String(), "s3cret") {
		t.Fatalf("password leaked: %s %s", out, stderr.String())
	}
}

func TestCheck_ExitsNonZeroWhenNothingIsAlive(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"check", "-config", writeCheckConfig(t, closedPort(t))}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
}

func writeServeConfig(t *testing.T, content string) string {
	t.Helper()
	config := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(config, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return config
}

// A scan through an empty pool would turn every request into an error, so the
// default profile refuses to start.
func TestServe_ScannerRefusesEmptyPool(t *testing.T) {
	var stdout, stderr bytes.Buffer
	config := writeServeConfig(t, "listen: \"127.0.0.1:0\"\n")
	if code := run(context.Background(), []string{"serve", "-config", config}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stderr.String(), "pool is empty") {
		t.Fatalf("stderr: %s", stderr.String())
	}
}

func TestServe_ScraperStartsWithEmptyPoolAndStopsCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout bytes.Buffer
	stderr := &syncBuffer{}
	config := writeServeConfig(t, "profile: scraper\nlisten: \"127.0.0.1:0\"\n")
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"serve", "-config", config}, &stdout, stderr) }()

	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(stderr.String(), "forward proxy listening") {
		if time.Now().After(deadline) {
			t.Fatalf("never started: %s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(stderr.String(), "profile=scraper") {
		t.Fatalf("the active profile should be logged at startup: %s", stderr.String())
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop")
	}
}

func TestServe_BusyPortFailsFast(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var stdout, stderr bytes.Buffer
	config := writeServeConfig(t, "profile: scraper\nlisten: \""+ln.Addr().String()+"\"\n")
	if code := run(context.Background(), []string{"serve", "-config", config}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d", code)
	}
}

// A proxy that passes plain HTTP but cannot open tunnels is useless to Burp or
// ZAP, so check must report it as failing.
func TestCheck_ReportsHTTPSSeparately(t *testing.T) {
	plainOnly := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer plainOnly.Close()
	config := writeServeConfig(t, "sources:\n  list_file: "+writeList(t, plainOnly.URL)+
		"\nhealth_check:\n  timeout: 2s\n  target_url: \"http://target.test/\"\n  https_target_url: \"https://target.test/\"\n")

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"check", "-config", config}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d: %s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), " ok ") || !strings.Contains(stdout.String(), " fail ") {
		t.Fatalf("output: %s", stdout.String())
	}
}

func TestCheck_InterruptedStillPrintsSummary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if code := run(ctx, []string{"check", "-config", writeCheckConfig(t, closedPort(t))}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout.String(), "Interrupted") {
		t.Fatalf("output: %s", stdout.String())
	}
}

func writeList(t *testing.T, proxies ...string) string {
	t.Helper()
	list := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(list, []byte(strings.Join(proxies, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(list)
}

// syncBuffer lets a test read log output while the server is still writing it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRun_BadUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, args := range [][]string{nil, {"bogus"}, {"serve", "-nope"}} {
		if code := run(context.Background(), args, &stdout, &stderr); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code := run(context.Background(), []string{"check", "-config", "absent.yaml"}, &stdout, &stderr); code != 1 {
		t.Errorf("missing config: exit %d, want 1", code)
	}
}
