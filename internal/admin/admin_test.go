package admin

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NoobforAl/proxyswitcher/switcher"
)

func newPool(proxies ...string) *switcher.Pool {
	pool := switcher.NewPool(
		switcher.PoolConfig{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
		switcher.StaticSource{Proxies: proxies})
	pool.Refresh(context.Background())
	return pool
}

func get(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestHealthz(t *testing.T) {
	if got := get(t, Handler(newPool(), "scanner"), "/healthz").Code; got != http.StatusServiceUnavailable {
		t.Errorf("empty pool: %d", got)
	}
	if got := get(t, Handler(newPool("http://a:1"), "scanner"), "/healthz").Code; got != http.StatusOK {
		t.Errorf("non-empty pool: %d", got)
	}
}

func TestStatus_ReportsPoolWithoutCredentials(t *testing.T) {
	rec := get(t, Handler(newPool("http://user:s3cret@a:1"), "scanner"), "/status")
	if strings.Contains(rec.Body.String(), "s3cret") {
		t.Fatalf("password leaked: %s", rec.Body.String())
	}
	var status Status
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Profile != "scanner" || status.Usable != 1 || status.Total != 1 || status.Proxies[0].Proxy != "http://a:1" {
		t.Fatalf("status = %+v", status)
	}
}
