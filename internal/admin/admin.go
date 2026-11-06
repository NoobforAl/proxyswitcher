// Package admin serves health and status endpoints, so scripts can wait until
// the proxy is usable before starting a scan or crawl.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/NoobforAl/proxyswitcher/switcher"
)

const (
	readHeaderTimeout = 5 * time.Second
	shutdownTimeout   = 5 * time.Second
)

// ProxyStatus describes one proxy, with credentials removed.
type ProxyStatus struct {
	Proxy         string    `json:"proxy"`
	Tier          string    `json:"tier"`
	Score         int       `json:"score"`
	Successes     int       `json:"successes"`
	Failures      int       `json:"failures"`
	BlockedSites  int       `json:"blocked_sites"`
	CooldownUntil time.Time `json:"cooldown_until,omitzero"`
}

// Status is the /status response.
type Status struct {
	Profile string        `json:"profile"`
	Usable  int           `json:"usable"`
	Total   int           `json:"total"`
	Proxies []ProxyStatus `json:"proxies"`
}

// Handler serves GET /healthz, which answers 503 when no proxy is usable, and
// GET /status.
func Handler(pool *switcher.Pool, profile string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if pool.UsableCount() == 0 {
			http.Error(w, "no usable proxies", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		entries := pool.Snapshot()
		status := Status{
			Profile: profile,
			Usable:  pool.UsableCount(),
			Total:   len(entries),
			Proxies: make([]ProxyStatus, 0, len(entries)),
		}
		now := time.Now()
		for _, e := range entries {
			item := ProxyStatus{
				Proxy:        switcher.RedactURL(e.URL),
				Tier:         string(e.Tier),
				Score:        e.Score,
				Successes:    e.Successes,
				Failures:     e.Failures,
				BlockedSites: e.BlockedSites,
			}
			if e.CooldownUntil.After(now) {
				item.CooldownUntil = e.CooldownUntil
			}
			status.Proxies = append(status.Proxies, item)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	})
	return mux
}

// Serve runs the endpoints on ln until ctx is canceled.
func Serve(ctx context.Context, ln net.Listener, handler http.Handler) error {
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: readHeaderTimeout}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	err := srv.Shutdown(shutdownCtx)
	if srvErr := <-errCh; !errors.Is(srvErr, http.ErrServerClosed) {
		return srvErr
	}
	return err
}
