// Command proxyswitcher runs a local forward proxy that switches between
// upstream proxies automatically, and can test a proxy pool.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NoobforAl/proxyswitcher/internal/admin"
	"github.com/NoobforAl/proxyswitcher/internal/config"
	"github.com/NoobforAl/proxyswitcher/internal/forward"
	"github.com/NoobforAl/proxyswitcher/switcher"
)

const usage = `proxyswitcher: local forward proxy with automatic proxy switching

Usage:
  proxyswitcher serve -config proxyswitcher.yaml   run the forward proxy
  proxyswitcher check -config proxyswitcher.yaml   test every proxy, printing rows as they finish
      -concurrency N   probes to run at once (default 10)
`

const defaultCheckConcurrency = 10

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	command := args[0]
	if command != "serve" && command != "check" {
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n%s", command, usage)
		return 2
	}

	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "proxyswitcher.yaml", "path to the config file")
	concurrency := fs.Int("concurrency", defaultCheckConcurrency, "check: probes to run at once")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.New(slog.NewTextHandler(stderr, nil)).Error("loading config failed", "error", err)
		return 1
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: cfg.SlogLevel()}))
	pool := switcher.NewPool(cfg.PoolConfig(logger), cfg.BuildSources()...)

	if command == "check" {
		return check(ctx, pool, *concurrency, stdout)
	}
	if err := serve(ctx, cfg, pool, logger); err != nil {
		logger.Error("server stopped", "error", err)
		return 1
	}
	return 0
}

func serve(ctx context.Context, cfg *config.Config, pool *switcher.Pool, logger *slog.Logger) error {
	// Bind before loading sources, so a busy port fails immediately.
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return err
	}
	pool.Refresh(ctx)
	if pool.UsableCount() == 0 {
		// A scan through an empty pool would turn every request into a 503, so
		// by default it stops here rather than producing a meaningless report.
		if *cfg.RequireProxies {
			_ = ln.Close()
			return errors.New("the proxy pool is empty; add proxies, or set require_proxies: false")
		}
		logger.Warn("the proxy pool is empty; requests will fail until a source provides proxies")
	}
	go pool.Run(ctx)
	go pool.RunHealthCheck(ctx)

	if cfg.AdminListen != "" {
		adminLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.AdminListen)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("admin listener: %w", err)
		}
		go func() {
			if err := admin.Serve(ctx, adminLn, admin.Handler(pool, cfg.Profile)); err != nil {
				logger.Warn("admin server stopped", "error", err)
			}
		}()
		logger.Info("admin endpoints listening", "addr", adminLn.Addr().String())
	}

	logger.Info("forward proxy listening", "addr", ln.Addr().String(), "profile", cfg.Profile, "proxies", pool.UsableCount())
	server := forward.New(switcher.NewTransport(pool, cfg.TransportConfig(logger)), cfg.ForwardOptions(logger))
	if err := server.Serve(ctx, ln); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// check probes the whole pool, printing each row as it finishes so a large list
// shows progress. It returns 1 when nothing passed, or when interrupted.
func check(ctx context.Context, pool *switcher.Pool, concurrency int, stdout io.Writer) int {
	pool.Refresh(ctx)
	const row = "%-44s %-6s %-6s %s\n"
	_, _ = fmt.Fprintf(stdout, row, "PROXY", "HTTP", "HTTPS", "LATENCY")

	alive := 0
	results := pool.Check(ctx, concurrency, func(r switcher.ProbeResult) {
		if r.Alive {
			alive++
		}
		secure := "skip"
		if r.HTTPSChecked {
			secure = passFail(r.HTTPS)
		}
		_, _ = fmt.Fprintf(stdout, row, switcher.RedactURL(r.URL), passFail(r.HTTP), secure, r.Latency.Round(time.Millisecond))
	})

	total := len(pool.Snapshot())
	if ctx.Err() != nil {
		_, _ = fmt.Fprintf(stdout, "\nInterrupted: %d of %d proxies alive, out of %d probed\n", alive, len(results), total)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "\n%d of %d proxies alive\n", alive, len(results))
	if alive == 0 {
		return 1
	}
	return 0
}

func passFail(ok bool) string {
	if ok {
		return "ok"
	}
	return "fail"
}
