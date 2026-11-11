# CLAUDE.md

Guidance for AI coding agents working in this repository. Read `README.md` for what the project does. Read `CONTRIBUTING.md` for the rules.

## What this is

proxyswitcher is a Go (see `go.mod`) local forward proxy and library. It routes traffic through a scored pool of upstream proxies and switches to another proxy when one fails. It has two profiles with opposite behaviour: `scanner` (the default; never retries a request that may have reached the target) and `scraper` (retries on 403, 429 and 5xx for safe methods).

## Layout

| Path | Role |
|---|---|
| `cmd/proxyswitcher/` | The binary: `serve` and `check` subcommands |
| `cmd/devstack/` | Fake local proxies used by `make dev` and `make dev-check` |
| `switcher/` | **Public library**: pool, sources, health checks, transport, tunnels, redaction |
| `internal/config/` | YAML and environment config, profiles |
| `internal/forward/` | The forward proxy (HTTP and CONNECT) and raw relay |
| `internal/admin/` | `/healthz` and `/status` |
| `dev/` | Sample data for `make dev` (tracked; fake addresses only) |
| `test/lab/` | Separate Go module: Docker lab with real scanners and a **deliberately vulnerable** target |

## Make commands

On Windows, run these from Git Bash. Run `make` or `make help` for the full list.

| Command | Use it when |
|---|---|
| `make test` | After any change. Fast, local fake proxies only, no internet. |
| `make test-race` | Before finishing concurrency-related work. Runs in Docker (`golang:1.27`). |
| `make dev-check` | After changing routing, retries or the forward proxy. Sends sample requests through both profiles and exits non-zero on failure. |
| `make build` | To produce the `proxyswitcher` binary (git ignores it). |
| `make fix` | To auto-fix: `go fix`, format, vet, `golangci-lint --fix`, gosec and govulncheck. |
| `make lint` / `make vet` | Report-only static checks. |
| `make security` | gosec (excludes `test/`) and govulncheck. |
| `make ci` | **Before you say work is done.** Runs everything CI runs: tidy, format, `go fix -diff`, vet, lint, race tests, dev-check, lab build and security. |
| `make dev` | Runs the proxy interactively on `127.0.0.1:8899` until Ctrl+C (`PROFILE=scanner` or `scraper`). Don't use it in non-interactive runs; use `make dev-check` instead. |
| `make lab` | Real scanners in Docker. Slow, and downloads several GB. Run it only when asked, or when scanner behaviour changes (`LAB="ffuf sqlmap"` runs only those steps). |
| `make tools` | Installs golangci-lint, gosec and govulncheck if they're missing. |

To run a single test: `go test -count=1 -run TestName ./switcher/`.

## Rules

- **Scanner-mode guarantees are a contract** (README, "What scanner mode guarantees"). Don't resend a request once it may have reached the target, and don't rewrite plain-HTTP requests in scanner mode. Any change here needs a test.
- **Never log credentials.** Proxy URLs carry `user:pass`. Use `RedactURL` / `RedactText` in `switcher/redact.go`.
- **Tests must not touch the internet.** Use `httptest` or the fake proxies in the existing tests.
- **Keep `switcher/` API-stable.** Put new internals in `internal/`.
- **Lint:** `//nolint` needs a specific linter and a reason (`nolintlint` enforces this). Imports are grouped with `github.com/NoobforAl/proxyswitcher` as the local prefix. `make format` handles this.
- **Don't run gosec on `test/`**, and don't "fix" the lab target's vulnerabilities; they're intentional.
- **Never commit** `proxyswitcher.yaml`, `personal_proxies.yaml` or `*proxies*.txt` at the root. They're git-ignored because they hold real credentials.
- No features for evading detection.

## Known gotchas

- `govulncheck` reports standard-library vulnerabilities for the **local** Go toolchain. If `make security` fails only on a `net/http`-style stdlib advisory, update Go to the "Fixed in" version. CI uses the latest patch release of the version in `go.mod`.
- `test/lab` is its own module. Run `go` commands for it from inside that directory, or use `make lab-build`.
