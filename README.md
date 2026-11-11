# proxyswitcher

Routes traffic through a scored, self-healing pool of proxies and switches to another proxy automatically when one fails. You can use it two ways:

- **Local forward proxy:** run the binary and point any tool at it, such as ZAP, Burp, sqlmap or a crawler.
- **Go library:** plug `switcher.Transport` into an `http.Client`.

Only scan systems you own or have permission to test. Rotation here is for reliability; this tool has no features for evading detection.

## Project layout

```
cmd/proxyswitcher/   the binary: `serve` and `check`
cmd/devstack/        fake local proxies for `make dev`
switcher/            public library: pool, sources, health checks, transport, tunnels
internal/config/     YAML and environment settings for the binary
internal/forward/    the local forward proxy and raw relay
internal/admin/      /healthz and /status
dev/                 sample data for `make dev`
docs/tools.md        setup for each tool, and how each was tested
test/lab/            real scanners in Docker, on a network with no internet access
```

## Quick start

```sh
go build ./cmd/proxyswitcher

cp proxyswitcher.example.yaml proxyswitcher.yaml
cp personal_proxies.example.yaml personal_proxies.yaml   # then add your proxies

./proxyswitcher check                                    # test every proxy
./proxyswitcher serve                                    # listen on 127.0.0.1:8899

curl -x http://127.0.0.1:8899 http://example.com/
```

Both commands read `proxyswitcher.yaml` unless you pass `-config <path>`. To set up a specific tool, see [docs/tools.md](docs/tools.md).

`check` prints each proxy as it finishes, testing HTTP and HTTPS separately. It verifies certificates, so a proxy that intercepts TLS fails. It exits with status 1 if none pass, and `-concurrency N` sets how many run at once (default 10).

## Choosing a profile

Scanners and crawlers need opposite behaviour. If a target answers 403 or 500, a crawler wants another proxy, but for a scanner that answer may be the finding.

| Behaviour | `scanner` (default) | `scraper` |
|---|---|---|
| For | ZAP, Burp, sqlmap, ffuf, nuclei | Scrapy, Playwright, your own crawler |
| Plain `http://` requests | Passed on as the tool sent them | Parsed and normalized by Go's HTTP stack |
| Switches on a target's status code | Never | 403, 429, 5xx, for GET, HEAD and OPTIONS |
| Switches when a proxy fails | Yes | Yes |
| Proxy per site | Pinned until it fails, so logins keep one exit IP | Rotates |
| Slow responses | No limit, so time-based tests work; 10 minute idle timeout | 30s per proxy, 60s across attempts |
| Empty pool at startup | Exits with an error | Warns and keeps running |

Set it with `profile: scraper` in the config file. `serve` logs the active profile at startup.

### What scanner mode guarantees

- **Requests aren't repeated once they may have reached the target.** It tries another proxy only when the target can't have seen the request: the proxy couldn't be reached, or it rejected our credentials with a 407 and a `Proxy-Authenticate` header.
- **Requests reach the upstream as sent:** invalid escapes like `%zz`, malformed headers, a `Host` that differs from the URL, conflicting `Content-Length`, `Transfer-Encoding`, header case and order, custom methods and `ws://` upgrades. Only `Connection` and `Proxy-*` headers change, because those belong to this hop.
- **Responses come back as received.** The one exception is `Connection: close`, which is removed unless the connection really is ending. The relay asks every upstream to close, so the header says nothing about the target, and passing it on makes ZAP report a false buffer overflow.
- **Client connections stay open between requests.** When framing is deliberately ambiguous, as in smuggling tests, the relay doesn't pick a side: it streams what the client sends, then closes the connection.

Limits you should know about:

- **The upstream proxy can still change requests.** Most real proxies normalize requests themselves, or reject malformed ones.
- **Each plain HTTP request opens a new upstream connection.** HTTPS tunnels aren't affected.
- **SOCKS5 and direct routes** rewrite the request line to the origin form the target expects.

## How failures are judged

| Outcome | Examples | Effect |
|---|---|---|
| The proxy's fault | Can't connect, TLS failure with the proxy, 407 | Global penalty right away |
| Unclear | 403, 429, 5xx, refused tunnel, timeout | Decided when the request ends |
| Success | Any other response | Global success |

An unclear failure is decided by what happens next:

- **Another proxy then gets through:** the site blocked the earlier proxies. They're skipped for that site only (`site_cooldown`) and stay usable elsewhere. Rejection by several distinct sites (`global_failure_after_sites`) starts counting globally, so a proxy that fails everywhere is still removed.
- **Every proxy failed:** the site is the likely problem, so no proxy is penalized. You get the site's real response, and it goes into a short `target_backoff` with one attempt per request, so a dead site doesn't multiply traffic.

**Scoring:** personal proxies start at 3 and public ones at 1. The highest score is used first, rotating among ties. A success adds 1 up to `max_score`, and a global failure subtracts 1. Below `blacklist_threshold`, a proxy is skipped for `cooldown`. A proxy is removed until restart when it has more than 10 global failures and at most 1 success, or a success rate of 10% or less after more than 10 attempts.

**Outages:** when every proxy is on cooldown, one is retried every few seconds, and a success brings it straight back. So a short outage doesn't take the pool down for 30 minutes, and failed retries don't count towards removal.

## HTTPS and switching

HTTPS travels in an encrypted `CONNECT` tunnel. In either profile, the forward proxy **can't see a target's 403 or 429 inside it**, and switches only when a proxy can't be reached or refuses the tunnel. Seeing the status would require intercepting TLS, which this tool doesn't do.

The library doesn't have this limit, because it sees HTTPS responses directly.

## Telling a proxy error from a target's answer

Every response proxyswitcher generates itself carries an [RFC 9209](https://www.rfc-editor.org/rfc/rfc9209) header, and a target's response never does:

```
Proxy-Status: proxyswitcher; error=destination_unavailable; details="no proxy available"
```

If your tool reports an unexpected 400, 502, 503 or 508, check for this header before treating it as a finding.

## Readiness checks

Set `admin_listen: "127.0.0.1:8898"` to enable:

- `GET /healthz`: 200 when a proxy is usable, 503 when none is. Use it to wait before starting a scan.
- `GET /status`: the pool's scores and blocks as JSON, with credentials removed.

## Your real IP

By default, proxyswitcher **fails closed**. With no proxy available, the library returns `ErrNoProxy` and the forward proxy answers 503, so nothing goes out directly. Two options change this, and both expose your IP to the target:

- `direct_first`: tries without a proxy first and uses the pool only on failure.
- `fallback_direct`: goes direct when no proxy is available.

## Security notes

- The forward proxy has no client authentication. It refuses a non-loopback `listen` or `admin_listen` address unless you set `allow_remote: true`, because that would expose it to your network.
- **Free public proxies are untrusted.** Their operators can read and alter plain `http://` traffic, so don't send credentials or scan traffic through them.
- Passwords in proxy URLs are removed from logs, errors, `check` output and `/status`. Keep real config files out of version control; `.gitignore` covers the default names.
- A proxy pointing back at this proxyswitcher is dropped from the pool, and a request targeting the listener gets a 508, so a config mistake can't cause a loop. Fetching proxy lists ignores `HTTP_PROXY`, so a shell configured to use this proxy can't make it call itself.

## Configuration

[`proxyswitcher.example.yaml`](proxyswitcher.example.yaml) documents every setting. Unknown keys are errors, so a typo can't silently disable something.

Environment variables override the file:

| Variable | Setting |
|---|---|
| `PROXYSWITCHER_PROFILE` | `profile` |
| `PROXYSWITCHER_LISTEN` | `listen` |
| `PROXYSWITCHER_ALLOW_REMOTE` | `allow_remote` |
| `PROXYSWITCHER_ADMIN_LISTEN` | `admin_listen` |
| `PROXYSWITCHER_LOG_LEVEL` | `log_level` |
| `PROXYSWITCHER_DIRECT_FIRST` | `direct_first` |
| `PROXYSWITCHER_FALLBACK_DIRECT` | `fallback_direct` |
| `PROXYSWITCHER_MAX_ATTEMPTS` | `max_attempts` |
| `PROXYSWITCHER_MAX_CONNECTIONS` | `max_connections` |
| `PROXYSWITCHER_DIAL_TIMEOUT` | `dial_timeout` |
| `PROXYSWITCHER_IDLE_TIMEOUT` | `idle_timeout` |
| `PROXYSWITCHER_RESPONSE_TIMEOUT` | `response_timeout` |
| `PROXYSWITCHER_REQUEST_TIMEOUT` | `request_timeout` |
| `PROXYSWITCHER_COOLDOWN` | `pool.cooldown` |
| `PROXYSWITCHER_REFRESH_INTERVAL` | `pool.refresh_interval` |
| `PROXYSWITCHER_PERSONAL_FILE` | `sources.personal_file` |
| `PROXYSWITCHER_LIST_FILE` | `sources.list_file` |
| `PROXYSWITCHER_PROXYSCRAPE_ENABLED` | `sources.proxyscrape_enabled` |
| `PROXYSWITCHER_DATABAY_ENABLED` | `sources.databay.enabled` |
| `PROXYSWITCHER_DATABAY_BASE_URL` | `sources.databay.base_url` |
| `PROXYSWITCHER_HEALTHCHECK_ENABLED` | `health_check.enabled` |
| `PROXYSWITCHER_HEALTHCHECK_DELAY` | `health_check.delay` |
| `PROXYSWITCHER_HEALTHCHECK_TIMEOUT` | `health_check.timeout` |
| `PROXYSWITCHER_HEALTHCHECK_TARGET_URL` | `health_check.target_url` |
| `DATABAY_API_KEY` | Databay API key (only settable here) |

## Library

```go
import "github.com/NoobforAl/proxyswitcher/switcher"

pool := switcher.NewPool(switcher.PoolConfig{},
	switcher.PersonalFileSource{Path: "personal_proxies.yaml"},
	switcher.StaticSource{Proxies: []string{"203.0.113.10:8080"}},
)
pool.Refresh(ctx)
go pool.Run(ctx) // reloads sources until ctx is cancelled

client := &http.Client{
	Transport: switcher.NewTransport(pool, switcher.TransportConfig{}),
}
resp, err := client.Get("https://example.com/")
if errors.Is(err, switcher.ErrNoProxy) {
	// no proxy is available and direct connections are off
}
```

By default the library switches on 403, 429 and 5xx, and only repeats GET, HEAD and OPTIONS after a request may have reached the target. Set `RetryStatus: []int{}` to never switch on a status, and `StickyHosts: true` to keep one proxy per site. To add a proxy source, implement the `Source` interface. Use `Transport.DialTunnel` for raw TCP connections through the pool.

## Development

| Command | What it does |
|---|---|
| `make ci` | Runs every check the CI workflow runs: tidy, format, `go fix`, vet, lint, race tests, `dev-check`, lab build and security. |
| `make build` | Builds the `proxyswitcher` binary. |
| `make test` | Runs all tests. They use local fake proxies only and don't touch the internet. |
| `make test-race` | Runs all tests with the race detector, in Docker, because it needs a C compiler. |
| `make fix` | Runs `gofix`, `format`, `vet`, `lint-fix` and `security`, in that order. |
| `make gofix` / `format` / `vet` | Runs `go fix`, formats the code, or runs `go vet`. |
| `make lint` / `lint-fix` | Runs golangci-lint, either reporting only or applying its automatic fixes. |
| `make security` | Runs gosec and govulncheck. |
| `make dev` | Runs the proxy on `127.0.0.1:8899` with the sample data in `dev/`, until Ctrl+C. Add `PROFILE=scanner` to try scanner mode. |
| `make dev-check` | Sends the sample requests through both profiles, and exits non-zero if anything behaves wrongly. |
| `make lab` | Runs real scanners in Docker against a fake target. See below. Add `LAB="ffuf sqlmap"` to run only those steps. |
| `make lab-clean` | Stops the lab and removes its containers and network. |
| `make tools` | Installs golangci-lint, gosec and govulncheck. |

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

`make dev` needs no real proxies. It starts fake ones locally: one that blocks everything, two that work, and a sample address with nothing listening. Nothing leaves your machine.

### The lab

`make lab` runs each tool directly and through proxyswitcher against a deliberately weak test site, then compares the findings and the requests the site received. The first run downloads a few GB of Docker images.

It's built so a scan can't reach a real system:

- The Docker network is `internal`, with no route to the internet, and the run stops if a container can reach one.
- The test proxies refuse every host except the lab's target.
- The target is a fake site with test rows in an in-memory database.

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
