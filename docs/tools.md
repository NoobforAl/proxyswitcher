# Using proxyswitcher with other tools

The chain is always: **your tool → proxyswitcher → upstream proxy → target**.

Start proxyswitcher first, then point the tool at `127.0.0.1:8899`. Only scan systems you own or have permission to test.

## Which tools were tested

"Lab tested" means `make lab` ran the real tool directly and through proxyswitcher against a local test site, and confirmed that traffic went through the upstream proxies, the findings matched, and the site received the same requests.

| Tool | Profile | Status |
|---|---|---|
| OWASP ZAP (full scan) | `scanner` | Lab tested: same 7 alerts; 745 requests direct, 748 proxied |
| sqlmap | `scanner` | Lab tested: same injection found; 48 requests each way |
| ffuf, HTTP and HTTPS | `scanner` | Lab tested: same pages found; 35 requests each way |
| nuclei, HTTP and HTTPS | `scanner` | Lab tested: same findings, using the lab's own templates |
| Scrapy | `scraper` | Lab tested: same 6 pages crawled |
| curl | Either | Lab tested |
| Burp Suite | `scanner` | **Not tested.** See the [manual checklist](#burp-suite) |
| Dastardly | n/a | Runs in the lab, but **can't use a proxy** |
| Playwright | `scraper` | **Not tested.** Setting taken from its documentation |

ZAP's small difference in requests is within the variation between its own direct runs.

## Burp Suite

Burp's upstream proxy setting is under **Settings > Network > Connections > Upstream proxy servers**. The exact menu path varies by version, and this one comes from third-party guides.

1. Run proxyswitcher with `profile: scanner`.
2. Add a rule with destination host `*`, proxy host `127.0.0.1` and proxy port `8899`.
3. Leave authentication empty. Your upstream proxies' credentials belong in proxyswitcher's config.

### Manual checklist

Automating Burp isn't practical, so please run this once and treat Burp as untested until you have. Use a target you control.

- [ ] Proxy a browser through Burp and load an HTTPS page. It should load, and a tunnel should appear in the proxyswitcher log.
- [ ] Do the same for a plain `http://` page.
- [ ] In Repeater, send a request with `%zz` in the path and a different `Host` header, over plain HTTP. In proxyswitcher's `/status`, check the proxy's success count rose. Your upstream proxy may still reject the request itself.
- [ ] In Repeater, send a request to a page that returns 500. You should see the 500, and the target's log should show one request.
- [ ] Stop the upstream proxy in use and send another request. It should move to another proxy, and the log should show `switching proxy`.
- [ ] Stop every upstream proxy. Burp should show a 503 with a `Proxy-Status: proxyswitcher` header.

### Dastardly

[Dastardly](https://portswigger.net/burp/dastardly) is PortSwigger's free Docker scanner, built on Burp's engine. It found the lab site's issues in a direct scan, but has no upstream proxy setting, and JVM proxy options had no effect. Its banner says that running it affirms [PortSwigger's terms](https://portswigger.net/burp/dastardly/eula), and `make lab` runs it, so read those before using the lab.

## OWASP ZAP

In the desktop app, use **Options > Network > Connection**, and set the HTTP proxy to `127.0.0.1:8899`. For the Docker scan scripts:

```sh
zap-full-scan.py -t http://target/ -z "-config network.connection.httpProxy.enabled=true \
  -config network.connection.httpProxy.host=127.0.0.1 \
  -config network.connection.httpProxy.port=8899"
```

The lab used these Docker options with ZAP 2.16.1. The desktop menu path wasn't tested.

ZAP also makes its own update and telemetry requests to `cfu.zaproxy.org` and `tel.zaproxy.org`, and these go through your proxies too. Pass `-I` so the scan isn't failed by warnings, and turn off update checks in ZAP's options if you don't want them sent.

## Command-line tools

| Tool | Setting |
|---|---|
| sqlmap | `sqlmap -u "http://target/item?id=1" --proxy=http://127.0.0.1:8899` |
| ffuf | `ffuf -u http://target/FUZZ -w words.txt -x http://127.0.0.1:8899` |
| nuclei | `nuclei -u http://target -proxy http://127.0.0.1:8899` |
| curl | `curl -x http://127.0.0.1:8899 http://target/` |

## Crawlers

Use `profile: scraper`, so 403, 429 and 5xx responses switch to another proxy.

| Tool | Setting |
|---|---|
| Scrapy | `http_proxy=http://127.0.0.1:8899 scrapy crawl myspider` |
| Playwright | `chromium.launch({ proxy: { server: "http://127.0.0.1:8899" } })` |

Over HTTPS, switching only happens when a proxy can't be reached or refuses the tunnel, because the proxy can't see status codes inside it. If you need to switch on HTTPS status codes, use the Go library. Otherwise, have the crawler retry, which opens a new tunnel.

## Common mistakes

| Symptom | Likely cause | Fix |
|---|---|---|
| Unexpected 400, 502, 503 or 508 | proxyswitcher answered, not the target | Look for a `Proxy-Status: proxyswitcher` header |
| `serve` exits with "pool is empty" | No proxies loaded in scanner mode | Check your source paths, or set `require_proxies: false` |
| Crawler keeps getting 403 on plain HTTP | The default `scanner` profile doesn't switch on status | Set `profile: scraper` |
| A 502 saying the request "was not repeated" | The upstream dropped the connection, and the request may have been delivered | Expected in scanner mode. Have the tool retry if that's safe |
| Slow HTTPS on public proxy lists | Hung proxies use up `dial_timeout` one by one | Lower `dial_timeout`, and run `proxyswitcher check` first |
| Scan results differ on plain HTTP | The upstream proxy is normalizing requests | Use a proxy that doesn't, or test over HTTPS, which it can't alter |
| Certificate errors in your tool | An upstream proxy is intercepting TLS | Run `check`, which fails such proxies, and stop using them |
| Tool can't reach proxyswitcher from Docker | It listens on loopback by default | Bind to the container network with `allow_remote: true`, and keep it off public networks |

## Free public proxies

Free proxies are unreliable: in one live test, only about a quarter of a sample responded, and fewer could open HTTPS tunnels. They can also read and alter plain HTTP traffic. **Don't send scan traffic through them.** Besides the risk, scanner mode doesn't repeat requests, so flaky proxies show up as failed requests. Use proxies you control.
