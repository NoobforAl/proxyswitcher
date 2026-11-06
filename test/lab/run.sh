#!/usr/bin/env bash
# Runs real tools against the lab's fake target, directly and through
# proxyswitcher, and compares the results. See compose.yaml for the isolation.
#
# Usage: run.sh [check ffuf sqlmap nuclei scrapy zap dastardly failover ...]
# With no arguments it runs everything.
set -u
export MSYS_NO_PATHCONV=1 # stop Git for Windows rewriting /data paths
# Under make on Windows, plain sort can resolve to Windows' own sort.exe.
export PATH="/usr/bin:/bin:$PATH"
cd "$(dirname "$0")"
mkdir -p out

PS=http://proxyswitcher:8899
SCRAPER=http://proxyswitcher-scraper:8899
HTTP=http://target:8080
HTTPS=https://target:8443
compose() { docker compose "$@"; }
tools() { compose run --rm -T --no-deps tools "$@"; }
log_summary() { compose exec -T target wget -qO- "http://localhost:8080/__log"; }
log_reset() { compose exec -T target wget -qO- "http://localhost:8080/__reset" >/dev/null; }
RESULTS=out/results.txt
: >"$RESULTS"
FAILED=0

report() { # status, name, details
  printf '%-6s %-34s %s\n' "$1" "$2" "$3" | tee -a "$RESULTS"
  [ "$1" = FAIL ] && FAILED=1
  return 0
}

compare() { # name, direct findings, proxied findings
  if [ "$2" = "$3" ]; then
    report PASS "$1 findings" "direct=[$2] proxied=[$3]"
  else
    report FAIL "$1 findings" "direct=[$2] proxied=[$3]"
  fi
}

compare_log() { # name, direct log, proxied log
  local d p
  d=$(echo "$2" | sed -n 's/.*total=\([0-9]*\).*/\1/p')
  p=$(echo "$3" | sed -n 's/.*total=\([0-9]*\).*/\1/p')
  if [ "$d" = "$p" ]; then
    report PASS "$1 requests at target" "direct: $2 | proxied: $3"
  else
    report FAIL "$1 requests at target" "direct: $2 | proxied: $3"
  fi
}

# How many requests the upstream proxies have relayed. Without this, a tool that
# ignored its proxy setting would look like a pass, since it can reach the target.
hits() { compose logs proxy-a proxy-b --no-log-prefix 2>/dev/null | grep -c 'relay '; }

assert_through() { # name, hits before
  local after
  after=$(hits)
  if [ "$after" -gt "$2" ]; then
    report PASS "$1 went through proxies" "$((after - $2)) relayed"
  else
    report FAIL "$1 went through proxies" "no traffic reached the upstream proxies"
  fi
}

check_isolated() {
  if compose run --rm -T --no-deps tools curl -s -m 5 -o /dev/null http://example.com/; then
    report FAIL "lab isolation" "a container reached the internet; stopping"
    exit 1
  fi
  report PASS "lab isolation" "containers cannot reach the internet"
}

run_check() {
  local out
  out=$(compose run --rm -T --no-deps --entrypoint proxyswitcher proxyswitcher check -config /data/scanner.yaml 2>/dev/null)
  echo "$out" | tail -4
  # The HTTPS probe verifies certificates, so the lab's own self-signed target
  # is reported by the unit tests rather than here.
  report INFO "check command" "$(echo "$out" | tail -1)"
}

run_ffuf() { # scheme label, base url, extra flags
  local direct_log proxied_log direct proxied
  ffuf_cmd() { tools ffuf -s -k -t 10 -mc 200 -w /data/words.txt -u "$2/FUZZ" $1 | sort | tr '\n' ' '; }
  log_reset
  direct=$(ffuf_cmd "" "$2")
  direct_log=$(log_summary)
  log_reset
  local before
  before=$(hits)
  proxied=$(ffuf_cmd "-x $PS" "$2")
  proxied_log=$(log_summary)
  assert_through "ffuf $1" "$before"
  compare "ffuf $1" "$direct" "$proxied"
  compare_log "ffuf $1" "$direct_log" "$proxied_log"
}

run_sqlmap() {
  local direct proxied direct_log proxied_log
  sqlmap_cmd() {
    tools sqlmap -u "$HTTP/item?id=1" --batch --flush-session --technique=B --level=1 --risk=1 --disable-coloring "$@" 2>&1 |
      grep -Ei "Parameter: id|Type: boolean" | sort -u | tr -s ' ' | tr '\n' ';'
  }
  log_reset
  direct=$(sqlmap_cmd)
  direct_log=$(log_summary)
  log_reset
  local before
  before=$(hits)
  proxied=$(sqlmap_cmd --proxy="$PS")
  proxied_log=$(log_summary)
  assert_through sqlmap "$before"
  compare sqlmap "$direct" "$proxied"
  [ -n "$proxied" ] || report FAIL "sqlmap detection" "found nothing through the proxy"
  report INFO "sqlmap requests at target" "direct: $direct_log | proxied: $proxied_log"
}

run_nuclei() { # label, base
  local direct proxied
  nuclei_cmd() {
    compose run --rm -T --no-deps nuclei -t /data/nuclei -u "$2" -duc -ni -silent -nc -or $1 2>/dev/null |
      grep -o 'lab-[a-z-]*' | sort -u | tr '\n' ' '
  }
  direct=$(nuclei_cmd "" "$2")
  local before
  before=$(hits)
  proxied=$(nuclei_cmd "-proxy $PS" "$2")
  assert_through "nuclei $1" "$before"
  compare "nuclei $1" "$direct" "$proxied"
  [ -n "$proxied" ] || report FAIL "nuclei $1 detection" "found nothing through the proxy"
}

run_scrapy() {
  local direct proxied
  scrapy_cmd() {
    tools sh -c "cd /tmp && $1 scrapy runspider /data/spider.py 2>/dev/null" | grep '^crawled' | sort -u | wc -l | tr -d ' '
  }
  direct=$(scrapy_cmd "")
  local before
  before=$(hits)
  proxied=$(scrapy_cmd "http_proxy=$SCRAPER")
  assert_through scrapy "$before"
  compare "scrapy pages" "$direct" "$proxied"
}

run_zap() {
  local direct proxied alerts
  # Reads the alert names and counts out of the report, using the tools image.
  alerts='import json,sys
d=json.load(open(sys.argv[1]))
print(";".join(sorted(a["pluginid"] for s in d.get("site",[]) for a in s.get("alerts",[]))))'
  zap_scan() { # report name, extra ZAP options
    compose run --rm -T --no-deps zap zap-full-scan.py -t "$HTTP/" -m 1 -I -J "$1" ${2:+-z "$2"} >"out/$1.log" 2>&1
    tools python -c "$alerts" "/out/$1"
  }
  log_reset
  direct=$(zap_scan zap-direct.json "")
  local direct_log proxied_log
  direct_log=$(log_summary)
  log_reset
  local before
  before=$(hits)
  proxied=$(zap_scan zap-proxied.json "-config network.connection.httpProxy.enabled=true -config network.connection.httpProxy.host=proxyswitcher -config network.connection.httpProxy.port=8899")
  proxied_log=$(log_summary)
  assert_through zap "$before"
  compare zap "$direct" "$proxied"
  [ -n "$proxied" ] || report FAIL "zap detection" "no alerts through the proxy; see out/zap-proxied.json.log"
  report INFO "zap requests at target" "direct: $direct_log | proxied: $proxied_log"
}

run_dastardly() {
  # Dastardly is built on Burp's scanner. It has no upstream proxy setting, so this
  # is a direct baseline only. See docs/tools.md for testing Burp itself.
  # Running it affirms PortSwigger's terms: https://portswigger.net/burp/dastardly/eula
  log_reset
  compose run --rm -T --no-deps dastardly >out/dastardly-direct.log 2>&1
  # It exits 1 when it finds issues, which is what the weak target should produce.
  local code=$? found
  found=$(grep -c 'Issue Type' out/dastardly-direct.log)
  report INFO "dastardly direct only" "exit=$code issues=$found target: $(log_summary)"
}

run_slow() {
  local result
  result=$(tools curl -s -m 60 -x "$PS" "$HTTP/slow?s=35" -w ' code=%{http_code}')
  case "$result" in
    *"slow answer"*"code=200") report PASS "35s slow target" "answer arrived (scanner mode has no response limit)" ;;
    *) report FAIL "35s slow target" "$result" ;;
  esac
}

run_failover() {
  local before total found switches
  compose up -d proxy-a proxy-b >/dev/null 2>&1
  compose restart proxyswitcher >/dev/null 2>&1
  sleep 3

  # One proxy down at a time, so one always works. Nothing should be lost, apart
  # from requests in flight at the moment a proxy dies, which are reported rather
  # than repeated.
  log_reset
  before=$(compose logs proxyswitcher 2>/dev/null | grep -c "switching proxy")
  (sleep 3; compose stop -t 0 proxy-a >/dev/null 2>&1; sleep 3; compose start proxy-a >/dev/null 2>&1; sleep 3; compose stop -t 0 proxy-b >/dev/null 2>&1) &
  found=$(tools sh -c "for i in \$(seq 1 40); do cat /data/words.txt; done > /tmp/w.txt; ffuf -s -k -t 5 -p 0.05 -mc 200 -w /tmp/w.txt:FUZZ -u $HTTP/FUZZ -x $PS" | sort -u | tr '\n' ' ')
  wait
  total=$(log_summary | sed -n 's/.*total=\([0-9]*\).*/\1/p')
  switches=$(($(compose logs proxyswitcher 2>/dev/null | grep -c "switching proxy") - before))
  if [ "$total" -ge 1390 ] && [ "$switches" -gt 0 ] && [ "$found" = "about admin backup login secret " ]; then
    report PASS "failover, one proxy down" "$total of 1400 reached the target, $switches switches, found=[$found]"
  else
    report FAIL "failover, one proxy down" "$total of 1400 reached the target, $switches switches, found=[$found]"
  fi
  compose start proxy-b >/dev/null 2>&1

  # Every proxy down, then back. The pool must recover in seconds, not after the
  # 30 minute cooldown.
  compose stop -t 0 proxy-a proxy-b >/dev/null 2>&1
  tools sh -c "for i in 1 2 3 4 5 6; do curl -s -m 5 -o /dev/null -x $PS $HTTP/; curl -s -m 5 -o /dev/null -k -x $PS $HTTPS/; done"
  local during
  during=$(tools curl -s -m 5 -D - -o /dev/null -x "$PS" "$HTTP/" | tr -d '\r' | grep -i '^proxy-status' | cut -c1-60)
  compose start proxy-a proxy-b >/dev/null 2>&1
  sleep 8
  found=$(tools curl -s -m 10 -o /dev/null -w '%{http_code}' -x "$PS" "$HTTP/about")
  if [ "$found" = 200 ]; then
    report PASS "recovery after full outage" "works again within seconds; during the outage: [$during]"
  else
    report FAIL "recovery after full outage" "status $found after proxies returned; during the outage: [$during]"
  fi
}

compose build >/dev/null 2>&1 || { echo "lab build failed"; compose build; exit 1; }
compose build tools >/dev/null 2>&1 || { echo "tools build failed"; compose build tools; exit 1; }
compose up -d target proxy-a proxy-b proxyswitcher proxyswitcher-scraper >/dev/null 2>&1
sleep 3
check_isolated

STEPS=${*:-check ffuf sqlmap nuclei scrapy slow failover zap dastardly}
for step in $STEPS; do
  echo "--- $step"
  case "$step" in
    check) run_check ;;
    ffuf) run_ffuf http "$HTTP"; run_ffuf https "$HTTPS" ;;
    sqlmap) run_sqlmap ;;
    nuclei) run_nuclei http "$HTTP"; run_nuclei https "$HTTPS" ;;
    scrapy) run_scrapy ;;
    slow) run_slow ;;
    zap) run_zap ;;
    dastardly) run_dastardly ;;
    failover) run_failover ;;
    *) echo "unknown step: $step"; FAILED=1 ;;
  esac
done

echo
echo "=== results"
cat "$RESULTS"
exit "$FAILED"
