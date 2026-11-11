## What this changes

<!-- One or two sentences. Link the issue it fixes, for example "Fixes #12". -->

## Why

<!-- The problem or use case. -->

## Profiles affected

- [ ] `scanner`
- [ ] `scraper`
- [ ] Library (`switcher/`) API
- [ ] None (docs, CI, tooling)

## Checks run

- [ ] `make ci` (or `make test` if Docker isn't available; say which)
- [ ] `make dev-check`, if routing behaviour changed
- [ ] `make lab`, if scanner behaviour changed
- [ ] Tests added or updated
- [ ] Docs or example configs updated

## Checklist

- [ ] Scanner mode still never resends a request that may have reached the target
- [ ] No real proxies, credentials or secrets in code, tests or logs
- [ ] No features for evading detection
