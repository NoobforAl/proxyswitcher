# Contributing to proxyswitcher

Thanks for helping. This guide covers how to set up, what to check before you open a pull request, and what we won't accept.

## Ground rules

- proxyswitcher is for reliability when you test systems **you own or have permission to test**. We don't accept features whose purpose is evading detection, such as fingerprint spoofing, WAF bypass or CAPTCHA solving.
- Don't commit real proxy lists or credentials. `proxyswitcher.yaml`, `personal_proxies.yaml` and `*proxies*.txt` at the repository root are ignored by git for that reason.
- Report security problems privately (see [Security issues](#security-issues)), not in a public issue.

## Setup

You need Go (the version in `go.mod`), `make`, and Docker for `make test-race` and `make lab`.

```sh
make tools        # golangci-lint, gosec, govulncheck
make test         # quick check that everything works
```

On Windows, run `make` from Git Bash.

## Before you open a pull request

Run:

```sh
make fix          # go fix, format, vet, lint --fix, security
make ci           # every check the CI workflow runs
```

`make ci` passing locally means CI should pass too. If you can't run Docker, run `make test` instead of `make test-race`, and say so in the PR.

If your change affects how traffic is routed, also run `make dev-check`. For changes to scanner behaviour, run `make lab` as well (it downloads a few GB of images on the first run).

## Code guidelines

- **Tests:** add or update tests for behaviour changes. Tests use only local fake proxies and must never reach the internet.
- **Scanner mode guarantees:** the guarantees in the README ("What scanner mode guarantees") are a contract. Never resend a request that may have reached the target, and never rewrite what a scanner sent.
- **Public API:** `switcher/` is the public library. Avoid breaking changes there; code under `internal/` can change freely.
- **Secrets in logs:** proxy URLs can hold credentials. Pass URLs and error text through `RedactURL` / `RedactText` in `switcher/redact.go`.
- **Lint suppressions:** `//nolint` must name the linter and give a reason, for example `//nolint:gosec // reason`.
- **Docs:** update `README.md`, `docs/tools.md` or the example configs when you change behaviour or configuration.

## Commits and pull requests

- Keep each PR to one change. Write commit messages in the imperative mood, such as `fix: keep the pinned proxy after a 407`. A conventional prefix (`feat:`, `fix:`, `docs:`, `ci:`, `test:`, `refactor:`) is welcome.
- Fill in the pull request template, including which checks you ran.

## Reporting bugs and requesting features

Use the issue templates. For bugs, include the profile (`scanner` or `scraper`), the tool you used, your config with **credentials removed**, and the relevant log lines.

## Security issues

Use GitHub's [private vulnerability reporting](https://github.com/NoobforAl/proxyswitcher/security/advisories/new) instead of opening an issue.

## License

By contributing, you agree that your contributions are licensed under the [GNU GPL v3.0](LICENSE).
