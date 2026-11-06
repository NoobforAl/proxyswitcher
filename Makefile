.DEFAULT_GOAL := help

GO_TEST_FLAGS := -count=1 -timeout 180s
RACE_IMAGE    := golang:1.27
PROFILE       ?= scraper

.PHONY: help test test-race fix gofix format vet lint lint-fix security dev dev-check lab lab-clean tools

help:
	@echo "Targets:"
	@echo "  test        run all tests"
	@echo "  test-race   run all tests with the race detector, in Docker (it needs a C compiler)"
	@echo "  fix         gofix + format + vet + lint-fix + security"
	@echo "  gofix       apply 'go fix' modernizations"
	@echo "  format      format the code (gofmt, goimports)"
	@echo "  vet         run go vet"
	@echo "  lint        run golangci-lint, reporting only"
	@echo "  lint-fix    run golangci-lint and apply its automatic fixes"
	@echo "  security    run gosec and govulncheck"
	@echo "  dev         run the proxy on 127.0.0.1:8899 with sample data, until Ctrl+C"
	@echo "              PROFILE=scanner or PROFILE=scraper (default scraper)"
	@echo "  dev-check   run the sample requests for both profiles, and exit non-zero on failure"
	@echo "  lab         run real scanners in Docker, on an isolated network, against a fake target"
	@echo "              LAB="ffuf sqlmap" runs only those steps"
	@echo "  lab-clean   stop the lab and remove its containers and network"
	@echo "  tools       install golangci-lint, gosec and govulncheck"

test:
	go test $(GO_TEST_FLAGS) ./...

# The double slashes stop Git for Windows' shell turning /src into a Windows
# path. Linux treats //src the same as /src.
test-race:
	docker run --rm -v "$(CURDIR)://src:ro" -w //src $(RACE_IMAGE) go test -race $(GO_TEST_FLAGS) ./...

fix: gofix format vet lint-fix security

gofix:
	go fix ./...

format:
	golangci-lint fmt ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

lint-fix:
	golangci-lint run --fix ./...

# test/ holds the lab's fake target, which is vulnerable on purpose.
security:
	gosec -quiet -exclude-dir=test ./...
	govulncheck ./...

dev:
	go run ./cmd/devstack -profile $(PROFILE)

dev-check:
	go run ./cmd/devstack -once

lab:
	sh test/lab/run.sh $(LAB)

lab-clean:
	docker compose -f test/lab/compose.yaml --profile tools down --remove-orphans

tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
