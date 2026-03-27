MODULE = $(shell go list -m)
VERSION ?= $(shell git describe --tags --always --dirty --match=v* 2> /dev/null || echo "1.0.0")
PACKAGES := $(shell go list ./... | grep -v /vendor/)
GOBIN ?= $$(go env GOPATH)/bin
GOLINT := golangci-lint

.PHONY: default
default: test

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: test
test: ## Run all tests
	go test -v -race ./...

.PHONY: test-brainpool
test-brainpool: ## Run brainpool plugin tests
	cd brainpool && go test -v -race ./...

.PHONY: coverage
coverage: ## Generate coverage report
	go test -coverprofile=cover.out -covermode=atomic -coverpkg=./... ./...
	go tool cover -func=cover.out

.PHONY: coverage-html
coverage-html: coverage ## Open coverage report in browser
	go tool cover -html=cover.out -o cover.html

.PHONY: install-go-test-coverage
install-go-test-coverage:
	go install github.com/vladopajic/go-test-coverage/v2@latest

.PHONY: check-coverage
check-coverage: install-go-test-coverage ## Check coverage thresholds
	go test ./... -coverprofile=./cover.out -covermode=atomic -coverpkg=./...
	${GOBIN}/go-test-coverage --config=./.testcoverage.yml

.PHONY: lint
lint: ## Run golangci-lint
	@if command -v $(GOLINT) > /dev/null 2>&1; then \
		$(GOLINT) run ./...; \
	else \
		echo "golangci-lint not installed. Run: make tools"; \
	fi

.PHONY: fmt
fmt: ## Format code
	go fmt ./...
	@if command -v goimports > /dev/null 2>&1; then \
		goimports -w -local $(MODULE) .; \
	fi

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: tidy
tidy: ## Tidy module dependencies
	go mod tidy
	cd brainpool && go mod tidy

.PHONY: clean
clean: ## Remove build artifacts
	go clean
	rm -f cover.out cover.html

.PHONY: tools
tools: ## Install development tools
	go install github.com/golangci-lint/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/vladopajic/go-test-coverage/v2@latest

.PHONY: setup
setup: tools ## Set up development environment (tools + git hooks)
	@echo "Setting up git hooks..."
	@mkdir -p .git/hooks
	@ln -sf ../../scripts/pre-commit.sh .git/hooks/pre-commit
	@chmod +x scripts/pre-commit.sh
	@echo "Running initial checks..."
	@make fmt
	@make vet
	@make test
	@echo "Setup complete!"

.PHONY: gosec
gosec: ## Run security scanner
	gosec ./...

.PHONY: staticcheck
staticcheck: ## Run static analysis
	staticcheck ./...

.PHONY: ci
ci: lint test ## Run CI checks (lint + test)

.PHONY: quick
quick: fmt vet ## Quick pre-commit check (fmt + vet)
