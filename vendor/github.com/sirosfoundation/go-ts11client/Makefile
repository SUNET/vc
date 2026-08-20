MODULE = $(shell go list -m)
VERSION ?= $(shell git describe --tags --always --dirty --match=v* 2> /dev/null || echo "0.0.0")
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

.PHONY: coverage
coverage: ## Generate coverage report
	go test -coverprofile=cover.out -covermode=atomic -coverpkg=./... ./...
	go tool cover -func=cover.out

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

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: tidy
tidy: ## Tidy module dependencies
	go mod tidy

.PHONY: clean
clean: ## Remove build artifacts
	go clean
	rm -f cover.out cover.html

.PHONY: tools
tools: ## Install development tools
	go install github.com/golangci-lint/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
