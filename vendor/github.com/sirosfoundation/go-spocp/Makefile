.PHONY: all build test test-verbose coverage clean fmt vet lint help bench bench-long perftest perftest-sizes perftest-large indexperf indexperf-large protocolperf protocolperf-quick

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Binary name
BINARY_NAME=spocp
COVERAGE_FILE=coverage.out
COVERAGE_HTML=coverage.html

# Binary output directory
BIN_DIR=bin

# Server binaries
SERVER_BINARY=$(BIN_DIR)/spocpd
CLIENT_BINARY=$(BIN_DIR)/spocp-client

# Packages
PACKAGES=$(shell $(GOCMD) list ./...)

all: test build ## Run tests and build

build: ## Build the library (verify it compiles)
	@echo "Building..."
	$(GOBUILD) -v ./...

build-server: ## Build spocpd server binary to bin/
	@echo "Building spocpd server..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(SERVER_BINARY) ./cmd/spocpd

build-client: ## Build spocp-client binary to bin/
	@echo "Building spocp-client..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(CLIENT_BINARY) ./cmd/spocp-client

build-tools: build-server build-client ## Build all server tools to bin/

test: ## Run tests
	@echo "Running tests..."
	$(GOTEST) -v -race ./...

test-short: ## Run tests in short mode
	@echo "Running tests (short mode)..."
	$(GOTEST) -short ./...

test-verbose: ## Run tests with verbose output
	@echo "Running tests (verbose)..."
	$(GOTEST) -v -race -count=1 ./...

coverage: ## Generate test coverage report
	@echo "Generating coverage report..."
	$(GOTEST) -race -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	$(GOCMD) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "Coverage report generated: $(COVERAGE_HTML)"

coverage-cli: ## Show test coverage in terminal
	@echo "Generating coverage report..."
	$(GOTEST) -race -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	$(GOCMD) tool cover -func=$(COVERAGE_FILE)

clean: ## Remove build artifacts, coverage reports, and log files
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(COVERAGE_FILE) $(COVERAGE_HTML)
	rm -rf bin/
	rm -f *.log

fmt: ## Format code
	@echo "Formatting code..."
	$(GOFMT) ./...

vet: ## Run go vet
	@echo "Running go vet..."
	$(GOVET) ./...

lint: fmt vet ## Run all linters

tidy: ## Tidy go modules
	@echo "Tidying go modules..."
	$(GOMOD) tidy

check: fmt vet test ## Format, vet, and test

bench: ## Run benchmarks
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

bench-long: ## Run benchmarks with longer duration
	@echo "Running benchmarks (longer)..."
	$(GOTEST) -bench=. -benchmem -benchtime=10s ./...

perftest: ## Run performance testing tool (1000 rules, 10000 queries)
	@echo "Running performance test..."
	$(GOCMD) run cmd/perftest/main.go -rules 1000 -queries 10000

perftest-sizes: ## Run performance tests across multiple ruleset sizes
	@echo "Running performance test (multiple sizes)..."
	$(GOCMD) run cmd/perftest/main.go -sizes -queries 5000

perftest-large: ## Run performance test with large ruleset (50k rules)
	@echo "Running performance test (large)..."
	$(GOCMD) run cmd/perftest/main.go -rules 50000 -queries 1000

indexperf: ## Compare indexed vs non-indexed performance (10k rules)
	@echo "Running index performance comparison..."
	$(GOCMD) run cmd/indexperf/main.go -rules 10000 -queries 10000 -stats

indexperf-large: ## Compare indexed vs non-indexed with large ruleset (50k rules)
	@echo "Running index performance comparison (large)..."
	$(GOCMD) run cmd/indexperf/main.go -rules 50000 -queries 5000 -tags 20 -stats

protocolperf: ## Compare Direct vs TCP vs HTTP/AuthZen performance
	@echo "Running protocol performance comparison..."
	$(GOCMD) run cmd/protocolperf/main.go -rules 1000 -queries 10000

protocolperf-concurrent: ## Compare protocols with concurrent clients
	@echo "Running protocol performance comparison (concurrent)..."
	$(GOCMD) run cmd/protocolperf/main.go -rules 1000 -queries 10000 -concurrent 4

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	$(GOMOD) download

verify: ## Verify dependencies
	@echo "Verifying dependencies..."
	$(GOMOD) verify

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
