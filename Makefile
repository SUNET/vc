# ==============================================================================
# Configuration Variables
# ==============================================================================

NAME                    := vc
VERSION                 ?= latest
NEWTAG                  ?= $(VERSION)
CURRENT_BRANCH          := $(shell git rev-parse --abbrev-ref HEAD)
W3C_TEST_PORT           ?= 8888
W3C_TEST_SUITE_DIR      := /tmp/w3c-test-suite

# Build Configuration
LDFLAGS                 := -ldflags "-w -s --extldflags '-static'"
LDFLAGS_DYNAMIC         := -ldflags "-w -s"
CGO_ENABLED_STATIC      := CGO_ENABLED=0
CGO_ENABLED_DYNAMIC     := CGO_ENABLED=1
BUILD_OS                := linux
BUILD_ARCH              := amd64
BUILD_FLAGS             := -v

# Services Configuration
SERVICES                := verifier registry mockas apigw issuer ui
WEB_SERVICES            := verifier ui
WORKER_SERVICES         := registry mockas apigw issuer

# Docker Configuration
DOCKER_REGISTRY         := docker.sunet.se/iam_vc
DOCKER_BUILD_FLAGS      := 
GO_BUILD_TAGS           ?=

# Build Tags for Optional Features
SAML_TAG                := saml
OIDCRP_TAG              := oidcrp
PKCS11_TAG              := pkcs11
VC20_TAG                := vc20
ALL_TAGS                := $(SAML_TAG),$(OIDCRP_TAG)

# Service Build Configuration (service -> static/dynamic, tags)
# Format: service_name:cgo_mode:build_tags
BUILD_CONFIGS           := \
	verifier:static: \
	registry:static: \
	mockas:static: \
	apigw:static: \
	issuer:static: \
	ui:static: \
	vc20-test-server:static:$(VC20_TAG)

# ==============================================================================
# Phony Targets Declaration
# ==============================================================================

.PHONY: help pki pki-clean test test-env \
	build build-% \
	docker-build docker-build-% docker-push docker-push-% docker-push-apigw-saml docker-push-apigw-oidcrp docker-push-apigw-all docker-push-issuer-hsm docker-tag docker-tag-% docker-pull docker-archive \
	start stop restart clean_docker_images \
	proto proto-% swagger swagger-% swagger-fmt \
	check-protoc diagram install-tools clean-apt-cache vscode \
	gosec staticcheck vulncheck \
	test-saml test-oidcrp test-vc20 test-pkcs11 test-all-tags \
	test-wallet test-wallet-vci test-wallet-vp test-wallet-e2e test-wallet-stack \
	test-wallet-stack-vci test-wallet-stack-vp test-wallet-stack-e2e test-wallet-stack-security \
	test-workflows test-workflows-run \
	w3c-test create-w3c-test-suite run-w3c-test \
	release check_current_branch ci_build

# ==============================================================================
# Help Target
# ==============================================================================

help: ## Show this help message
	$(info Usage: make [target] [VERSION=x.x.x])
	$(info )
	$(info Common Targets:)
	$(info   build                 - Build all services)
	$(info   build-SERVICE         - Build specific service (e.g., make build-apigw))
	$(info   test                  - Run all tests)
	$(info   docker-build          - Build all Docker images)
	$(info   docker-push           - Push all Docker images)
	$(info   start                 - Start services with docker-compose)
	$(info   stop                  - Stop services)
	$(info )
	$(info Services: $(SERVICES))
	$(info )
	$(info Optional Build Features:)
	$(info   make build-apigw-saml     - Build apigw with SAML support)
	$(info   make build-apigw-oidcrp   - Build apigw with OIDC RP support)
	$(info   make build-apigw-all      - Build apigw with all features)
	$(info   make build-issuer-hsm     - Build issuer with PKCS#11 HSM support)
	$(info )
	$(info Environment Variables:)
	$(info   VERSION               - Docker image version (default: latest))
	$(info   NEWTAG                - Target tag for docker-tag operations (default: VERSION))
	$(info   W3C_TEST_PORT         - W3C test server port (default: 8888))
	@:

# ==============================================================================
# Helper Functions
# ==============================================================================

# Get CGO setting for a service: $(call get-cgo,service)
define get-cgo
$(if $(filter static,$(word 2,$(subst :, ,$(filter $1:%,$(BUILD_CONFIGS))))),$(CGO_ENABLED_STATIC),$(CGO_ENABLED_DYNAMIC))
endef

# Get build tags for a service: $(call get-tags,service)
define get-tags
$(word 3,$(subst :, ,$(filter $1:%,$(BUILD_CONFIGS))))
endef

# Get LDFLAGS for a service: $(call get-ldflags,service)
define get-ldflags
$(if $(filter static,$(word 2,$(subst :, ,$(filter $1:%,$(BUILD_CONFIGS))))),$(LDFLAGS),$(LDFLAGS_DYNAMIC))
endef

# Docker image tag: $(call docker-tag,service,version)
define docker-tag
$(DOCKER_REGISTRY)/$1:$2
endef

# ==============================================================================
# PKI Management
# ==============================================================================


pki: ## Set up PKI infrastructure
	$(info Setting up PKI)
	./developer_tools/scripts/create_pki.sh

pki-clean: ## Clean PKI material
	$(info Cleaning PKI material)
	rm -rf developer_tools/pki

# ==============================================================================
# Testing Targets
# ==============================================================================

test: $(addprefix test-,$(SERVICES)) ## Run all service tests

# Generate test-SERVICE targets dynamically
define TEST_TEMPLATE
test-$(1): ## Test $(1) service
	$$(info Testing $(1))
	go test -v ./cmd/$(1)/... ./internal/$(1)/...

endef

$(foreach service,$(SERVICES),$(eval $(call TEST_TEMPLATE,$(service))))

test-env: ## Set up test environment
	$(info Setting up test environment)
	sudo apt-get update && sudo apt-get install -y softhsm2 opensc

# Test targets with build tags
test-saml: ## Test with SAML build tag
	$(info Testing with SAML build tag)
	go test -tags $(SAML_TAG) -v ./pkg/saml/... ./internal/apigw/...

test-oidcrp: ## Test with OIDC RP build tag
	$(info Testing with OIDC RP build tag)
	go test -tags $(OIDCRP_TAG) -v ./pkg/oidcrp/... ./internal/apigw/...

test-vc20: ## Test with VC 2.0 build tag
	$(info Testing with VC 2.0 build tag)
	go test -tags $(VC20_TAG) -v ./pkg/vc20/... ./pkg/authzen/... ./pkg/keyresolver/...

test-pkcs11: ## Test with PKCS#11 build tag
	$(info Testing with PKCS#11 build tag)
	go test -tags $(PKCS11_TAG) -v ./pkg/signing/...

test-all-tags: ## Test with all build tags
	$(info Testing with all build tags)
	go test -tags "$(SAML_TAG),$(OIDCRP_TAG),$(VC20_TAG),$(PKCS11_TAG)" -v ./...

# DIDComm v2.1 Test targets
test-didcomm: ## Test DIDComm v2.1 implementation
	$(info Testing DIDComm v2.1 implementation)
	go test -tags "didcomm,$(VC20_TAG)" -v ./pkg/didcomm/...

test-didcomm-interop: ## Run DIDComm interoperability tests
	$(info Running DIDComm interoperability tests)
	go test -tags "didcomm,$(VC20_TAG),didcomm_interop" -v ./test/didcomm_interop/...

test-didcomm-all: ## Run all DIDComm tests including interop
	$(info Running all DIDComm tests including interop)
	go test -tags "didcomm,$(VC20_TAG),didcomm_interop" -v ./pkg/didcomm/... ./test/didcomm_interop/...

# Wallet Test targets
test-wallet: test-wallet-vci test-wallet-vp test-wallet-e2e ## Run all wallet mock tests

test-wallet-vci: ## Run wallet VCI mock tests
	$(info Testing wallet VCI flows)
	go test -v -count=1 -run 'TestVCI' ./internal/wallet/integration/...

test-wallet-vp: ## Run wallet VP mock tests
	$(info Testing wallet VP flows)
	go test -v -count=1 -run 'TestVP' ./internal/wallet/integration/...

test-wallet-e2e: ## Run wallet end-to-end mock tests (VCI then VP)
	$(info Testing wallet end-to-end flows)
	go test -v -count=1 -run 'TestEndToEnd' ./internal/wallet/integration/...

test-wallet-stack: ## Run all wallet stack tests (requires: docker compose up)
	$(info Testing wallet against live stack — requires: docker compose up)
	go test -v -tags stack -count=1 -timeout 180s ./internal/wallet/integration/...

test-wallet-stack-vci: ## Run wallet stack VCI tests (happy path + negative)
	$(info Testing wallet stack VCI flows)
	go test -v -tags stack -count=1 -timeout 180s -run 'TestStack_VCI' ./internal/wallet/integration/...

test-wallet-stack-vp: ## Run wallet stack VP tests
	$(info Testing wallet stack VP flows)
	go test -v -tags stack -count=1 -timeout 180s -run 'TestStack_VP' ./internal/wallet/integration/...

test-wallet-stack-e2e: ## Run wallet stack end-to-end test (VCI then VP)
	$(info Testing wallet stack E2E flow)
	go test -v -tags stack -count=1 -timeout 180s -run 'TestStack_E2E' ./internal/wallet/integration/...

test-wallet-stack-security: ## Run wallet stack security/negative tests (DPoP, PKCE, replay)
	$(info Testing wallet stack security — DPoP, PKCE, replay)
	go test -v -tags stack -count=1 -timeout 180s -run 'TestStack_VCI_(PAR_|Token_|Credential_)' ./internal/wallet/integration/...

# ==============================================================================
# Code Quality & Security
# ==============================================================================

gosec: ## Run gosec security scanner
	$(info Running gosec)
	gosec -color -tests -tags $(VC20_TAG) -exclude-dir=internal/gen ./...

staticcheck: ## Run staticcheck linter
	$(info Running staticcheck)
	staticcheck ./...

vulncheck: ## Run vulnerability checker
	$(info Running vulncheck)
	govulncheck -scan package -tags $(VC20_TAG) ./...

# ==============================================================================
# Docker Compose Operations
# ==============================================================================

start: ## Start services with docker-compose
	$(info Starting services)
	docker compose -f docker-compose.yaml up -d --remove-orphans

stop: ## Stop services
	$(info Stopping VC)
	docker compose -f docker-compose.yaml rm -s -f

restart: stop start ## Restart services

# ==============================================================================
# Build Targets
# ==============================================================================

build: proto $(addprefix build-,$(SERVICES)) build-vc20-test-server ## Build all services

# Generate standard build targets dynamically
define BUILD_TEMPLATE
build-$(1): ## Build $(1) service
	$$(info Building $(1))
	$$(call get-cgo,$(1)) GOOS=$$(BUILD_OS) GOARCH=$$(BUILD_ARCH) go build \
		$$(if $$(call get-tags,$(1)),-tags "$$(call get-tags,$(1))") \
		$$(BUILD_FLAGS) -o ./bin/$$(NAME)_$(1) \
		$$(call get-ldflags,$(1)) ./cmd/$(1)/

endef

$(foreach service,$(SERVICES),$(eval $(call BUILD_TEMPLATE,$(service))))

build-vc20-test-server: ## Build VC 2.0 test server
	$(info Building vc20-test-server)
	$(CGO_ENABLED_STATIC) GOOS=$(BUILD_OS) GOARCH=$(BUILD_ARCH) go build \
		-tags $(VC20_TAG) $(BUILD_FLAGS) -o ./bin/$(NAME)_vc20-test-server \
		$(LDFLAGS) ./cmd/vc20-test-server/

build-wallet: ## Build wallet test tool
	$(info Building wallet)
	$(CGO_ENABLED_STATIC) GOOS=$(BUILD_OS) GOARCH=$(BUILD_ARCH) go build \
		$(BUILD_FLAGS) -o ./bin/$(NAME)_wallet \
		$(LDFLAGS) ./cmd/wallet/

docker-build-wallet: ## Build Docker image for wallet test tool
	$(info Docker Building wallet with tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=wallet \
		--tag $(call docker-tag,wallet,$(VERSION)) \
		--file dockerfiles/wallet .

# ==============================================================================
# Optional Feature Builds (with build tags)
# ==============================================================================

build-issuer-hsm: ## Build issuer with PKCS#11 HSM support
	$(info Building issuer with PKCS#11 HSM support)
	$(CGO_ENABLED_DYNAMIC) GOOS=$(BUILD_OS) GOARCH=$(BUILD_ARCH) go build \
		-tags $(PKCS11_TAG) $(BUILD_FLAGS) -o ./bin/$(NAME)_issuer-hsm \
		$(LDFLAGS_DYNAMIC) ./cmd/issuer/

build-apigw-saml: ## Build apigw with SAML support
	$(info Building apigw with SAML support)
	$(CGO_ENABLED_STATIC) GOOS=$(BUILD_OS) GOARCH=$(BUILD_ARCH) go build \
		-tags $(SAML_TAG) $(BUILD_FLAGS) -o ./bin/$(NAME)_apigw-saml \
		$(LDFLAGS) ./cmd/apigw/

build-apigw-oidcrp: ## Build apigw with OIDC RP support
	$(info Building apigw with OIDC RP support)
	$(CGO_ENABLED_STATIC) GOOS=$(BUILD_OS) GOARCH=$(BUILD_ARCH) go build \
		-tags $(OIDCRP_TAG) $(BUILD_FLAGS) -o ./bin/$(NAME)_apigw-oidcrp \
		$(LDFLAGS) ./cmd/apigw/

build-apigw-all: ## Build apigw with all optional features
	$(info Building apigw with all optional features - SAML and OIDC RP)
	$(CGO_ENABLED_STATIC) GOOS=$(BUILD_OS) GOARCH=$(BUILD_ARCH) go build \
		-tags "$(ALL_TAGS)" $(BUILD_FLAGS) -o ./bin/$(NAME)_apigw-all \
		$(LDFLAGS) ./cmd/apigw/

# ==============================================================================
# Docker Build Targets
# ==============================================================================

docker-build: $(addprefix docker-build-,$(SERVICES)) ## Build all Docker images

# Generate docker-build targets for web workers
define DOCKER_BUILD_WEB_TEMPLATE
docker-build-$(1): ## Build Docker image for $(1)
	$$(info Docker Building $(1) with tag: $$(VERSION))
	docker build --build-arg SERVICE_NAME=$(1) \
		$$(if $$(GO_BUILD_TAGS),--build-arg GO_BUILD_TAGS=$$(GO_BUILD_TAGS)) \
		--tag $$(call docker-tag,$(1),$$(VERSION)) \
		--file dockerfiles/web_worker .

endef

$(foreach service,$(WEB_SERVICES),$(eval $(call DOCKER_BUILD_WEB_TEMPLATE,$(service))))

# Generate docker-build targets for workers
define DOCKER_BUILD_WORKER_TEMPLATE
docker-build-$(1): ## Build Docker image for $(1)
	$$(info Docker Building $(1) with tag: $$(VERSION))
	docker build --build-arg SERVICE_NAME=$(1) \
		$$(if $$(filter apigw,$(1)),--build-arg BUILDTAG=$$(VERSION)) \
		$$(if $$(GO_BUILD_TAGS),--build-arg GO_BUILD_TAGS=$$(GO_BUILD_TAGS)) \
		--tag $$(call docker-tag,$(1),$$(VERSION)) \
		--file dockerfiles/worker .

endef

$(foreach service,$(WORKER_SERVICES),$(eval $(call DOCKER_BUILD_WORKER_TEMPLATE,$(service))))

# Docker builds with optional features
docker-build-apigw-saml: ## Build apigw Docker image with SAML support
	$(info Docker building apigw with SAML support, tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=apigw --build-arg BUILDTAG=$(VERSION) \
		--build-arg GO_BUILD_TAGS=$(SAML_TAG) \
		--tag $(call docker-tag,apigw-saml,$(VERSION)) \
		--file dockerfiles/worker .

docker-build-apigw-oidcrp: ## Build apigw Docker image with OIDC RP support
	$(info Docker building apigw with OIDC RP support, tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=apigw --build-arg BUILDTAG=$(VERSION) \
		--build-arg GO_BUILD_TAGS=$(OIDCRP_TAG) \
		--tag $(call docker-tag,apigw-oidcrp,$(VERSION)) \
		--file dockerfiles/worker .

docker-build-apigw-all: ## Build apigw Docker image with all features
	$(info Docker building apigw with all features - SAML and OIDC RP, tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=apigw --build-arg BUILDTAG=$(VERSION) \
		--build-arg GO_BUILD_TAGS="$(ALL_TAGS)" \
		--tag $(call docker-tag,apigw-full,$(VERSION)) \
		--file dockerfiles/worker .

docker-build-issuer-hsm: ## Build issuer Docker image with PKCS#11 HSM support
	$(info Docker building issuer with PKCS#11 HSM support, tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=issuer --build-arg BUILDTAG=$(VERSION) \
		--build-arg GO_BUILD_TAGS=$(PKCS11_TAG) \
		--tag $(call docker-tag,issuer-hsm,$(VERSION)) \
		--file dockerfiles/worker .

docker-build-gobuild: ## Build gobuild Docker image
	$(info Docker Building gobuild with tag: $(VERSION))
	docker build --tag $(call docker-tag,gobuild,$(VERSION)) --file dockerfiles/gobuild .

# ==============================================================================
# Docker Push Targets
# ==============================================================================

docker-push: $(addprefix docker-push-,$(SERVICES)) ## Push all Docker images

# Generate docker-push targets dynamically
define DOCKER_PUSH_TEMPLATE
docker-push-$(1): ## Push Docker image for $(1)
	$$(info Pushing docker image $(1))
	docker push $$(call docker-tag,$(1),$$(VERSION))

endef

$(foreach service,$(SERVICES),$(eval $(call DOCKER_PUSH_TEMPLATE,$(service))))

# Push targets for optional feature builds
docker-push-apigw-saml: ## Push apigw Docker image with SAML support
	$(info Pushing docker image apigw-saml)
	docker push $(call docker-tag,apigw-saml,$(VERSION))

docker-push-apigw-oidcrp: ## Push apigw Docker image with OIDC RP support
	$(info Pushing docker image apigw-oidcrp)
	docker push $(call docker-tag,apigw-oidcrp,$(VERSION))

docker-push-apigw-all: ## Push apigw Docker image with all features
	$(info Pushing docker image apigw-full)
	docker push $(call docker-tag,apigw-full,$(VERSION))

docker-push-issuer-hsm: ## Push issuer Docker image with PKCS#11 HSM support
	$(info Pushing docker image issuer-hsm)
	docker push $(call docker-tag,issuer-hsm,$(VERSION))

docker-push-gobuild: ## Push gobuild Docker image
	$(info Pushing docker image gobuild)
	docker push $(call docker-tag,gobuild,$(VERSION))

# ==============================================================================
# Docker Tag Targets
# ==============================================================================

docker-tag: $(addprefix docker-tag-,$(SERVICES)) ## Tag all Docker images

# Generate docker-tag targets dynamically
define DOCKER_TAG_TEMPLATE
docker-tag-$(1): ## Tag Docker image for $(1)
	$$(info Tagging docker image $(1))
	docker tag $$(call docker-tag,$(1),$$(VERSION)) $$(call docker-tag,$(1),$$(NEWTAG))

endef

$(foreach service,$(SERVICES),$(eval $(call DOCKER_TAG_TEMPLATE,$(service))))

# ==============================================================================
# Docker Utilities
# ==============================================================================

docker-pull: ## Pull all Docker images
	$(info Pulling docker images)
	$(foreach service,$(SERVICES),docker pull $(call docker-tag,$(service),$(VERSION));)

docker-archive: ## Create Docker archive
	docker save --output docker_archives/vc_$(VERSION).tar \
		$(call docker-tag,verifier,$(VERSION)) \
		$(call docker-tag,registry,$(VERSION))

clean_docker_images: ## Clean Docker images
	$(info Cleaning docker images)
	$(foreach service,$(SERVICES),docker rmi $(call docker-tag,$(service),$(VERSION)) -f;)

# ==============================================================================
# Protocol Buffers
# ==============================================================================

check-protoc: ## Check if protoc is installed
	@which protoc > /dev/null || ( \
		$(info ) \
		&& $(error protoc not installed. Install via: apt-get install protobuf-compiler (Ubuntu/Debian) or brew install protobuf (macOS) or download from https://github.com/protocolbuffers/protobuf/releases. Then install Go plugins: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest))
	@protoc --version

proto: proto-status proto-registry proto-issuer ## Generate all protobuf files

PROTO_OPTS := --proto_path=./proto/ --go-grpc_opt=module=vc --go-grpc_out=. --go_opt=module=vc --go_out=.

proto-registry: ## Generate registry protobuf
	protoc $(PROTO_OPTS) ./proto/v1-registry.proto

proto-status: ## Generate status protobuf
	protoc $(PROTO_OPTS) ./proto/v1-status-model.proto

proto-issuer: ## Generate issuer protobuf
	protoc $(PROTO_OPTS) ./proto/v1-issuer.proto

# ==============================================================================
# Swagger Documentation
# ==============================================================================

swagger: swagger-registry swagger-verifier swagger-apigw swagger-issuer swagger-fmt ## Generate all Swagger docs

swagger-fmt: ## Format Swagger annotations
	swag fmt

SWAGGER_OPTS := --parseDependency --packageName docs

swagger-registry: ## Generate registry Swagger docs
	swag init -d internal/registry/apiv1/ -g client.go --output docs/registry $(SWAGGER_OPTS)

swagger-verifier: ## Generate verifier Swagger docs
	swag init -d internal/verifier/apiv1/ -g client.go --output docs/verifier $(SWAGGER_OPTS)

swagger-apigw: ## Generate apigw Swagger docs
	swag init -d internal/apigw/apiv1/ -g client.go --output docs/apigw $(SWAGGER_OPTS)

swagger-issuer: ## Generate issuer Swagger docs
	swag init -d internal/issuer/apiv1/ -g client.go --output docs/issuer $(SWAGGER_OPTS)

# ==============================================================================
# W3C Test Suite
# ==============================================================================

create-w3c-test-suite: ## Create W3C VC 2.0 test suite
	$(info Creating W3C test suite in $(W3C_TEST_SUITE_DIR))
	rm -rf $(W3C_TEST_SUITE_DIR)
	mkdir -p $(W3C_TEST_SUITE_DIR)
	cd $(W3C_TEST_SUITE_DIR) && \
	git clone https://github.com/w3c/vc-data-model-2.0-test-suite.git . && \
	npm install
	./scripts/gen-w3c-config.sh $(W3C_TEST_PORT)

run-w3c-test: build-vc20-test-server ## Run W3C test suite
	$(info Starting test server on port $(W3C_TEST_PORT))
	./bin/$(NAME)_vc20-test-server -port $(W3C_TEST_PORT)&
	$(info Running W3C test suite against server on port $(W3C_TEST_PORT))
	$(info Logs will be saved to /tmp/w3c-test.log)
	cd $(W3C_TEST_SUITE_DIR) && \
	SERVER_URL=http://localhost:$(W3C_TEST_PORT) npm test 2>&1 | tee /tmp/w3c-test.log ; \
	curl -s http://localhost:$(W3C_TEST_PORT)/stop 2>/dev/null || true ; \
	sleep 1
	$(info Test results saved to /tmp/w3c-test.log)
	$(info )
	$(info Test Summary:)
	$(info ============)
	$(info $$(grep -c "✓" /tmp/w3c-test.log 2>/dev/null || printf "0") passing tests)
	$(info $$(grep -c "❌" /tmp/w3c-test.log 2>/dev/null || printf "0") failing tests)

w3c-test: build-vc20-test-server ## Run W3C test suite (managed)
	$(info Running W3C test suite)
	$(info Stopping any existing server...)
	-@killall $(NAME)_vc20-test-server 2>/dev/null
	$(info Starting server...)
	@./bin/$(NAME)_vc20-test-server > server.log 2>&1 & printf "%s\n" "$$!" > server.pid
	@sleep 2
	$(info Running tests...)
	-@cd $(W3C_TEST_SUITE_DIR) && SERVER_URL=http://localhost:$(W3C_TEST_PORT) npm test > /tmp/w3c-test.log 2>&1
	$(info Stopping server...)
	-@kill $$(cat server.pid) 2>/dev/null
	-@rm -f server.pid
	$(info Test results saved to /tmp/w3c-test.log)
	$(info Summary:)
	$(info $$(grep -c '✓' /tmp/w3c-test.log 2>/dev/null || printf '0') passing tests)
	$(info $$(grep -c '❌' /tmp/w3c-test.log 2>/dev/null || printf '0') failing tests)

# ==============================================================================
# Development Tools
# ==============================================================================

diagram: ## Generate PlantUML diagrams
	plantuml docs/diagrams/*.puml

build-gen-config-docs: ## Build gen_config_docs tool
	$(info Building gen_config_docs)
	$(CGO_ENABLED_STATIC) go build $(BUILD_FLAGS) -o ./bin/gen_config_docs ./developer_tools/scripts/gen_config_docs/

gen-config-docs: build-gen-config-docs ## Generate configuration reference documentation
	$(info Generating docs/CONFIGURATION.md)
	./bin/gen_config_docs

install-tools: ## Install required development tools
	$(info Installing from apt)
	apt-get update && apt-get install -y \
		protobuf-compiler \
		netcat-openbsd
	$(info Installing from go)
	go install github.com/swaggo/swag/cmd/swag@latest && \
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

clean-apt-cache: ## Clean apt cache
	$(info Cleaning apt cache)
	rm -rf /var/lib/apt/lists/*

vscode: test-env ## Set up VS Code development environment
	$(info Installing APT packages)
	sudo apt-get update && sudo apt-get install -y \
		protobuf-compiler \
		netcat-openbsd \
		plantuml
	$(info Installing act for local GitHub Actions testing)
	curl -sfL https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash -s -- -b /usr/local/bin
	$(info Installing go packages)
	go install github.com/swaggo/swag/cmd/swag@latest && \
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest && \
	go install golang.org/x/tools/cmd/deadcode@latest && \
	go install github.com/securego/gosec/v2/cmd/gosec@latest && \
	go install golang.org/x/vuln/cmd/govulncheck@latest && \
	go install honnef.co/go/tools/cmd/staticcheck@latest

# ==============================================================================
# GitHub Actions Testing
# ==============================================================================

test-workflows: ## Test all GitHub Actions workflows locally (dry run)
	$(info Testing all GitHub Actions workflows locally with act)
	$(file >/tmp/act-pr-event.json,{"action": "closed", "pull_request": {"merged": true}})
	act -l
	$(info --- Running pull_request workflow (dry run) ---)
	act pull_request -e /tmp/act-pr-event.json -n
	@rm -f /tmp/act-pr-event.json

test-workflows-run: ## Run all GitHub Actions workflows locally
	$(info Running all GitHub Actions workflows locally with act)
	$(file >/tmp/act-pr-event.json,{"action": "closed", "pull_request": {"merged": true}})
	act pull_request -e /tmp/act-pr-event.json
	@rm -f /tmp/act-pr-event.json

# ==============================================================================
# Release Management
# ==============================================================================

VERSION_FILE            := VERSION
RELEASE_VERSION         := $(shell cat $(VERSION_FILE) 2>/dev/null | tr -d '[:space:]')

check_current_branch: ## Verify current branch is main
	$(info Current branch: $(CURRENT_BRANCH))
ifeq ($(CURRENT_BRANCH),main)
	$(info On main branch)
else
	$(error Not on main branch)
endif

get_release-tag: ## Show current release version from VERSION file
	@echo "$(RELEASE_VERSION)"

release: check_current_branch ## Create and push a git tag from VERSION file
	$(info Release version: v$(RELEASE_VERSION))
	git tag -a v$(RELEASE_VERSION) -m "Release v$(RELEASE_VERSION)"
	git push origin v$(RELEASE_VERSION)
	$(info Release v$(RELEASE_VERSION) tagged — Jenkins will build and push Docker images)

ci_build: ## CI build: vanilla + HSM Docker images (used by Jenkins)
	$(info CI Build: VERSION=$(VERSION))
	make docker-build VERSION=$(VERSION)
	make docker-push VERSION=$(VERSION)
	make docker-build VERSION=$(VERSION)-hsm GO_BUILD_TAGS=pkcs11
	make docker-push VERSION=$(VERSION)-hsm
	$(info CI Build complete)
