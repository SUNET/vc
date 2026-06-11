# ==============================================================================
# Configuration Variables
# ==============================================================================

NAME                    := vc
VERSION                 ?= local
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
SERVICES                := verifier registry apigw issuer
WORKER_SERVICES         := verifier registry apigw issuer

# Docker Configuration
DOCKER_REGISTRY         := docker.sunet.se/iam_vc
DOCKER_BUILD_FLAGS      := 
GO_BUILD_TAGS           ?=

# Release Guard Configuration
_RELEASE_MODE           ?=
RESERVED_TAGS           := latest testing demo dev

# Build Tags for Optional Features
# PKCS#11 requires CGO for hardware security module support.
PKCS11_TAG              := pkcs11

# Service Build Configuration (service -> static/dynamic, tags)
# Format: service_name:cgo_mode:build_tags
BUILD_CONFIGS           := \
	verifier:static: \
	registry:static: \
	apigw:static: \
	issuer:static: \
	vc20-test-server:static:

# ==============================================================================
# Phony Targets Declaration
# ==============================================================================

.PHONY: help pki pki-clean test test-env test-js \
	build build-% \
	docker-build docker-build-% docker-push docker-push-% docker-push-issuer-hsm docker-tag docker-tag-% docker-pull docker-archive \
	start stop restart clean_docker_images \
	proto proto-% swagger swagger-% swagger-fmt \
	check-protoc diagram install-tools clean-apt-cache vscode vendor-js update formatting \
	gosec staticcheck vulncheck \
	test-pkcs11 \
	test-wallet test-wallet-vci test-wallet-vp test-wallet-e2e test-wallet-stack \
	test-wallet-stack-vci test-wallet-stack-vp test-wallet-stack-e2e test-wallet-stack-security \
	test-didcomm test-didcomm-interop test-didcomm-all \
	test-workflows test-workflows-run \
	w3c-test create-w3c-test-suite run-w3c-test \
	oidc-conformance-setup oidc-conformance-stop oidc-conformance-clean \
	oidc-conformance-test oidc-conformance-test-vci oidc-conformance-test-vp oidc-conformance-test-oidc \
	oidc-conformance-status \
	_check-reserved-tag \
	release release-prod release-demo check_current_branch \
	release-check-issuer-jwks \
	release-jwt-issuer build-jwt-issuer

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
	$(info   make build-issuer-hsm     - Build issuer with PKCS#11 HSM support)
	$(info )
	$(info OpenID Conformance Suite:)
	$(info   make oidc-conformance-setup      - Start conformance suite)
	$(info   make oidc-conformance-test-vci   - Test OpenID4VCI issuer)
	$(info   make oidc-conformance-test-vp    - Test OpenID4VP verifier)
	$(info   make oidc-conformance-test-oidc  - Test OIDC OP)
	$(info   make oidc-conformance-status     - Show results)
	$(info   make oidc-conformance-clean      - Cleanup)
	$(info )
	$(info Environment Variables:)
	$(info   VERSION               - Docker image version (default: latest))
	$(info   NEWTAG                - Target tag for docker-tag operations (default: VERSION))
	$(info   W3C_TEST_PORT         - W3C test server port (default: 8888))
	$(info   OIDC_CONFORMANCE_URL  - Conformance suite URL (default: https://localhost:8443))
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
# Reserved Tag Guard
# ==============================================================================
# Prevents reserved Docker tags from being used outside of release targets.
# Reserved: semver (vX.Y.Z), latest, testing, demo, dev.
# Only 'make release', 'make release-prod', and 'make release-demo' may use them.

_check-reserved-tag:
ifneq ($(_RELEASE_MODE),1)
	@for val in "$(VERSION)" "$(NEWTAG)"; do \
		if echo "$$val" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$'; then \
			echo "Error: '$$val' is a reserved semver tag. Use 'make release', 'make release-prod', or 'make release-demo' instead."; exit 1; \
		fi; \
		for reserved in $(RESERVED_TAGS); do \
			if [ "$$val" = "$$reserved" ]; then \
				echo "Error: '$$val' is a reserved tag. Use 'make release', 'make release-prod', or 'make release-demo' instead."; exit 1; \
			fi; \
		done; \
	done
endif

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

test: $(addprefix test-,$(SERVICES)) test-js ## Run all service tests

# Generate test-SERVICE targets dynamically
define TEST_TEMPLATE
test-$(1): ## Test $(1) service
	$$(info Testing $(1))
	go test -v ./cmd/$(1)/... ./internal/$(1)/...

endef

$(foreach service,$(SERVICES),$(eval $(call TEST_TEMPLATE,$(service))))

test-env: ## Set up test environment
	$(info Setting up test environment)
	sudo apt-get update && sudo apt-get install -y softhsm2 opensc nodejs npm

test-js: ## Run JS unit tests for staticembed helpers
	$(info Running JS unit tests)
	@node --test $(APIGW_STATIC)/tests/*.test.js

# Test targets with build tags
test-pkcs11: ## Test with PKCS#11 build tag
	$(info Testing with PKCS#11 build tag)
	go test -tags $(PKCS11_TAG) -v ./pkg/signing/...

# DIDComm v2.1 Test targets
test-didcomm: ## Test DIDComm v2.1 implementation
	$(info Testing DIDComm v2.1 implementation)
	go test -v ./pkg/didcomm/...

test-didcomm-interop: ## Run DIDComm interoperability tests
	$(info Running DIDComm interoperability tests)
	go test -v ./test/didcomm_interop/...

test-didcomm-all: ## Run all DIDComm tests including interop
	$(info Running all DIDComm tests including interop)
	go test -v ./pkg/didcomm/... ./test/didcomm_interop/...

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
	go test -v -count=1 -timeout 180s ./internal/wallet/integration/...

test-wallet-stack-vci: ## Run wallet stack VCI tests (happy path + negative)
	$(info Testing wallet stack VCI flows)
	go test -v -count=1 -timeout 180s -run 'TestStack_VCI' ./internal/wallet/integration/...

test-wallet-stack-vp: ## Run wallet stack VP tests
	$(info Testing wallet stack VP flows)
	go test -v -count=1 -timeout 180s -run 'TestStack_VP' ./internal/wallet/integration/...

test-wallet-stack-e2e: ## Run wallet stack end-to-end test (VCI then VP)
	$(info Testing wallet stack E2E flow)
	go test -v -count=1 -timeout 180s -run 'TestStack_E2E' ./internal/wallet/integration/...

test-wallet-stack-security: ## Run wallet stack security/negative tests (DPoP, PKCE, replay)
	$(info Testing wallet stack security — DPoP, PKCE, replay)
	go test -v -count=1 -timeout 180s -run 'TestStack_VCI_(PAR_|Token_|Credential_)' ./internal/wallet/integration/...

# ==============================================================================
# Code Quality & Security
# ==============================================================================

gosec: ## Run gosec security scanner
	$(info Running gosec)
	gosec -color -tests -exclude-dir=internal/gen ./...

staticcheck: ## Run staticcheck linter
	$(info Running staticcheck)
	staticcheck ./...

vulncheck: ## Run vulnerability checker
	$(info Running vulncheck)
	govulncheck -scan package ./...

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
		$(BUILD_FLAGS) -o ./bin/$(NAME)_vc20-test-server \
		$(LDFLAGS) ./cmd/vc20-test-server/

build-wallet: ## Build wallet test tool
	$(info Building wallet)
	$(CGO_ENABLED_STATIC) GOOS=$(BUILD_OS) GOARCH=$(BUILD_ARCH) go build \
		$(BUILD_FLAGS) -o ./bin/$(NAME)_wallet \
		$(LDFLAGS) ./cmd/wallet/

build-check-issuer-jwks: ## Build check_issuer_jwks developer tool
	$(info Building check_issuer_jwks)
	$(eval CHECK_ISSUER_JWKS_VERSION := $(or $(shell git tag -l "check-issuer-jwks-v*" --sort=-v:refname | head -n1 | sed 's/^check-issuer-jwks-//'),dev))
	$(CGO_ENABLED_STATIC) GOOS=$(BUILD_OS) GOARCH=$(BUILD_ARCH) go build \
		$(BUILD_FLAGS) -o ./bin/check_issuer_jwks \
		-ldflags "-w -s --extldflags '-static' -X main.version=$(CHECK_ISSUER_JWKS_VERSION)" \
		./developer_tools/scripts/check_issuer_jwks/

build-jwt-issuer: ## Build jwt_issuer developer tool
	$(info Building jwt_issuer)
	$(eval JWT_ISSUER_VERSION := $(or $(shell git tag -l "jwt-issuer-v*" --sort=-v:refname | head -n1 | sed 's/^jwt-issuer-//'),dev))
	$(CGO_ENABLED_STATIC) GOOS=$(BUILD_OS) GOARCH=$(BUILD_ARCH) go build \
		$(BUILD_FLAGS) -o ./bin/jwt_issuer \
		-ldflags "-w -s --extldflags '-static' -X main.version=$(JWT_ISSUER_VERSION)" \
		./developer_tools/scripts/jwt_issuer/

release-check-issuer-jwks: check_current_branch ## Tag and push a release for check_issuer_jwks (BUMP=major|minor|patch)
	@echo "$(BUMP)" | grep -qE '^(major|minor|patch)$$' || \
		{ echo "Error: BUMP must be major, minor, or patch (got: $(BUMP))"; exit 1; }
	@if [ "$(FORCE)" != "true" ] && ! git diff --quiet HEAD 2>/dev/null; then \
		echo "Error: working tree is dirty — commit or stash changes first (use FORCE=true to override)"; exit 1; \
	fi
	@LATEST=$$(git tag -l "check-issuer-jwks-v*" --sort=-v:refname | grep -E '^check-issuer-jwks-v[0-9]+\.[0-9]+\.[0-9]+$$' | head -n1); \
	if [ -z "$$LATEST" ]; then \
		echo "No existing check-issuer-jwks tags found, starting at check-issuer-jwks-v0.0.0"; \
		LATEST="check-issuer-jwks-v0.0.0"; \
	fi; \
	CURRENT=$$(echo "$$LATEST" | sed 's/^check-issuer-jwks-v//'); \
	MAJOR=$$(echo "$$CURRENT" | cut -d. -f1); \
	MINOR=$$(echo "$$CURRENT" | cut -d. -f2); \
	PATCH=$$(echo "$$CURRENT" | cut -d. -f3); \
	case "$(BUMP)" in \
		major) MAJOR=$$((MAJOR + 1)); MINOR=0; PATCH=0 ;; \
		minor) MINOR=$$((MINOR + 1)); PATCH=0 ;; \
		patch) PATCH=$$((PATCH + 1)) ;; \
	esac; \
	NEW_TAG="check-issuer-jwks-v$$MAJOR.$$MINOR.$$PATCH"; \
	echo ""; \
	echo "$$LATEST -> $$NEW_TAG"; \
	echo ""; \
	if git rev-parse "$$NEW_TAG" >/dev/null 2>&1; then \
		echo "Error: tag $$NEW_TAG already exists"; exit 1; \
	fi; \
	git tag -a "$$NEW_TAG" -m "Release $$NEW_TAG"; \
	git push origin "$$NEW_TAG"; \
	echo ""; \
	echo "==> $$NEW_TAG pushed. GitHub Actions will build check_issuer_jwks binaries."; \
	echo ""

release-jwt-issuer: check_current_branch ## Tag and push a release for jwt_issuer (BUMP=major|minor|patch)
	@echo "$(BUMP)" | grep -qE '^(major|minor|patch)$$' || \
		{ echo "Error: BUMP must be major, minor, or patch (got: $(BUMP))"; exit 1; }
	@if [ "$(FORCE)" != "true" ] && ! git diff --quiet HEAD 2>/dev/null; then \
		echo "Error: working tree is dirty — commit or stash changes first (use FORCE=true to override)"; exit 1; \
	fi
	@LATEST=$$(git tag -l "jwt-issuer-v*" --sort=-v:refname | grep -E '^jwt-issuer-v[0-9]+\.[0-9]+\.[0-9]+$$' | head -n1); \
	if [ -z "$$LATEST" ]; then \
		echo "No existing jwt-issuer tags found, starting at jwt-issuer-v0.0.0"; \
		LATEST="jwt-issuer-v0.0.0"; \
	fi; \
	CURRENT=$$(echo "$$LATEST" | sed 's/^jwt-issuer-v//'); \
	MAJOR=$$(echo "$$CURRENT" | cut -d. -f1); \
	MINOR=$$(echo "$$CURRENT" | cut -d. -f2); \
	PATCH=$$(echo "$$CURRENT" | cut -d. -f3); \
	case "$(BUMP)" in \
		major) MAJOR=$$((MAJOR + 1)); MINOR=0; PATCH=0 ;; \
		minor) MINOR=$$((MINOR + 1)); PATCH=0 ;; \
		patch) PATCH=$$((PATCH + 1)) ;; \
	esac; \
	NEW_TAG="jwt-issuer-v$$MAJOR.$$MINOR.$$PATCH"; \
	echo ""; \
	echo "$$LATEST -> $$NEW_TAG"; \
	echo ""; \
	if git rev-parse "$$NEW_TAG" >/dev/null 2>&1; then \
		echo "Error: tag $$NEW_TAG already exists"; exit 1; \
	fi; \
	git tag -a "$$NEW_TAG" -m "Release $$NEW_TAG"; \
	git push origin "$$NEW_TAG"; \
	echo ""; \
	echo "==> $$NEW_TAG pushed."; \
	echo ""

docker-build-wallet: _check-reserved-tag ## Build Docker image for wallet test tool
	$(info Docker Building wallet with tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=wallet \
		--tag $(call docker-tag,wallet,$(VERSION)) \
		--file dockerfiles/worker .

# ==============================================================================
# Optional Feature Builds (with build tags)
# ==============================================================================

build-issuer-hsm: ## Build issuer with PKCS#11 HSM support
	$(info Building issuer with PKCS#11 HSM support)
	$(CGO_ENABLED_DYNAMIC) GOOS=$(BUILD_OS) GOARCH=$(BUILD_ARCH) go build \
		-tags $(PKCS11_TAG) $(BUILD_FLAGS) -o ./bin/$(NAME)_issuer-hsm \
		$(LDFLAGS_DYNAMIC) ./cmd/issuer/

# ==============================================================================
# Docker Build Targets
# ==============================================================================

docker-build: $(addprefix docker-build-,$(SERVICES)) ## Build all Docker images

# Generate docker-build targets for workers
define DOCKER_BUILD_WORKER_TEMPLATE
docker-build-$(1): _check-reserved-tag ## Build Docker image for $(1)
	$$(info Docker Building $(1) with tag: $$(VERSION))
	docker build --build-arg SERVICE_NAME=$(1) \
		$$(if $$(filter apigw,$(1)),--build-arg BUILDTAG=$$(VERSION)) \
		$$(if $$(GO_BUILD_TAGS),--build-arg GO_BUILD_TAGS=$$(GO_BUILD_TAGS)) \
		--tag $$(call docker-tag,$(1),$$(VERSION)) \
		--file dockerfiles/worker .

endef

$(foreach service,$(WORKER_SERVICES),$(eval $(call DOCKER_BUILD_WORKER_TEMPLATE,$(service))))

# Docker build with PKCS#11 feature
docker-build-issuer-hsm: _check-reserved-tag ## Build issuer Docker image with PKCS#11 HSM support
	$(info Docker building issuer with PKCS#11 HSM support, tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=issuer --build-arg BUILDTAG=$(VERSION) \
		--build-arg GO_BUILD_TAGS=$(PKCS11_TAG) \
		--build-arg CGO_ENABLED=1 \
		--tag $(call docker-tag,issuer-hsm,$(VERSION)) \
		--file dockerfiles/worker .

docker-build-gobuild: _check-reserved-tag ## Build gobuild Docker image
	$(info Docker Building gobuild with tag: $(VERSION))
	docker build --tag $(call docker-tag,gobuild,$(VERSION)) --file dockerfiles/gobuild .

docker-build-developer-tools: _check-reserved-tag ## Build developer tools Docker image
	$(info Docker Building developer tools with tag: $(VERSION))
	docker build --tag $(call docker-tag,developer_tools,$(VERSION)) \
		--file dockerfiles/developer_tools .

# ==============================================================================
# Docker Push Targets
# ==============================================================================

docker-push: $(addprefix docker-push-,$(SERVICES)) ## Push all Docker images

# Generate docker-push targets dynamically
define DOCKER_PUSH_TEMPLATE
docker-push-$(1): _check-reserved-tag ## Push Docker image for $(1)
	$$(info Pushing docker image $(1))
	docker push $$(call docker-tag,$(1),$$(VERSION))

endef

$(foreach service,$(SERVICES),$(eval $(call DOCKER_PUSH_TEMPLATE,$(service))))

# Push target for PKCS#11 feature build
docker-push-issuer-hsm: _check-reserved-tag ## Push issuer Docker image with PKCS#11 HSM support
	$(info Pushing docker image issuer-hsm)
	docker push $(call docker-tag,issuer-hsm,$(VERSION))

docker-push-gobuild: _check-reserved-tag ## Push gobuild Docker image
	$(info Pushing docker image gobuild)
	docker push $(call docker-tag,gobuild,$(VERSION))

docker-push-developer-tools: _check-reserved-tag ## Push developer tools Docker image
	$(info Pushing docker image developer tools)
	docker push $(call docker-tag,developer_tools,$(VERSION))

# ==============================================================================
# Docker Tag Targets
# ==============================================================================

docker-tag: $(addprefix docker-tag-,$(SERVICES)) ## Tag all Docker images

# Generate docker-tag targets dynamically
define DOCKER_TAG_TEMPLATE
docker-tag-$(1): _check-reserved-tag ## Tag Docker image for $(1)
	$$(info Tagging docker image $(1))
	docker tag $$(call docker-tag,$(1),$$(VERSION)) $$(call docker-tag,$(1),$$(NEWTAG))

endef

$(foreach service,$(SERVICES),$(eval $(call DOCKER_TAG_TEMPLATE,$(service))))

# ==============================================================================
# Docker Utilities
# ==============================================================================

docker-pull: _check-reserved-tag ## Pull all Docker images
	$(info Pulling docker images)
	$(foreach service,$(SERVICES),docker pull $(call docker-tag,$(service),$(VERSION));)

docker-archive: _check-reserved-tag ## Create Docker archive
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

# Catch-all for services without explicit proto targets (e.g. apigw)
proto-%:
	@echo "No protobuf for $*"

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

SWAGGER_OPTS := --packageName docs

# Catch-all for services without explicit swagger targets
swagger-%:
	@echo "No swagger docs for $*"
	@mkdir -p docs

swagger-registry: ## Generate registry Swagger docs
	swag init -d internal/registry/apiv1/ -g client.go --output docs/registry $(SWAGGER_OPTS)

swagger-verifier: ## Generate verifier Swagger docs
	swag init -d internal/verifier/apiv1/ -g client.go --output docs/verifier $(SWAGGER_OPTS)

swagger-apigw: ## Generate apigw Swagger docs
	swag init -d internal/apigw/apiv1/,pkg/helpers,pkg/model,pkg/vcclient,pkg/openid4vci,pkg/oauth2,internal/gen/issuer/apiv1_issuer -g client.go --output docs/apigw $(SWAGGER_OPTS)

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
# OpenID Foundation Conformance Suite
# ==============================================================================
# Tests OpenID4VCI (Issuer), OpenID4VP (Verifier), and OIDC OP conformance
# using the OpenID Foundation Conformance Suite (https://openid.net/certification/)
#
# Prerequisites:
#   1. VC dev stack running: make start
#   2. Conformance suite started: make oidc-conformance-setup
#
# Quick start:
#   make start                        # Start VC services
#   make oidc-conformance-setup        # Start conformance suite
#   make oidc-conformance-test-vci     # Test OpenID4VCI issuer
#   make oidc-conformance-test-vp      # Test OpenID4VP verifier
#   make oidc-conformance-test-oidc    # Test OIDC OP (verifier)
#   make oidc-conformance-status       # Check results
#   make oidc-conformance-clean        # Cleanup
# ==============================================================================

OIDC_CONFORMANCE_URL    ?= https://localhost:8443
OIDC_CONFORMANCE_LOG    := /tmp/oidc-conformance

oidc-conformance-setup: ## Clone, build & start the OpenID Conformance Suite
	$(info Setting up OpenID Conformance Suite)
	@chmod +x ./scripts/oidc-conformance.sh
	CONFORMANCE_URL=$(OIDC_CONFORMANCE_URL) ./scripts/oidc-conformance.sh setup

oidc-conformance-stop: ## Stop the OpenID Conformance Suite
	$(info Stopping OpenID Conformance Suite)
	@chmod +x ./scripts/oidc-conformance.sh
	CONFORMANCE_URL=$(OIDC_CONFORMANCE_URL) ./scripts/oidc-conformance.sh stop

oidc-conformance-clean: ## Stop and remove all conformance suite data
	$(info Cleaning up OpenID Conformance Suite)
	@chmod +x ./scripts/oidc-conformance.sh
	CONFORMANCE_URL=$(OIDC_CONFORMANCE_URL) ./scripts/oidc-conformance.sh clean
	rm -rf $(OIDC_CONFORMANCE_LOG)

# Conformance test targets — each creates a test plan via the suite API
oidc-conformance-test: oidc-conformance-test-vci oidc-conformance-test-vp oidc-conformance-test-oidc ## Run all OpenID conformance tests

oidc-conformance-test-vci: ## Test OpenID4VCI issuer conformance
	$(info Running OpenID4VCI Issuer conformance test)
	@chmod +x ./scripts/oidc-conformance.sh
	CONFORMANCE_URL=$(OIDC_CONFORMANCE_URL) ./scripts/oidc-conformance.sh test-vci

oidc-conformance-test-vp: ## Test OpenID4VP verifier conformance
	$(info Running OpenID4VP Verifier conformance test)
	@chmod +x ./scripts/oidc-conformance.sh
	CONFORMANCE_URL=$(OIDC_CONFORMANCE_URL) ./scripts/oidc-conformance.sh test-vp

oidc-conformance-test-oidc: ## Test OIDC OP (verifier) conformance
	$(info Running OIDC OP conformance test)
	@chmod +x ./scripts/oidc-conformance.sh
	CONFORMANCE_URL=$(OIDC_CONFORMANCE_URL) ./scripts/oidc-conformance.sh test-oidc

oidc-conformance-status: ## Show OpenID conformance test results
	@chmod +x ./scripts/oidc-conformance.sh
	@CONFORMANCE_URL=$(OIDC_CONFORMANCE_URL) ./scripts/oidc-conformance.sh status

# ==============================================================================
# Vendored JS/CSS Dependencies
# ==============================================================================
# Re-run this target to update vendored frontend dependencies.
# After updating versions here, commit the downloaded files.

ALPINEJS_VERSION        := 3.14.8
VALIBOT_VERSION         := 1.1.0
JSON_VIEWER_VERSION     := 2.2.0

APIGW_STATIC            := internal/apigw/staticembed
VERIFIER_STATIC         := internal/verifier/static

vendor-js: ## Download vendored JS/CSS dependencies
	$(info Downloading Alpine.js $(ALPINEJS_VERSION))
	curl -sL -o $(APIGW_STATIC)/alpinejs.esm.min.js \
		"https://cdn.jsdelivr.net/npm/alpinejs@$(ALPINEJS_VERSION)/dist/module.esm.min.js"
	curl -sL -o $(VERIFIER_STATIC)/alpinejs.esm.min.js \
		"https://cdn.jsdelivr.net/npm/alpinejs@$(ALPINEJS_VERSION)/dist/module.esm.min.js"
	$(info Downloading Valibot $(VALIBOT_VERSION))
	curl -sL -o $(APIGW_STATIC)/valibot.min.js \
		"https://cdn.jsdelivr.net/npm/valibot@$(VALIBOT_VERSION)/dist/index.min.js"
	curl -sL -o $(VERIFIER_STATIC)/valibot.min.js \
		"https://cdn.jsdelivr.net/npm/valibot@$(VALIBOT_VERSION)/dist/index.min.js"
	$(info Downloading Tailwind CSS CDN)
	curl -sL -o $(APIGW_STATIC)/tailwindcss.js \
		"https://cdn.tailwindcss.com"
	$(info Downloading @andypf/json-viewer $(JSON_VIEWER_VERSION))
	curl -sL -o $(VERIFIER_STATIC)/json-viewer.esm.js \
		"https://cdn.jsdelivr.net/npm/@andypf/json-viewer@$(JSON_VIEWER_VERSION)/+esm"
	$(info Done — vendored JS/CSS dependencies updated)

# ==============================================================================
# Go Dependency Management
# ==============================================================================

update: ## Update all Go dependencies to their latest versions and re-vendor
	$(info Updating all Go dependencies...)
	GOFLAGS="" go get -u ./...
	GOFLAGS="" go mod tidy
	go mod vendor
	$(info Done — all Go dependencies updated and vendor refreshed)

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

build-gen-bootstrap: ## Build gen_bootstrap tool
	$(info Building gen_bootstrap)
	$(CGO_ENABLED_STATIC) go build $(BUILD_FLAGS) -o ./bin/gen_bootstrap ./developer_tools/scripts/gen_bootstrap/

gen-bootstrap: build-gen-bootstrap ## Generate bootstrapping JSON files from YAML source
	$(info Generating bootstrapping/*.json from developer_tools/scripts/gen_bootstrap/users_paris.yaml)
	./bin/gen_bootstrap developer_tools/scripts/gen_bootstrap/users_paris.yaml bootstrapping

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
	$(info Installing yq)
	sudo wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/local/bin/yq &&\
    sudo chmod +x /usr/local/bin/yq
	$(info Installing act for local GitHub Actions testing)
	curl -sfL https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash -s -- -b /usr/local/bin
	$(info Installing go packages)
	go install github.com/swaggo/swag/cmd/swag@latest && \
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest && \
	go install golang.org/x/tools/cmd/deadcode@latest && \
	go install github.com/securego/gosec/v2/cmd/gosec@latest && \
	go install golang.org/x/vuln/cmd/govulncheck@latest && \
	go install honnef.co/go/tools/cmd/staticcheck@latest && \
	go install mvdan.cc/gofumpt@latest

# ==============================================================================
# Formatting
# ==============================================================================

formatting: ## Format Go code with gofumpt
	gofumpt -l -w .

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

BUMP                    ?= patch
FORCE                   ?=

check_current_branch: ## Verify current branch is main
	$(info Current branch: $(CURRENT_BRANCH))
ifeq ($(CURRENT_BRANCH),main)
	$(info On main branch)
else
ifneq ($(FORCE),true)
	$(error Not on main branch — use FORCE=true to override)
else
	$(warning Not on main branch — continuing because FORCE=true)
endif
endif

get_release-tag: ## Show current release version from latest git tag
	@git tag -l "v*" --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -n1 || echo "v0.0.0"

#### Release target
# Creates a vX.Y.Z tag by bumping the latest existing tag.
# Usage:
#   make release                       # defaults to patch bump
#   make release BUMP=minor            # minor bump
#   make release BUMP=major            # major bump
#   make release FORCE=true            # release from any branch
#   make release BUMP=minor FORCE=true # combine options
release: check_current_branch ## Create and push a git tag (BUMP=major|minor|patch)
	@echo "$(BUMP)" | grep -qE '^(major|minor|patch)$$' || \
		{ echo "Error: BUMP must be major, minor, or patch (got: $(BUMP))"; exit 1; }
	@if [ "$(FORCE)" != "true" ] && ! git diff --quiet HEAD 2>/dev/null; then \
		echo "Error: working tree is dirty — commit or stash changes first (use FORCE=true to override)"; exit 1; \
	fi
	@LATEST=$$(git tag -l "v*" --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -n1); \
	if [ -z "$$LATEST" ]; then \
		echo "No existing version tags found, starting at v0.0.0"; \
		LATEST="v0.0.0"; \
	fi; \
	CURRENT=$$(echo "$$LATEST" | sed 's/^v//'); \
	MAJOR=$$(echo "$$CURRENT" | cut -d. -f1); \
	MINOR=$$(echo "$$CURRENT" | cut -d. -f2); \
	PATCH=$$(echo "$$CURRENT" | cut -d. -f3); \
	case "$(BUMP)" in \
		major) MAJOR=$$((MAJOR + 1)); MINOR=0; PATCH=0 ;; \
		minor) MINOR=$$((MINOR + 1)); PATCH=0 ;; \
		patch) PATCH=$$((PATCH + 1)) ;; \
	esac; \
	NEW_TAG="v$${MAJOR}.$${MINOR}.$${PATCH}"; \
	echo ""; \
	echo "Bumping $$LATEST -> $$NEW_TAG ($(BUMP))"; \
	echo ""; \
	git tag -a "$$NEW_TAG" -m "Release $$NEW_TAG"; \
	git push origin "$$NEW_TAG"; \
	echo ""; \
	echo "==> Release $$NEW_TAG created and pushed"; \
	echo ""; \
	echo "Building and pushing Docker images for $$NEW_TAG..."; \
	echo ""; \
	$(MAKE) docker-build VERSION=$$NEW_TAG _RELEASE_MODE=1 && \
	$(MAKE) docker-push VERSION=$$NEW_TAG _RELEASE_MODE=1 && \
	$(MAKE) docker-tag VERSION=$$NEW_TAG NEWTAG=dev _RELEASE_MODE=1 && \
	$(MAKE) docker-push VERSION=dev _RELEASE_MODE=1; \
	echo ""; \
	echo "==> Docker images built and pushed for $$NEW_TAG (:dev)"; \
	echo ""; \
	echo "Requesting Go module proxy indexing for $$NEW_TAG..."; \
	for i in 5 4 3 2 1; do printf "\r    Waiting for tag to propagate... $$i "; sleep 1; done; printf "\r                                       \r"; \
	curl -sf "https://proxy.golang.org/github.com/SUNET/vc/@v/$${NEW_TAG}.info" > /dev/null && \
		echo "==> Go module proxy indexed $$NEW_TAG" || \
		echo "==> Warning: Go module proxy indexing request failed (will be indexed on first fetch)"; \
	echo ""

#### Prod promotion
# Promotes a version to prod by locally pulling :vX.Y.Z images
# and re-tagging/pushing as :latest. No rebuild.
# Usage:
#   make release-prod              # promotes latest vX.Y.Z tag to prod
#   make release-prod TAG=v1.2.3   # promotes v1.2.3 to prod
release-prod: ## Promote a release tag to prod
	@set -e; \
	if [ -n "$(TAG)" ]; then \
		SRC_TAG=$$(echo "$(TAG)" | sed 's#^refs/tags/##'); \
	else \
		SRC_TAG=$$(git tag -l "v*" --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -n1); \
		if [ -z "$$SRC_TAG" ]; then \
			echo "Error: no version tags found. Run 'make release' first."; exit 1; \
		fi; \
	fi; \
	echo "$$SRC_TAG" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' || \
		{ echo "Error: TAG must match vX.Y.Z (got: $$SRC_TAG)"; exit 1; }; \
	echo ""; \
	echo "Promoting $$SRC_TAG -> prod"; \
	echo ""; \
	$(MAKE) docker-pull VERSION=$$SRC_TAG _RELEASE_MODE=1 && \
	$(MAKE) docker-tag VERSION=$$SRC_TAG NEWTAG=latest _RELEASE_MODE=1 && \
	$(MAKE) docker-push VERSION=latest _RELEASE_MODE=1; \
	echo ""; \
	echo "==> Prod promotion complete for $$SRC_TAG (:latest)"; \
	echo ""

#### Demo promotion
# Promotes a version to demo by pulling :vX.Y.Z images
# and re-tagging/pushing as :demo. No rebuild.
# Usage:
#   make release-demo              # promotes latest vX.Y.Z tag to demo
#   make release-demo TAG=v1.2.3   # promotes v1.2.3 to demo
release-demo: ## Promote a release tag to demo
	@set -e; \
	if [ -n "$(TAG)" ]; then \
		SRC_TAG=$$(echo "$(TAG)" | sed 's#^refs/tags/##'); \
	else \
		SRC_TAG=$$(git tag -l "v*" --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -n1); \
		if [ -z "$$SRC_TAG" ]; then \
			echo "Error: no version tags found. Run 'make release' first."; exit 1; \
		fi; \
	fi; \
	echo "$$SRC_TAG" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' || \
		{ echo "Error: TAG must match vX.Y.Z (got: $$SRC_TAG)"; exit 1; }; \
	echo ""; \
	echo "Promoting $$SRC_TAG -> demo"; \
	echo ""; \
	$(MAKE) docker-pull VERSION=$$SRC_TAG _RELEASE_MODE=1 && \
	$(MAKE) docker-tag VERSION=$$SRC_TAG NEWTAG=demo _RELEASE_MODE=1 && \
	$(MAKE) docker-push VERSION=demo _RELEASE_MODE=1; \
	echo ""; \
	echo "==> Demo promotion complete for $$SRC_TAG (:demo)"; \
	echo ""
