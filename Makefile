.PHONY : docker-build docker-push release build-issuer-hsm build-apigw-saml build-apigw-oidcrp build-apigw-all test-saml test-oidcrp test-vc20 test-pkcs11 test-all-tags test-didcomm test-didcomm-interop test-didcomm-all docker-build-apigw-saml docker-build-apigw-oidcrp docker-build-apigw-all docker-build-issuer-hsm pki pki-clean

NAME 					:= vc
LDFLAGS                 := -ldflags "-w -s --extldflags '-static'"
LDFLAGS_DYNAMIC			:= -ldflags "-w -s"
CURRENT_BRANCH 			:= $(shell git rev-parse --abbrev-ref HEAD)
SERVICES 				:= verifier registry persistent mockas apigw issuer ui wallet
PORT                    := 8888
W3C_TEST_SUITE_DIR      := /tmp/w3c-test-suite

pki:
	$(info Setting up PKI)
	./developer_tools/scripts/create_pki.sh

pki-clean:
	$(info Cleaning PKI material)
	rm -rf developer_tools/pki

test: test-apigw test-issuer test-mockas test-persistent test-registry test-ui test-verifier

test-apigw:
	$(info Testing apigw)
	go test -v ./cmd/apigw/... ./internal/apigw/...

test-issuer:
	$(info Testing issuer)
	go test -v ./cmd/issuer/... ./internal/issuer/...

test-mockas:
	$(info Testing mockas)
	go test -v ./cmd/mockas/... ./internal/mockas/...

test-persistent:
	$(info Testing persistent)
	go test -v ./cmd/persistent/... ./internal/persistent/...

test-registry:
	$(info Testing registry)
	go test -v ./cmd/registry/... ./internal/registry/...

test-ui:
	$(info Testing ui)
	go test -v ./cmd/ui/... ./internal/ui/...

test-verifier:
	$(info Testing verifier)
	go test -v ./cmd/verifier/... ./internal/verifier/...

# W3C VC 2.0 Test Suite targets
create-w3c-test-suite:
	$(info Creating W3C test suite in $(W3C_TEST_SUITE_DIR))
	rm -rf $(W3C_TEST_SUITE_DIR)
	mkdir -p $(W3C_TEST_SUITE_DIR)
	cd $(W3C_TEST_SUITE_DIR) && \
	git clone https://github.com/w3c/vc-data-model-2.0-test-suite.git . && \
	npm install
	./scripts/gen-w3c-config.sh $(PORT)

run-w3c-test: build-vc20-test-server
	$(info Starting test server on port $(PORT))
	./bin/vc_vc20-test-server -port $(PORT)&
	$(info Running W3C test suite against server on port $(PORT))
	$(info Logs will be saved to /tmp/w3c-test.log)
	cd $(W3C_TEST_SUITE_DIR) && \
	SERVER_URL=http://localhost:$(PORT) npm test 2>&1 | tee /tmp/w3c-test.log ; \
	curl -s http://localhost:$(PORT)/stop 2>/dev/null || true ; \
	sleep 1
	$(info Test results saved to /tmp/w3c-test.log)
	@echo ""; \
	echo "Test Summary:"; \
	echo "============"; \
	grep -c "✓" /tmp/w3c-test.log 2>/dev/null && echo " passing tests" || echo "Tests completed"; \
	grep -c "❌" /tmp/w3c-test.log 2>/dev/null && echo " failing tests" || true

gosec:
	$(info Run gosec)
	gosec -color -tests -tags vc20 -exclude-dir=internal/gen ./...

staticcheck:
	$(info Run staticcheck)
	staticcheck ./...

vulncheck:
	$(info Run vulncheck)
	govulncheck -scan package -tags vc20 ./...

start:
	$(info Run!)
	docker compose -f docker-compose.yaml up -d --remove-orphans

stop:
	$(info stopping VC)
	docker compose -f docker-compose.yaml rm -s -f

restart: stop start

get_release-tag:
	@date +'%Y%m%d%H%M%S%9N'

ifndef VERSION
VERSION := latest
endif


DOCKER_TAG_APIGW 		:= docker.sunet.se/dc4eu/apigw:$(VERSION)
DOCKER_TAG_VERIFIER		:= docker.sunet.se/dc4eu/verifier:$(VERSION)
DOCKER_TAG_REGISTRY 	:= docker.sunet.se/dc4eu/registry:$(VERSION)
DOCKER_TAG_PERSISTENT 	:= docker.sunet.se/dc4eu/persistent:$(VERSION)
DOCKER_TAG_GOBUILD 		:= docker.sunet.se/dc4eu/gobuild:$(VERSION)
DOCKER_TAG_MOCKAS 		:= docker.sunet.se/dc4eu/mockas:$(VERSION)
DOCKER_TAG_ISSUER 		:= docker.sunet.se/dc4eu/issuer:$(VERSION)
DOCKER_TAG_UI 			:= docker.sunet.se/dc4eu/ui:$(VERSION)
DOCKER_TAG_WALLET 		:= docker.sunet.se/dc4eu/wallet:$(VERSION)


build: proto build-verifier build-registry build-persistent build-mockas build-apigw build-ui build-vc20-test-server

build-verifier:
	$(info Building verifier)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o ./bin/$(NAME)_verifier ${LDFLAGS} ./cmd/verifier/main.go

build-vc20-test-server:
	$(info Building vc20-test-server)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags vc20 -v -o ./bin/$(NAME)_vc20-test-server ${LDFLAGS} ./cmd/vc20-test-server/main.go

build-registry:
	$(info Building registry)
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -v -o ./bin/$(NAME)_registry ${LDFLAGS_DYNAMIC} ./cmd/registry/main.go

build-persistent:
	$(info Building persistent)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o ./bin/$(NAME)_persistent ${LDFLAGS} ./cmd/persistent/main.go

build-mockas:
	$(info Building mockas)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o ./bin/$(NAME)_mockas ${LDFLAGS} ./cmd/mockas/main.go

build-apigw:
	$(info Building apigw)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o ./bin/$(NAME)_apigw ${LDFLAGS} ./cmd/apigw/main.go

build-ui:
	$(info Building ui)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o ./bin/$(NAME)_ui ${LDFLAGS} ./cmd/ui/main.go

build-wallet:
	$(info Building wallet)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o ./bin/$(NAME)_wallet ${LDFLAGS} ./cmd/wallet/main.go

# Build targets with optional features (build tags)
# Usage: make build-issuer-hsm  (builds issuer with PKCS#11 HSM support)
#        make build-apigw-saml  (builds apigw with SAML support)
#        make build-apigw-all   (builds apigw with all optional features)

build-issuer-hsm:
	$(info Building issuer with PKCS#11 HSM support)
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags pkcs11 -v -o ./bin/$(NAME)_issuer-hsm ${LDFLAGS_DYNAMIC} ./cmd/issuer/main.go

build-apigw-saml:
	$(info Building apigw with SAML support)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags saml -v -o ./bin/$(NAME)_apigw-saml ${LDFLAGS} ./cmd/apigw/main.go

build-apigw-oidcrp:
	$(info Building apigw with OIDC RP support)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags oidcrp -v -o ./bin/$(NAME)_apigw-oidcrp ${LDFLAGS} ./cmd/apigw/main.go

build-apigw-all:
	$(info Building apigw with all optional features - SAML and OIDC RP)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags "saml,oidcrp" -v -o ./bin/$(NAME)_apigw-all ${LDFLAGS} ./cmd/apigw/main.go

# Test targets with build tags
test-saml:
	$(info Testing with SAML build tag)
	go test -tags saml -v ./pkg/saml/... ./internal/apigw/...

test-oidcrp:
	$(info Testing with OIDC RP build tag)
	go test -tags oidcrp -v ./pkg/oidcrp/... ./internal/apigw/...

test-vc20:
	$(info Testing with VC 2.0 build tag)
	go test -tags vc20 -v ./pkg/vc20/... ./pkg/authzen/... ./pkg/keyresolver/...

test-pkcs11:
	$(info Testing with PKCS#11 build tag)
	go test -tags pkcs11 -v ./pkg/signing/...

test-all-tags:
	$(info Testing with all build tags)
	go test -tags "saml,oidcrp,vc20,pkcs11" -v ./...

# DIDComm v2.1 Test targets
test-didcomm:
	$(info Testing DIDComm v2.1 implementation)
	go test -tags "didcomm,vc20" -v ./pkg/didcomm/...

test-didcomm-interop:
	$(info Running DIDComm interoperability tests)
	go test -tags "didcomm,vc20,didcomm_interop" -v ./test/didcomm_interop/...

test-didcomm-all:
	$(info Running all DIDComm tests including interop)
	go test -tags "didcomm,vc20,didcomm_interop" -v ./pkg/didcomm/... ./test/didcomm_interop/...

docker-build: docker-build-verifier docker-build-registry docker-build-persistent docker-build-mockas docker-build-apigw docker-build-issuer docker-build-ui

docker-build-gobuild:
	$(info Docker Building gobuild with tag: $(VERSION))
	docker build --tag $(DOCKER_TAG_GOBUILD) --file dockerfiles/gobuild .

docker-build-verifier:
	$(info Docker Building verifier with tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=verifier --tag $(DOCKER_TAG_VERIFIER) --file dockerfiles/web_worker .

docker-build-registry:
	$(info Docker Building registry with tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=registry --tag $(DOCKER_TAG_REGISTRY) --file dockerfiles/worker .

docker-build-persistent:
	$(info Docker Building persistent with tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=persistent --tag $(DOCKER_TAG_PERSISTENT) --file dockerfiles/worker .

docker-build-mockas:
	$(info Docker Building mockas with tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=mockas --tag $(DOCKER_TAG_MOCKAS) --file dockerfiles/worker .

docker-build-apigw:
	$(info Docker building apigw with tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=apigw --build-arg BUILDTAG=$(VERSION) --tag $(DOCKER_TAG_APIGW) --file dockerfiles/worker .

docker-build-issuer:
	$(info Docker building issuer with tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=issuer --tag $(DOCKER_TAG_ISSUER) --file dockerfiles/worker .

docker-build-ui:
	$(info Docker building ui with tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=ui --tag $(DOCKER_TAG_UI) --file dockerfiles/web_worker .

docker-build-wallet:
	$(info Docker building wallet with tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=wallet --tag $(DOCKER_TAG_WALLET) --file dockerfiles/worker .

# Docker build targets with build tags
# Usage: make docker-build-apigw-saml VERSION=1.0.0
#        make docker-build-issuer-hsm VERSION=1.0.0

DOCKER_TAG_APIGW_SAML 		:= docker.sunet.se/dc4eu/apigw-saml:$(VERSION)
DOCKER_TAG_APIGW_OIDCRP 	:= docker.sunet.se/dc4eu/apigw-oidcrp:$(VERSION)
DOCKER_TAG_APIGW_ALL 		:= docker.sunet.se/dc4eu/apigw-full:$(VERSION)
DOCKER_TAG_ISSUER_HSM 		:= docker.sunet.se/dc4eu/issuer-hsm:$(VERSION)

docker-build-apigw-saml:
	$(info Docker building apigw with SAML support, tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=apigw --build-arg BUILDTAG=$(VERSION) --build-arg GO_BUILD_TAGS=saml --tag $(DOCKER_TAG_APIGW_SAML) --file dockerfiles/worker .

docker-build-apigw-oidcrp:
	$(info Docker building apigw with OIDC RP support, tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=apigw --build-arg BUILDTAG=$(VERSION) --build-arg GO_BUILD_TAGS=oidcrp --tag $(DOCKER_TAG_APIGW_OIDCRP) --file dockerfiles/worker .

docker-build-apigw-all:
	$(info Docker building apigw with all features - SAML and OIDC RP, tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=apigw --build-arg BUILDTAG=$(VERSION) --build-arg GO_BUILD_TAGS="saml,oidcrp" --tag $(DOCKER_TAG_APIGW_ALL) --file dockerfiles/worker .

docker-build-issuer-hsm:
	$(info Docker building issuer with PKCS#11 HSM support, tag: $(VERSION))
	docker build --build-arg SERVICE_NAME=issuer --build-arg BUILDTAG=$(VERSION) --build-arg GO_BUILD_TAGS=pkcs11 --tag $(DOCKER_TAG_ISSUER_HSM) --file dockerfiles/worker .

docker-push-gobuild:
	$(info Pushing docker images)
	docker push $(DOCKER_TAG_GOBUILD)

docker-push-verifier:
	$(info Pushing docker images)
	docker push $(DOCKER_TAG_VERIFIER)

docker-push-registry:
	$(info Pushing docker images)
	docker push $(DOCKER_TAG_REGISTRY)

docker-push-mockas:
	$(info Pushing docker images)
	docker push $(DOCKER_TAG_MOCKAS)

docker-push-persistent:
	$(info Pushing docker images)
	docker push $(DOCKER_TAG_PERSISTENT)

docker-push-apigw:
	$(info Pushing docker images)
	docker push $(DOCKER_TAG_APIGW)

docker-push-issuer:
	$(info Pushing docker images)
	docker push $(DOCKER_TAG_ISSUER)

docker-push-ui:
	$(info Pushing docker images)
	docker push $(DOCKER_TAG_UI)

docker-push: docker-push-verifier docker-push-registry docker-push-persistent docker-push-apigw docker-push-issuer docker-push-ui docker-push-mockas
	$(info Pushing docker images)

docker-tag-apigw:
	$(info Tagging docker images)
	docker tag $(DOCKER_TAG_APIGW) docker.sunet.se/dc4eu/apigw:$(NEWTAG)

docker-tag-issuer:
	$(info Tagging docker images)
	docker tag $(DOCKER_TAG_ISSUER) docker.sunet.se/dc4eu/issuer:$(NEWTAG)

docker-tag-verifier:
	$(info Tagging docker images)
	docker tag $(DOCKER_TAG_VERIFIER) docker.sunet.se/dc4eu/verifier:$(NEWTAG)

docker-tag-registry:
	$(info Tagging docker images)
	docker tag $(DOCKER_TAG_REGISTRY) docker.sunet.se/dc4eu/registry:$(NEWTAG)

docker-tag-persistent:
	$(info Tagging docker images)
	docker tag $(DOCKER_TAG_PERSISTENT) docker.sunet.se/dc4eu/persistent:$(NEWTAG)

docker-tag-mockas:
	$(info Tagging docker images)
	docker tag $(DOCKER_TAG_MOCKAS) docker.sunet.se/dc4eu/mockas:$(NEWTAG)

docker-tag-ui:
	$(info Tagging docker images)
	docker tag $(DOCKER_TAG_UI) docker.sunet.se/dc4eu/ui:$(NEWTAG)

docker-tag: docker-tag-apigw docker-tag-issuer docker-tag-verifier docker-tag-registry docker-tag-persistent docker-tag-mockas docker-tag-ui
	$(info Tagging docker images)

check_current_branch:
	$(info Current branch: $(CURRENT_BRANCH))
ifeq ($(CURRENT_BRANCH),main)
	$(info main branch)
else
	$(error Not on main branch)
endif


release: check_current_branch
	$(info Release version: $(VERSION))
	git tag $(VERSION)
	git push origin ${VERSION}
	make docker-build
	make docker-push
	$(info Release version $(VERSION) done)
	$(info tag $(NEWTAG) from $(VERSION))
	make docker-tag
	make VERSION=$(NEWTAG) docker-push

	$(info point latest to $(NEWTAG))
	make NEWTAG=latest docker-tag
	make VERSION=latest docker-push

docker-pull:
	$(info Pulling docker images)
	docker pull $(DOCKER_TAG_APIGW)
	docker pull $(DOCKER_TAG_GOBUILD)
	docker pull $(DOCKER_TAG_MOCKAS)
	docker pull $(DOCKER_TAG_PERSISTENT)
	docker pull $(DOCKER_TAG_VERIFIER)
	docker pull $(DOCKER_TAG_REGISTRY)
	docker pull $(DOCKER_TAG_UI)

docker-archive:
	docker save --output docker_archives/vc_$(VERSION).tar $(DOCKER_TAG_VERIFIER) $(DOCKER_TAG_REGISTRY)


clean_redis:
	$(info Cleaning redis volume)
	docker volume rm vc_redis_data 

clean_docker_images:
	$(info Cleaning docker images)
	docker rmi $(DOCKER_TAG_VERIFIER) -f
	docker rmi $(DOCKER_TAG_REGISTRY) -f


ci_build: docker-build docker-push
	$(info CI Build)

# Check if protoc is installed
check-protoc:
	@which protoc > /dev/null || (echo ""; \
		echo "ERROR: protoc (Protocol Buffer Compiler) is not installed"; \
		echo ""; \
		echo "Please install protoc using one of these methods:"; \
		echo ""; \
		echo "Ubuntu/Debian:"; \
		echo "  sudo apt-get update"; \
		echo "  sudo apt-get install -y protobuf-compiler"; \
		echo ""; \
		echo "macOS (Homebrew):"; \
		echo "  brew install protobuf"; \
		echo ""; \
		echo "Or download from: https://github.com/protocolbuffers/protobuf/releases"; \
		echo ""; \
		echo "After installation, also install Go plugins:"; \
		echo "  go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"; \
		echo "  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"; \
		echo ""; \
		exit 1)
	@protoc --version

proto: check-protoc proto-status proto-registry proto-issuer

proto-registry: check-protoc
	protoc --proto_path=./proto/ --go-grpc_opt=module=vc --go-grpc_out=. --go_opt=module=vc --go_out=. ./proto/v1-registry.proto

proto-status: check-protoc
	protoc --proto_path=./proto/ --go-grpc_opt=module=vc --go_opt=module=vc --go_out=. --go-grpc_out=. ./proto/v1-status-model.proto 

proto-issuer: check-protoc
	protoc --proto_path=./proto/ --go-grpc_opt=module=vc --go_opt=module=vc --go_out=. --go-grpc_out=. ./proto/v1-issuer.proto 

swagger: swagger-registry swagger-verifier swagger-apigw swagger-issuer swagger-fmt

swagger-fmt:
	swag fmt

swagger-registry:
	swag init -d internal/registry/apiv1/ -g client.go --output docs/registry --parseDependency --packageName docs

swagger-verifier:
	swag init -d internal/verifier/apiv1/ -g client.go --output docs/verifier --parseDependency --packageName docs

swagger-apigw:
	swag init -d internal/apigw/apiv1/ -g client.go --output docs/apigw --parseDependency --packageName docs

swagger-issuer:
	swag init -d internal/issuer/apiv1/ -g client.go --output docs/issuer --parseDependency --packageName docs

diagram:
	plantuml docs/diagrams/*.puml

install-tools:
	$(info Install from apt)
	apt-get update && apt-get install -y \
		protobuf-compiler \
		netcat-openbsd
	$(info Install from go)
	go install github.com/swaggo/swag/cmd/swag@latest && \
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest


clean-apt-cache:
	$(info Cleaning apt cache)
	rm -rf /var/lib/apt/lists/*

vscode:
	$(info Install APT packages)
	sudo apt-get update && sudo apt-get install -y \
		protobuf-compiler \
		netcat-openbsd \
		plantuml \
		docker.io \
		docker-compose
	$(info Install act for local GitHub Actions testing)
	curl -sfL https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash -s -- -b /usr/local/bin
	$(info Install go packages)
	go install github.com/swaggo/swag/cmd/swag@latest && \
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest && \
	go install golang.org/x/tools/cmd/deadcode@latest && \
	go install github.com/securego/gosec/v2/cmd/gosec@latest && \
	go install golang.org/x/vuln/cmd/govulncheck@latest && \
	go install honnef.co/go/tools/cmd/staticcheck@latest

w3c-test: build-vc20-test-server
	$(info Running W3C test suite)
	@echo "Stopping any existing server..."
	@killall $(NAME)_vc20-test-server 2>/dev/null || true
	@echo "Starting server..."
	@./bin/$(NAME)_vc20-test-server > server.log 2>&1 & echo $$! > server.pid
	@sleep 2
	@echo "Running tests..."
	@cd $(W3C_TEST_SUITE_DIR) && \
	SERVER_URL=http://localhost:$(PORT) npm test > /tmp/w3c-test.log 2>&1 || true
	@echo "Stopping server..."
	@kill `cat server.pid` || true
	@rm server.pid
	@echo "Test results saved to /tmp/w3c-test.log"
	@echo "Summary:"
	@grep "✓" /tmp/w3c-test.log | wc -l | tr -d '\n' && echo " passing tests"
	@grep "❌" /tmp/w3c-test.log | wc -l | tr -d '\n' && echo " failing tests"

test-workflows:
	$(info Testing all GitHub Actions workflows locally with act)
	@echo '{"action": "closed", "pull_request": {"merged": true}}' > /tmp/act-pr-event.json
	act -l
	@echo "--- Running pull_request workflow (dry run) ---"
	act pull_request -e /tmp/act-pr-event.json -n
	@rm -f /tmp/act-pr-event.json

test-workflows-run:
	$(info Running all GitHub Actions workflows locally with act)
	@echo '{"action": "closed", "pull_request": {"merged": true}}' > /tmp/act-pr-event.json
	act pull_request -e /tmp/act-pr-event.json
	@rm -f /tmp/act-pr-event.json
