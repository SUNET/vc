# --- Stage 1: Build C++ ZK Libraries and Go Binary ---
    FROM golang:latest AS builder

    RUN apt update -y && apt install -y \
        clang cmake libssl-dev libzstd-dev libgtest-dev \
        libbenchmark-dev zlib1g-dev build-essential git
    
    # 1. Clone the external dependency
    RUN git clone https://github.com/google/longfellow-zk.git /tmp/longfellow-zk
    
    WORKDIR /tmp/longfellow-zk
    RUN CXX=clang++ cmake -D CMAKE_BUILD_TYPE=Release -S lib -B build \
        --install-prefix /usr/local/zk-install && \
        cd build && make -j$(nproc) install
    
    WORKDIR /app
    COPY . .
    # Ensure 'vendor' was created on host via `go mod vendor`
    COPY vendor/ ./vendor/
    
    RUN --mount=type=cache,target=/root/.cache/go-build \
        CGO_ENABLED=1 \
        CGO_CFLAGS="-I/usr/local/zk-install/include" \
        CGO_LDFLAGS="-L/usr/local/zk-install/lib -lmdoc_static -lcrypto -lzstd -lstdc++" \
        go build -mod=vendor -v -o /app/bin/vc_verifier ./cmd/verifier/main.go
    
    # --- Stage 2: Final Runtime Image ---
    FROM docker.sunet.se/dc4eu/verifier:latest
    
    USER root
    RUN apt update -y && apt install -y libssl3 libzstd1 zlib1g && rm -rf /var/lib/apt/lists/*
    
    # Copy the binary
    COPY --from=builder /app/bin/vc_verifier /usr/local/bin/verifier
    COPY --from=builder /tmp/longfellow-zk/lib/circuits /app/vc/internal/verifier/zk/circuits/
    
    # Copy compiled libraries
    COPY --from=builder /usr/local/zk-install/lib /usr/local/lib/
    RUN ldconfig
    
    WORKDIR /
    ENTRYPOINT ["/usr/local/bin/verifier"]