# --- Stage 1: Build C++ ZK Libraries and Go Binary ---
    FROM golang:latest AS builder

    RUN apt update -y && apt install -y \
        clang cmake libssl-dev libzstd-dev libgtest-dev \
        libbenchmark-dev zlib1g-dev build-essential git
    
    WORKDIR /app/vc/internal/verifier/zk
    COPY ../internal/verifier/zk/lib ./lib
    COPY ../internal/verifier/zk/lib/circuits/mdoc/circuits ./server/circuits/LONGFELLOW_V1
    
    RUN CXX=clang++ cmake -D CMAKE_BUILD_TYPE=Release -S lib -B build \
        --install-prefix /app/vc/internal/verifier/zk/install && \
        cd build && make -j$(nproc) install
    
    WORKDIR /app
    COPY . .
    
    
    RUN find /app -name "mdoc_zk.h" && find /app -name "*.a"
    
    RUN --mount=type=cache,target=/root/.cache/go-build \
        CGO_ENABLED=1 \
        CGO_CFLAGS="-I/app/vc/internal/verifier/zk/install/include" \
        CGO_LDFLAGS="-L/app/vc/internal/verifier/zk/install/lib -lmdoc_static -lcrypto -lzstd -lstdc++" \
        GOOS=linux GOARCH=amd64 \
        go build -v -o /app/bin/vc_verifier ./cmd/verifier/main.go
        
    # --- Stage 2: Final Runtime Image ---
    FROM docker.sunet.se/dc4eu/verifier:latest
    
    USER root
    RUN apt update -y && apt install -y libssl3 libzstd1 zlib1g && rm -rf /var/lib/apt/lists/*
    
    COPY --from=builder /app/bin/vc_verifier /usr/local/bin/verifier
    COPY --from=builder /app/vc/internal/verifier/zk/server/circuits /app/vc/internal/verifier/zk/circuits/
    
    COPY --from=builder /app/vc/internal/verifier/zk/install/lib /usr/local/lib/
    COPY ../internal/verifier/zk/certs.pem /app/vc/internal/verifier/zk/certs.pem
    
    RUN ldconfig
    
    
    WORKDIR /
    
    ENTRYPOINT ["/usr/local/bin/verifier"]
    