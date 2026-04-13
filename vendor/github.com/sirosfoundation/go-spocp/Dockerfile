FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY . .
RUN go build -trimpath -o /spocpd ./cmd/spocpd

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=builder /spocpd /usr/local/bin/spocpd
ENTRYPOINT ["/usr/local/bin/spocpd"]
