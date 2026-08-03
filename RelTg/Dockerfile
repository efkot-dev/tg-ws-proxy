FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /usr/local/bin/relay .

FROM alpine:3.20
RUN apk --no-cache add ca-certificates
COPY --from=builder /usr/local/bin/relay /usr/local/bin/relay
CMD ["/usr/local/bin/relay"]
