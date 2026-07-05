# syntax=docker/dockerfile:1
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY . .
RUN cargo build --release --bin dns-filter

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/dns-filter /usr/local/bin/dns-filter
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["dns-filter"]
CMD ["-c", "/etc/dns-filter/config.toml"]
