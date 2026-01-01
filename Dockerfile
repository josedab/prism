# Build stage
FROM rust:1.75-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

WORKDIR /app

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./

# Create dummy source to build dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    echo "pub fn dummy() {}" > src/lib.rs

# Build dependencies only
RUN cargo build --release && \
    rm -rf src

# Copy actual source code
COPY src ./src
COPY tests ./tests

# Touch main.rs to force rebuild with actual code
RUN touch src/main.rs src/lib.rs

# Build the application
RUN cargo build --release --bin prism

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tini

# Create non-root user
RUN addgroup -g 1000 prism && \
    adduser -u 1000 -G prism -s /bin/sh -D prism

# Create directories
RUN mkdir -p /etc/prism /var/log/prism && \
    chown -R prism:prism /etc/prism /var/log/prism

# Copy binary from builder
COPY --from=builder /app/target/release/prism /usr/local/bin/prism

# Copy example config
COPY examples/basic.yaml /etc/prism/prism.yaml

# Use non-root user
USER prism

# Expose default ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health || exit 1

# Use tini as init system
ENTRYPOINT ["/sbin/tini", "--"]

# Default command
CMD ["prism", "--config", "/etc/prism/prism.yaml"]
