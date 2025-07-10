# Build stage
FROM rust:1.75-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

# Create app directory
WORKDIR /usr/src/app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build the application
RUN cargo build --release

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Copy the binary from builder
COPY --from=builder /usr/src/app/target/release/procgather /usr/local/bin/procgather

# Create non-root user
RUN adduser -D -u 1000 procgather

# Switch to non-root user
USER procgather

# Set the entrypoint
ENTRYPOINT ["procgather"]

# Default command
CMD ["--help"]