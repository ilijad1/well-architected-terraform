# Multi-stage build for minimal final image
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

WORKDIR /build

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o wat .

# Runtime stage - use minimal alpine image
FROM alpine:latest

# Install ca-certificates for HTTPS (if needed for future features)
RUN apk --no-cache add ca-certificates

WORKDIR /workspace

# Copy binary from builder
COPY --from=builder /build/wat /usr/local/bin/wat

# Set entrypoint
ENTRYPOINT ["wat"]

# Default command shows help
CMD ["--help"]

# Usage examples:
# docker build -t wat .
# docker run --rm -v $(pwd):/workspace wat analyze plan.json
# docker run --rm -v $(pwd):/workspace wat list-rules
# docker run --rm -v $(pwd):/workspace wat analyze --format json plan.json > findings.json
