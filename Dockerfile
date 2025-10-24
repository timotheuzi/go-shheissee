# Build stage
FROM golang:1.21-alpine AS builder

# Install git (needed for go mod download)
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o go-shheissee ./cmd/shheissee

# Runtime stage
FROM alpine:latest

# Install system dependencies required for network scanning
RUN apk add --no-cache \
    wireless-tools \
    nmap \
    bluez \
    && rm -rf /var/cache/apk/*

# Create a non-root user
RUN addgroup -g 1000 shheissee && \
    adduser -D -s /bin/sh -u 1000 -G shheissee shheissee

# Copy the binary from builder stage
COPY --from=builder /app/go-shheissee /usr/local/bin/go-shheissee

# Copy web templates
COPY --from=builder /app/web /app/web

# Set working directory
WORKDIR /app

# Change ownership to non-root user
RUN chown -R shheissee:shheissee /app

# Switch to non-root user
USER shheissee

# Expose web port (default 8080)
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["go-shheissee"]

# Default command is monitor
CMD ["monitor"]
