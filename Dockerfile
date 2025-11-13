# Multi-stage build for Shimmy web version

# Build stage - Use golang alpine for static linking
FROM docker.io/library/golang:1.18-buster AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Use static linking to avoid glibc compatibility issues
RUN CGO_ENABLED=0 go build -ldflags "-w -s" -o bin/shimmy-web ./cmd/shheissee

# Runtime stage - Use Ubuntu with all required libraries
FROM docker.io/library/ubuntu:22.04
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    bluez \
    aircrack-ng \
    usbutils \
    && rm -rf /var/lib/apt/lists/*

# Install sudo and create a user with sudo access (no password)
RUN apt-get update && apt-get install -y sudo && \
    useradd -m -r -s /bin/bash shimmy && \
    echo 'shimmy ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/shimmy && \
    chmod 0440 /etc/sudoers.d/shimmy

# Add SDR tools (optional, but useful for radio monitoring)
RUN apt-get install -y rtl-sdr 2>/dev/null || echo "rtl-sdr not available, skipping"

WORKDIR /app
COPY --from=builder /app/bin/shimmy-web ./bin/
RUN chmod +x ./bin/shimmy-web

# Switch to root user for privileged operations (since we're running privileged container)
EXPOSE 8080
CMD ["/app/bin/shimmy-web", "--web"]
