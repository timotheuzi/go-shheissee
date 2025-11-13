#!/bin/bash

# Go-Shheissee Podman Runner with Sudo Powers
# This script runs the Go-Shheissee container with all necessary privileges for network monitoring

set -e

IMAGE_NAME="localhost/shheissee-web"
CONTAINER_NAME="shheissee-web-container"

echo "🐳 Go-Shheissee Podman Container Runner"
echo "======================================="

# Check if podman is available
if ! command -v podman &> /dev/null; then
    echo "❌ Podman is not installed or not in PATH"
    exit 1
fi

# Check if running as root (required for network capabilities)
if [ "$EUID" -ne 0 ]; then
    echo "🔐 Requesting sudo privileges for container networking capabilities..."
    echo "Network monitoring requires elevated privileges for raw sockets and network administration."
    exec sudo "$0" "$@"
fi

# Function to cleanup containers
cleanup() {
    echo ""
    echo "🛑 Stopping and removing container..."
    podman stop $CONTAINER_NAME 2>/dev/null || true
    podman rm $CONTAINER_NAME 2>/dev/null || true
}

# Set trap to cleanup on script exit
trap cleanup EXIT INT TERM

# Check if image exists
if ! podman image exists $IMAGE_NAME; then
    echo "🔨 Building container image..."
    podman build -t $IMAGE_NAME .
fi

echo "🚀 Starting Go-Shheissee container with enhanced networking capabilities..."
echo ""

# Run container with comprehensive network capabilities
podman run --rm \
    --cap-add=NET_RAW \
    --cap-add=NET_ADMIN \
    --cap-add=NET_BIND_SERVICE \
    --cap-add=NET_BROADCAST \
    --cap-add=SYS_ADMIN \
    --device=/dev/net/tun \
    --device=/dev/net/tap \
    --device=/dev/net/raw \
    -p 8080:8080 \
    -p 1001:1001 \
    --name $CONTAINER_NAME \
    $IMAGE_NAME

echo "✅ Container stopped"
