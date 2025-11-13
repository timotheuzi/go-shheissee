#!/bin/bash

# Go-Shheissee Security Monitor Runner for Linux

echo "Starting Go-Shheissee on Linux..."

# Check if running as root for Bluetooth and network privileges
if [ "$EUID" -ne 0 ]; then
  echo "Requesting sudo privileges for full monitoring capabilities..."
  echo "Bluetooth scanning, network monitoring, and system monitoring require elevated privileges."
  exec sudo "$0" "$@"
fi

# Ensure Bluetooth service is running
systemctl start bluetooth 2>/dev/null || echo "Warning: Could not start bluetooth service"

# Build and run the application with full privileges
go build -o shheissee ./cmd/shheissee
if [ $? -eq 0 ]; then
  echo "Running Go-Shheissee with elevated privileges for full functionality..."
  ./shheissee
else
  echo "Build failed"
  exit 1
fi
