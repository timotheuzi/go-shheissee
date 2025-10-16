# Go-Shheissee - Makefile

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Go environment variables for compatibility with module cache
export GOPATH:=$(HOME)/go

# Main package
MAIN_PACKAGE=./cmd/shheissee

# Configuration
PORT ?= 8080

# Binary name and distribution directory
BINARY_NAME=go-shheissee
DIST_DIR=bin

# Build targets
.PHONY: all build clean test coverage run deps fmt vet help create-dist

all: test build

# Create distribution directory
create-dist:
	mkdir -p $(DIST_DIR)

# Build the binary
build: create-dist
	$(GOBUILD) -o $(DIST_DIR)/$(BINARY_NAME) -v $(MAIN_PACKAGE)

# Build with race detection
build-race: create-dist
	$(GOBUILD) -race -o $(DIST_DIR)/$(BINARY_NAME) -v $(MAIN_PACKAGE)

# Build for Linux
build-linux: create-dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 -v $(MAIN_PACKAGE)

# Build for Windows
build-windows: create-dist
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe -v $(MAIN_PACKAGE)

# Build for macOS
build-darwin: create-dist
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 -v $(MAIN_PACKAGE)

# Cross-platform builds
build-all: build-linux build-windows build-darwin

# Clean build files
clean:
	$(GOCLEAN)
	rm -rf $(DIST_DIR)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-*

# Disk clean - deep clean including logs and generated files
disk-clean:
	$(GOCLEAN)
	rm -rf $(DIST_DIR)
	rm -rf $(BINARY_NAME)
	rm -rf $(BINARY_NAME)-*
	rm -rf coverage.out
	rm -rf coverage.html
	rm -rf log/
	rm -rf model/

# Run tests
test:
	$(GOTEST) -v ./...

# Run tests with coverage
coverage:
	$(GOTEST) -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Run the application
run:
	$(GOBUILD) -o $(BINARY_NAME) $(MAIN_PACKAGE)
	APP_PORT=$(PORT) ./$(BINARY_NAME)

# Run in monitor mode
run-monitor:
	$(GOBUILD) -o $(BINARY_NAME) $(MAIN_PACKAGE)
	APP_PORT=$(PORT) ./$(BINARY_NAME) monitor

# Download dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Format code
fmt:
	$(GOFMT) ./...

# Vet code
vet:
	$(GOVET) ./...

# Run all checks (format, vet, test)
check: fmt vet test

# Development setup
dev-setup: deps
	@echo "Development environment setup complete."
	@echo "Run 'make build' to build the project."
	@echo "Run 'make run' to run the application."

# Generate test demo data
demo:
	$(GOBUILD) -o $(BINARY_NAME) $(MAIN_PACKAGE)
	./$(BINARY_NAME) demo

# Quick scan
scan:
	$(GOBUILD) -o $(BINARY_NAME) $(MAIN_PACKAGE)
	./$(BINARY_NAME) scan

# Install system dependencies (Linux)
install-deps:
	@echo "Installing system dependencies..."
	@if grep -q "ID=org.freedesktop.platform" /etc/os-release; then \
		echo "Running in Flatpak environment. System dependencies must be declared in the Flatpak manifest."; \
		echo "Ensure the manifest includes permissions for:"; \
		echo "  - Network (to use nmap and iwlist)"; \
		echo "  - Bluetooth (if available)"; \
		echo "Required packages: wireless-tools, nmap, bluez, bluez-tools"; \
		echo "Skipping system installation."; \
	elif command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get update && sudo apt-get install -y wireless-tools nmap bluetooth bluez bluez-tools; \
	elif command -v dnf >/dev/null 2>&1; then \
		sudo dnf install -y wireless-tools nmap bluez bluez-tools; \
	elif command -v pacman >/dev/null 2>&1; then \
		sudo pacman -S --noconfirm wireless_tools nmap bluez bluez-utils; \
	else \
		echo "Unsupported package manager. Please install dependencies manually:"; \
		echo "  - wireless-tools (iwlist)"; \
		echo "  - nmap"; \
		echo "  - bluez bluez-tools (bluetoothctl)"; \
		exit 1; \
	fi
	@echo "System dependencies installed (if applicable)."

# Docker build
docker-build:
	docker build -t shheissee-go .

# Docker run
docker-run:
	docker run --privileged --net=host shheissee-go monitor

# Help
help:
	@echo "Go-Shheissee - Makefile Help"
	@echo ""
	@echo "Configuration variables:"
	@echo "  PORT           Web server port (default: 8080)"
	@echo ""
	@echo "Available targets:"
	@echo "  build          Build the binary"
	@echo "  build-race     Build with race detection"
	@echo "  build-linux    Build for Linux"
	@echo "  build-windows  Build for Windows"
	@echo "  build-darwin   Build for macOS"
	@echo "  build-all      Build for all platforms"
	@echo "  clean          Clean build files"
	@echo "  test           Run tests"
	@echo "  coverage       Run tests with coverage report"
	@echo "  run            Build and run the application"
	@echo "  run-monitor    Build and run in monitor mode"
	@echo "  deps           Download and tidy dependencies"
	@echo "  fmt            Format Go code"
	@echo "  vet            Run Go vet"
	@echo "  check          Run fmt, vet, and test"
	@echo "  dev-setup      Setup development environment"
	@echo "  demo           Run demo scenario setup"
	@echo "  scan           Run quick security scan"
	@echo "  install-deps   Install system dependencies (Linux)"
	@echo "  docker-build   Build Docker image"
	@echo "  docker-run     Run in Docker container"
	@echo "  help           Show this help message"
	@echo ""
	@echo "Usage examples:"
	@echo "  make build && ./go-shheissee              # Build and run interactively"
	@echo "  make run-monitor                       # Build and start monitoring"
	@echo "  make run PORT=9090                     # Run with custom port"
	@echo "  make build-all                         # Cross-platform build"
	@echo "  make check                             # Run all code checks"

# Default target
.DEFAULT_GOAL := help
