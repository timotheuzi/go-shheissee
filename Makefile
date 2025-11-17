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

# Ensure bin directory exists
bin:
	mkdir -p bin

# Build ALL possible executables at once (cleans first)
all: clean bin terminal web android container
	@echo "✅ All builds completed successfully!"
	@echo ""
	@echo "Built executables:"
	@echo "  📱 Terminal: bin/go-shheissee"
	@echo "  🌐 Web:      bin/go-shheissee-web"
	@echo "  🤖 Android:  bin/go-shheissee.apk"
	@echo "  🐳 Container: localhost/shheissee-web (Podman image)"
	@echo ""
	@echo "Usage:"
	@echo "  Terminal: ./bin/go-shheissee"
	@echo "  Web:      ./bin/go-shheissee-web --web"
	@echo "  Container: podman run -p 8080:8080 localhost/shheissee-web"

# Build terminal executable
terminal: bin
	GO111MODULE=on go build -mod=mod -o bin/go-shheissee ./cmd/shheissee

# Build web version executable
web: bin
	GO111MODULE=on go build -mod=mod -o bin/go-shheissee-web ./cmd/shheissee

# Build Android APK using gomobile
android: bin
	@echo "🔨 Building Android APK..."
	@if [ -x $(GOPATH)/bin/gomobile ]; then \
		export ANDROID_NDK_HOME=/home/maestro/Android/Sdk/ndk-bundle; \
		export PATH=$(GOPATH)/bin:$(PATH); \
		gomobile init; \
		GO111MODULE=on gomobile build -target=android -o bin/go-shheissee.apk ./cmd/shheissee; \
		echo "✅ Android APK built: bin/go-shheissee.apk"; \
	else \
		echo "⚠️  gomobile not found - skipping Android build"; \
		echo "   Install with: go install golang.org/x/mobile/cmd/gomobile@latest"; \
	fi

# Build native Android app with professional UI
build-android: bin
	@echo "🔨 Building native Android app..."
	@if command -v docker >/dev/null 2>&1; then \
		echo "📦 Setting up Android SDK and NDK..."; \
		cd android && docker run --rm -v $$(pwd):/project \
			-e ANDROID_HOME=/opt/android-sdk \
			-e ANDROID_NDK_HOME=/opt/android-sdk/ndk/26.1.10909125 \
			-e PATH=/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/tools/bin:/opt/android-sdk/platform-tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
			thyrlian/android-sdk:latest \
			bash -c "\
				echo '🔧 Installing Android SDK components...'; \
				sdkmanager --install 'platform-tools' 'platforms;android-34' 'build-tools;34.0.0' 'ndk;26.1.10909125'; \
				echo '✅ Accepting Android SDK licenses...'; \
				yes | sdkmanager --licenses; \
				echo '🔨 Creating Gradle wrapper...'; \
				gradle wrapper; \
				echo '🏗️ Building APK...'; \
				./gradlew assembleDebug --no-daemon; \
				echo '📋 Build completed'"; \
		if [ -f android/app/build/outputs/apk/debug/app-debug.apk ]; then \
			cp android/app/build/outputs/apk/debug/app-debug.apk bin/shheissee-monitor.apk; \
			echo "✅ Native Android APK built: bin/shheissee-monitor.apk"; \
			echo "📱 APK ready for installation on Android devices"; \
		else \
			echo "❌ APK build failed - check android/app/build/outputs/logs for details"; \
			exit 1; \
		fi; \
	else \
		echo "⚠️  Docker not found - cannot build native Android app"; \
		echo "   Install Docker and try again"; \
	fi

# Create Podman container image with web version
container: Dockerfile bin
	podman build -t localhost/shheissee-web .

# Build targets
.PHONY: all build clean test coverage run deps fmt vet help create-dist

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
	rm -f shimmy shimmy.log
	rm -rf bin .gocache *.tmp

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

# Run the terminal version (requires sudo for network monitoring)
run_terminal: terminal
	@echo "🔐 Running terminal version with sudo for network monitoring capabilities..."
	sudo ./bin/go-shheissee

# Run the web version (requires sudo for network monitoring)
run_web: web
	@echo "🔐 Running web version with sudo for network monitoring capabilities..."
	sudo ./bin/go-shheissee-web --web

# Run container with sudo and necessary capabilities for network monitoring
run_container: container
	@echo "🐳 Running container with sudo and network capabilities..."
	sudo podman run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE \
		--device=/dev/net/tun --device=/dev/net/tap \
		-p 8080:8080 -p 1001:1001 \
		--name shheissee-web-container \
		localhost/shheissee-web:latest

# Run container in privileged mode (alternative method)
run_container_privileged: container
	@echo "🐳 Running container in privileged mode with full capabilities..."
	podman run --rm --privileged --replace \
		-p 8080:8080 \
		--name shheissee-web-container \
		localhost/shheissee-web:latest

# Stop running container
stop_container:
	@echo "🛑 Stopping container..."
	sudo podman stop shheissee-web-container 2>/dev/null || echo "No container running"

# Clean containers and images
clean_container: stop_container
	@echo "🧹 Cleaning up containers and images..."
	sudo podman rm shheissee-web-container 2>/dev/null || echo "No container to remove"
	sudo podman rmi localhost/shheissee-web 2>/dev/null || echo "No image to remove"

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
		sudo pacman -S --nocondev wireless_tools nmap bluez bluez-utils; \
	else \
		echo "Unsupported package manager. Please install dependencies manually:"; \
		echo "  - wireless-tools (iwlist)"; \
		echo "  - nmap"; \
		echo "  - bluez bluez-tools (bluetoothctl)"; \
		exit 1; \
	fi
	@echo "System dependencies installed (if applicable)."

# Podman setup - configure sudo entitlement for podman user
podman-setup:
	@echo "Configuring sudo entitlement for podman user..."
	sudo sh -c 'echo "$(USER) ALL=(ALL) NOPASSWD: /usr/bin/podman" > /etc/sudoers.d/podman'
	sudo chmod 0440 /etc/sudoers.d/podman
	@echo "Podman user sudo entitlement configured."

# Podman build
podman-build:
	podman build -t shheissee-go .

# Podman clean
podman-clean:
	podman stop $$(podman ps -q -f ancestor=shheissee-go) || true
	podman rm $$(podman ps -aq -f ancestor=shheissee-go) || true
	podman rmi shheissee-go || true

# Podman run privileged
podman-run-privileged:
	podman run --privileged --net=host shheissee-go monitor

# Help
help:
	@echo "Go-Shheissee - Makefile Help"
	@echo ""
	@echo "Configuration variables:"
	@echo "  PORT           Web server port (default: 8080)"
	@echo ""
	@echo "Available targets:"
	@echo "  all       - Build ALL executables (cleans first)"
	@echo "  android   - Build Android APK using gomobile"
	@echo "  build-android - Build native Android app with professional UI"
	@echo "  terminal  - Build terminal executable"
	@echo "  web       - Build web version executable"
	@echo "  container - Create Podman container image with web version"
	@echo "  run_terminal - Run the terminal version (requires sudo)"
	@echo "  run_web   - Run the web version (requires sudo)"
	@echo "  run_container - Run container with network capabilities (requires sudo)"
	@echo "  run_container_privileged - Run container in privileged mode (requires sudo)"
	@echo "  stop_container - Stop running container"
	@echo "  clean_container - Clean containers and images"
	@echo "  clean     - Clean build artifacts and temporary files"
	@echo "  build          Build the binary"
	@echo "  build-race     Build with race detection"
	@echo "  build-linux    Build for Linux"
	@echo "  build-windows  Build for Windows"
	@echo "  build-darwin   Build for macOS"
	@echo "  build-all      Build for all platforms"
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
	@echo "  install-deps      Install system dependencies (Linux)"
	@echo "  podman-setup      Configure sudo entitlement for podman user"
	@echo "  podman-build      Build Podman image"
	@echo "  podman-clean      Clean Podman images"
	@echo "  podman-run-privileged Run in Podman container (privileged)"
	@echo "  help              Show this help message"
	@echo ""
	@echo "Scripts:"
	@echo "  ./scripts/run.sh - Run terminal version with sudo (interactive)"
	@echo "  ./scripts/run_podman.sh - Run container with full network capabilities (requires sudo)"
	@echo ""
	@echo "Usage examples:"
	@echo "  make build && ./go-shheissee              # Build and run interactively"
	@echo "  make run-monitor                       # Build and start monitoring"
	@echo "  make run PORT=9090                     # Run with custom port"
	@echo "  make build-all                         # Cross-platform build"
	@echo "  make check                             # Run all code checks"

# Default target
.DEFAULT_GOAL := help
