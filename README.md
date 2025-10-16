[![Go Version](https://img.shields.io/badge/Go-1.21-blue.svg)](https://golang.org)
[![Build Status](https://github.com/boboTheFoff/shheissee-go/workflows/build/badge.svg)](https://github.com/boboTheFoff/shheissee-go/actions?workflow=build)
[![Go Report Card](https://goreportcard.com/badge/github.com/boboTheFoff/shheissee-go)](https://goreportcard.com/report/github.com/boboTheFoff/shheissee-go)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)

# Go-Shheissee - Advanced Network & Wireless Intrusion Detection System

An intelligent AI-powered system designed to detect and warn about network intrusions, Bluetooth attacks, and WiFi threats in real-time with a beautiful web user interface. This is a complete rewrite of the original Python version in Go for better performance and cross-platform compatibility.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [API](#api)
- [Detection Rules](#detection-rules)
- [Contributing](#contributing)
- [License](#license)

## 🚀 Quick Start

**Prerequisites:**
```bash
# Install Go 1.21 or later
# On Ubuntu/Debian:
sudo apt update && sudo apt install golang-go

# On CentOS/RHEL:
sudo yum install golang

# Or download from https://golang.org/dl/
```

**Build and run:**
```bash
cd go-shh

# Build the application
go build -o shheissee ./cmd/shheissee

# Run the interactive menu
./shheissee

# Or run directly with commands
./shheissee monitor    # Start continuous monitoring
./shheissee scan       # Quick security scan
./shheissee bluetooth  # Bluetooth device monitor
./shheissee demo       # Setup demo scenario

# Using Makefile (recommended)
make run            # Run with default port (8080)
make run-monitor    # Run monitor with default port
PORT=9090 make run  # Run with custom port
```

**What happens automatically:**
- 🧹 Creates necessary directories and files
- 🔨 Builds scanning capabilities for network, Bluetooth, and WiFi
- 🚀 Starts the web interface on http://localhost:8080 (or custom port if configured)
- 📊 Begins continuous monitoring if started in monitor mode

## ✨ Features

### 🔍 Network Monitoring
- Continuous scanning of network devices
- Automatic detection of new and disappeared devices
- Real-time port analysis and suspicious activity detection
- Unknown device alerts with IP address tracking

### 📡 Bluetooth Attack Detection
- **Bluetooth Device Discovery**: Scans for nearby Bluetooth devices
- **KNOB Attack Detection**: Identifies devices with unusually strong signals (very close proximity)
- **BIAS Attack Detection**: Detects duplicate device names indicating impersonation
- **BlueBorne Vulnerability Scanning**: Identifies devices vulnerable to BlueBorne exploits
- **BLE Relay Attack Detection**: Monitors for weak signal devices that could be relayed
- **Mass Scanning Detection**: Alerts on unusual numbers of Bluetooth devices
- **BLE Flooding Detection**: Identifies excessive BLE device advertisements
- **Man-in-the-Middle Detection**: Flags devices with proxy/gateway naming patterns
- **Attack Pattern Recognition**: Detects common Bluetooth vulnerabilities
- **Proximity Detection**: Alerts for devices that are too close (potential attacks)
- **Device Spoofing Detection**: Identifies suspicious device names
- **Known Device Tracking**: Maintains whitelist of authorized Bluetooth devices
- **AI Anomaly Detection**: Uses machine learning to detect unusual device behavior patterns

### 🌐 WiFi Attack Detection
- **Rogue Access Point Detection**: Identifies potentially malicious WiFi networks
- **Deauthentication Attack Monitoring**: Detects WiFi deauth attacks
- **Evil Twin Detection**: Identifies duplicate SSID networks (potential man-in-the-Middle)
- **WPS Vulnerability Scanning**: Detects networks vulnerable to pixie dust and brute force attacks
- **Open Network Detection**: Identifies unencrypted WiFi networks
- **Weak Encryption Detection**: Flags WEP-encrypted networks
- **Suspicious SSID Analysis**: Flags networks with suspicious names

### 🚨 Advanced Intrusion Detection
- **Multi-layered Threat Detection**: Network + Bluetooth + WiFi monitoring
- **AI Anomaly Detection**: Machine learning-based detection of unusual device behavior patterns
- **RSSI Anomaly Detection**: Identifies sudden signal strength changes (potential relay attacks)
- **Connection Pattern Analysis**: Detects unusual connection frequency and timing
- **Mass Device Anomaly Detection**: Alerts on sudden appearance of multiple unknown devices
- **Severity-based Classification**: Low, Medium, High priority alerts
- **Real-time Notifications**: Color-coded alerts with detailed descriptions
- **Unknown Device Detection**: Immediate alerts for unauthorized devices
- **Suspicious Port Analysis**: Identifies dangerous open ports (RDP:3389, Telnet:23, FTP:21, SMB:445)

### 🎨 Beautiful Web User Interface
- **Modern Web Dashboard**: Built with HTML5, CSS3, and responsive design
- **Real-time Statistics**: Live attack count and severity breakdown
- **Color-coded Alerts**: Red (High), Yellow (Medium), Blue (Low) severity
- **Real-time Status Display**: Live monitoring statistics
- **Detailed Attack Reports**: Comprehensive information for each threat
- **Progress Indicators**: Visual feedback during scanning
- **Clean Interface**: Professional, easy-to-read design

### 📊 Comprehensive Logging & Reporting
- Detailed logging of all detected intrusions to `log/intrusion_log.log`
- Severity-based classification with timestamps
- Persistent storage of known devices in JSON format
- Attack history tracking with full details
- Web API for external integrations

## Installation

### System Dependencies

**For full functionality, install these system tools:**

```bash
# Ubuntu/Debian:
sudo apt update
sudo apt install wireless-tools nmap bluetooth bluez bluez-tools

# CentOS/RHEL/Fedora:
sudo dnf install wireless-tools nmap bluez bluez-tools

# Arch Linux:
sudo pacman -S wireless_tools nmap bluez bluez-utils
```

**Required system tools:**
- `bluetoothctl` - For Bluetooth device scanning and monitoring
- `hcitool` - Alternative Bluetooth scanning (falls back automatically)
- `iwlist` - For WiFi network scanning
- `nmcli` - Alternative WiFi scanning
- `nmap` - For network port scanning
- `fping` or `ping` - For basic network device discovery

### Go Installation

**Option 1: System package manager**
```bash
# Ubuntu/Debian:
sudo apt install golang-go

# CentOS/RHEL:
sudo yum install golang

# Arch Linux:
sudo pacman -S go
```

**Option 2: Manual installation**
```bash
# Download from https://golang.org/dl/
wget https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Building from Source

```bash
cd go-shh

# Install dependencies
go mod download

# Build the application
go build -o shheissee ./cmd/shheissee

# Optional: Build for multiple platforms
GOOS=linux GOARCH=amd64 go build -o shheissee-linux-amd64 ./cmd/shheissee
GOOS=windows GOARCH=amd64 go build -o shheissee-windows-amd64.exe ./cmd/shheissee
GOOS=darwin GOARCH=amd64 go build -o shheissee-macos-amd64 ./cmd/shheissee
```

## Usage

### Interactive Menu Mode

```bash
./shheissee
```

This starts the interactive menu with these options:
1. **Run Full Security Monitoring** - Start continuous monitoring
2. **List Nearby Bluetooth Devices** - Show Bluetooth devices
3. **Monitor Bluetooth Devices Continuously** - Real-time Bluetooth monitoring
4. **Monitor Bluetooth Connection Attempts** - Watch pairing/auth attempts
5. **Perform Quick Security Scan** - Single scan of all systems
6. **List Nearby WiFi Devices** - Show WiFi networks/devices
7. **Exit** - Quit the application

### Command Line Mode

```bash
# Start continuous monitoring
./shheissee monitor
./shheissee start

# Quick security scan
./shheissee scan

# Bluetooth monitoring only
./shheissee bluetooth

# Setup demo scenario
./shheissee demo

# Web server only
./shheissee web
```

### Web Interface

The web interface is automatically started with the application and available at:
**http://localhost:8080**

Features include:
- **Dashboard**: Overview with statistics and quick links
- **Intrusion Detection**: Full attack log with real-time updates
- **API Endpoints**: RESTful API for external integrations

### API Endpoints

```bash
# Get recent attacks (JSON)
curl http://localhost:8080/api/attacks

# Get system status (JSON)
curl http://localhost:8080/api/status

# Get attacks with limit (JSON)
curl http://localhost:8080/api/attacks?limit=10
```

## Configuration

### Default Configuration

The application uses sensible defaults but can be extended:

```go
// Default settings in internal/models/models.go
type AttackDetectorConfig struct {
    KnownDevicesFile     string        // "model/known_devices.json"
    BluetoothDevicesFile string        // "model/known_bluetooth_devices.json"
    LogFile             string        // "log/intrusion_log.log"
    ScanInterval        time.Duration // 60 seconds
    AnomalyThreshold    float64       // 2.0 standard deviations
    WebServerPort       int           // 8080
}
```

### Known Devices Files

**Network devices** (`model/known_devices.json`):
```json
["192.168.1.10", "192.168.1.20", "192.168.1.100"]
```

**Bluetooth devices** (`model/known_bluetooth_devices.json`):
```json
[
  {"address": "AA:BB:CC:DD:EE:FF", "name": "My Phone"},
  {"address": "11:22:33:44:55:66", "name": "My Speaker"}
]
```

## Detection Rules

### Device-Based Detection
- **Unknown Device**: Any IP/MAC not previously seen on the network
- **Device Disappeared**: Known device no longer responding to scans
- **Unusual Device Count**: Sudden appearance of multiple new devices

### Port-Based Detection
- **Suspicious Ports**: RDP (3389), Telnet (23), FTP (21), SMB (445)
- **Multiple Open Ports**: More than 5 ports open on a single device
- **Unauthorized Services**: Common attack vectors

### Bluetooth Attack Detection
- **Discovery Attack**: Unknown Bluetooth devices appearing in scans
- **Device Spoofing**: Suspicious device names containing attack-related keywords
- **KNOB Attack**: Devices with unusually strong signals (very close proximity)
- **BIAS Attack**: Duplicate device names indicating impersonation attempts
- **Mass Scanning**: Unusual number of Bluetooth devices detected (>20)

### WiFi Attack Detection
- **Evil Twin**: Duplicate SSID networks with different MAC addresses
- **Rogue AP**: Access points with suspicious naming patterns
- **Weak Encryption**: WEP encryption detection
- **Open Networks**: Networks without any encryption

## Docker Support

Build the Docker image:
```bash
docker build -t shheissee-go .
```

Run in container:
```bash
docker run --privileged --net=host shheissee-go monitor
```

## Troubleshooting

### Common Issues

**"command not found" errors:**
```bash
# Install missing system tools
sudo apt install wireless-tools nmap bluetooth bluez bluez-tools
```

**Bluetooth not working:**
```bash
# Ensure Bluetooth service is running
sudo systemctl start bluetooth
sudo systemctl enable bluetooth

# Add user to bluetooth group
sudo usermod -a -G bluetooth $USER
# Log out and back in for group changes to take effect
```

**Permission denied:**
```bash
# Run with elevated permissions if needed
sudo ./shheissee monitor
```

**Web interface not accessible:**
```bash
# Check if port 8080 is available
netstat -tlnp | grep :8080

# Change port using Makefile
PORT=8081 make run

# Or run directly with environment variable
APP_PORT=8081 ./shheissee
```

**No devices found:**
```bash
# Network/WiFi: Check wireless interface is up
iwconfig

# Bluetooth: Check Bluetooth adapter status
bluetoothctl show
```

### Debug Mode

Enable verbose logging by checking the log file:
```bash
tail -f log/intrusion_log.log
```

### Performance Tuning

Adjust scan intervals in `internal/models/models.go`:
```go
ScanInterval: 30 * time.Second,  // More frequent scanning
ScanInterval: 120 * time.Second, // Less frequent scanning
```

## Architecture

### Core Components

#### Models Package (`internal/models/`)
- Data structures and types
- Configuration management
- Color constants and severity levels

#### Logging Package (`internal/logging/`)
- File and console logging
- Attack event logging
- Formatted output for terminals

#### Scanners Package (`internal/scanners/`)
- **Network Scanner**: Device discovery and port scanning
- **Bluetooth Scanner**: BLE device detection and attack analysis
- **WiFi Scanner**: Wireless network monitoring and deauth detection

#### Detector Package (`internal/detector/`)
- Main coordination logic
- AI anomaly detection
- Attack pattern recognition

#### Web Package (`internal/web/`)
- HTTP server with Gorilla Mux
- HTML template rendering
- REST API endpoints

### Detection Flow

1. **Network Scan**: Discover active devices using nmap/fping
2. **Port Analysis**: Scan for open ports on discovered devices
3. **Bluetooth Scan**: Use bluetoothctl to discover BLE devices
4. **WiFi Scan**: Monitor wireless networks with iwlist/nmcli
5. **Attack Detection**: Apply rules and ML algorithms to identify threats
6. **Logging**: Record all events to files and console
7. **Web Update**: Push real-time updates to web interface
8. **Repeat**: Continuous monitoring based on scan interval

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`go test ./...`)
5. Format code (`go fmt ./...`)
6. Commit changes (`git commit -am 'Add amazing feature'`)
7. Push to branch (`git push origin feature/amazing-feature`)
8. Create a Pull Request

### Development Setup

```bash
# Clone repository
git clone https://github.com/boboTheFoff/shheissee-go.git
cd shheissee-go

# Install development dependencies
go mod download

# Run tests
go test ./...

# Format code
go fmt ./...

# Vet code
go vet ./...

# Build with race detection
go build -race -o shheissee ./cmd/shheissee
```

## Security Considerations

- Run with appropriate network permissions
- Regularly review and update known devices lists
- Monitor log files for false positives
- Consider integrating with existing security systems
- The web interface should be protected in production environments

## License

This software is protected by copyright. See the original Python version license for details.

## Credits

Original Python implementation by Maggotcorp and Timotheuzi.

Go rewrite for improved performance and maintainability.
