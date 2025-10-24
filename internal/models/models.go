package models

import (
	"os"
	"strconv"
	"time"
)

// Colors for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

// Severity levels for attacks
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

// Attack represents a detected security threat
type Attack struct {
	Type       string    `json:"type"`
	Severity   Severity  `json:"severity"`
	Description string   `json:"description"`
	Target     string    `json:"target"`
	Timestamp  time.Time `json:"timestamp"`
}

// NetworkDevice represents a device on the network
type NetworkDevice struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac,omitempty"`
	Name   string `json:"name,omitempty"`
	State  string `json:"state,omitempty"`
	Ports  []Port `json:"ports,omitempty"`
}

// Port represents an open port on a device
type Port struct {
	Number   int    `json:"number"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	State    string `json:"state"`
}

// BluetoothDevice represents a Bluetooth device
type BluetoothDevice struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
	RSSI    int    `json:"rssi,omitempty"`
	Status  string `json:"status"`
}

// WiFiDevice represents a WiFi access point or device
type WiFiDevice struct {
	Address string `json:"address"`
	SSID    string `json:"ssid,omitempty"`
	Signal  string `json:"signal,omitempty"`
	Channel string `json:"channel,omitempty"`
	Status  string `json:"status"`
}

// KnownDevices contains lists of known/authorized devices
type KnownDevices struct {
	NetworkDevices  []string `json:"network_devices"`
	BluetoothDevices []BluetoothDevice `json:"bluetooth_devices"`
	WiFiDevices     []string `json:"wifi_devices"`
}

// ScanResult represents the result of a scan operation
type ScanResult struct {
	Type      string         `json:"type"`
	Timestamp time.Time      `json:"timestamp"`
	Devices   []interface{}  `json:"devices,omitempty"`
	Attacks   []Attack       `json:"attacks,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// AttackDetectorConfig represents configuration for the attack detector
type AttackDetectorConfig struct {
	KnownDevicesFile        string        `json:"known_devices_file"`
	BluetoothDevicesFile    string        `json:"bluetooth_devices_file"`
	LogFile                 string        `json:"log_file"`
	ScanInterval            time.Duration `json:"scan_interval"`
	AnomalyThreshold        float64       `json:"anomaly_threshold"`
	WebServerPort           int           `json:"web_server_port"`
}

// DefaultConfig returns default configuration
func DefaultConfig() *AttackDetectorConfig {
	port := 8080
	if portStr := os.Getenv("APP_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	return &AttackDetectorConfig{
		KnownDevicesFile:        "model/known_devices.json",
		BluetoothDevicesFile:    "model/known_bluetooth_devices.json",
		LogFile:                 "log/intrusion_log.log",
		ScanInterval:            60 * time.Second,
		AnomalyThreshold:        2.0,
		WebServerPort:           port,
	}
}

// RSSIHistory tracks RSSI values for anomaly detection
type RSSIHistory struct {
	Values []int `json:"values"`
	Times  []time.Time `json:"times"`
}

// DeviceHistory tracks device appearance history for anomaly detection
type DeviceHistory struct {
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
	RSSI      *RSSIHistory `json:"rssi,omitempty"`
}

// AnomalyDetector holds data for AI-based anomaly detection
type AnomalyDetector struct {
	DeviceHistory     map[string]*DeviceHistory      `json:"device_history"`
	RSSIHistory       map[string]*RSSIHistory        `json:"rssi_history"`
	ConnectionHistory map[string][]time.Time         `json:"connection_history"`
	AnomalyThreshold  float64                        `json:"anomaly_threshold"`
}
