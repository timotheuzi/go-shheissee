package detector

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/boboTheFoff/shheissee-go/internal/logging"
	"github.com/boboTheFoff/shheissee-go/internal/models"
	"github.com/boboTheFoff/shheissee-go/internal/scanners"
)

// AttackDetector coordinates all security scanning and attack detection systems
type AttackDetector struct {
	config           *models.AttackDetectorConfig
	logger           *logging.Logger
	consoleLogger    *logging.ConsoleLogger
	networkScanner   *scanners.NetworkScanner
	bluetoothScanner *scanners.BluetoothScanner
	wifiScanner      *scanners.WiFiScanner
	anomalyDetector  *models.AnomalyDetector
	knownDevices     []string
	knownBtDevices   []models.BluetoothDevice
	attackLog        []models.Attack
	mu               sync.RWMutex
}

// NewAttackDetector creates a new attack detector instance
func NewAttackDetector(config *models.AttackDetectorConfig) (*AttackDetector, error) {
	// Load known devices
	knownDevices, err := scanners.LoadKnownDevices(config.KnownDevicesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load known devices: %v", err)
	}

	knownBtDevices, err := scanners.LoadKnownBluetoothDevices(config.BluetoothDevicesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load known Bluetooth devices: %v", err)
	}

	// Create logger
	logger, err := logging.NewLogger(config.LogFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %v", err)
	}

	consoleLogger := logging.NewConsoleLogger()

	// Create scanners
	networkScanner := scanners.NewNetworkScanner(knownDevices)
	bluetoothScanner := scanners.NewBluetoothScanner(knownBtDevices)
	wifiScanner := scanners.NewWiFiScanner()

	// Create anomaly detector
	anomalyDetector := &models.AnomalyDetector{
		DeviceHistory:     make(map[string]*models.DeviceHistory),
		RSSIHistory:       make(map[string]*models.RSSIHistory),
		ConnectionHistory: make(map[string][]time.Time),
		AnomalyThreshold:  config.AnomalyThreshold,
	}

	detector := &AttackDetector{
		config:           config,
		logger:           logger,
		consoleLogger:    consoleLogger,
		networkScanner:   networkScanner,
		bluetoothScanner: bluetoothScanner,
		wifiScanner:      wifiScanner,
		anomalyDetector:  anomalyDetector,
		knownDevices:     knownDevices,
		knownBtDevices:   knownBtDevices,
		attackLog:        []models.Attack{},
	}

	return detector, nil
}

// StartMonitoring begins continuous security monitoring
func (ad *AttackDetector) StartMonitoring() error {
	ad.consoleLogger.DisplayStatus(len(ad.knownDevices), len(ad.knownBtDevices), len(ad.attackLog))

	for {
		ad.mu.Lock()
		ad.performSecurityScan()
		ad.mu.Unlock()

		time.Sleep(ad.config.ScanInterval)
	}
}

// PerformSecurityScan performs a complete security scan
func (ad *AttackDetector) performSecurityScan() {
	fmt.Print("\n\033[34mScanning for threats...\033[0m\r")

	// Network scan
	networkDevices, networkAttacks, err := ad.networkScanner.ScanNetwork()
	if err != nil {
		ad.logger.LogError("Network scan failed", err)
	} else {
		// Update anomaly detector with network data
		ad.updateAnomalyDetector(networkDevices)

		// Detect AI anomalies
		aiAttacks := ad.detectAIAnomalies()
		networkAttacks = append(networkAttacks, aiAttacks...)

		// Log network attacks
		for _, attack := range networkAttacks {
			ad.logAttack(attack)
		}

		ad.logger.LogScanResult("network", &models.ScanResult{
			Type:      "network",
			Timestamp: time.Now(),
			Devices:   []interface{}{networkDevices},
			Attacks:   networkAttacks,
		})
	}

	// Port scan
	_, portAttacks, err := ad.networkScanner.ScanPorts(networkDevices)
	if err != nil {
		ad.logger.LogError("Port scan failed", err)
	} else {
		for _, attack := range portAttacks {
			ad.logAttack(attack)
		}
	}

	// Bluetooth scan
	bluetoothDevices, err := ad.bluetoothScanner.ScanBluetoothDevices()
	if err != nil {
		ad.logger.LogError("Bluetooth scan failed", err)
	} else {
		// Update anomaly detector with Bluetooth data
		ad.updateBluetoothAnomalyDetector(bluetoothDevices)

		// Detect Bluetooth attacks
		bluetoothAttacks := ad.bluetoothScanner.DetectBluetoothAttacks(bluetoothDevices)
		for _, attack := range bluetoothAttacks {
			ad.logAttack(attack)
		}

		ad.logger.LogScanResult("bluetooth", &models.ScanResult{
			Type:      "bluetooth",
			Timestamp: time.Now(),
			Devices:   []interface{}{bluetoothDevices},
			Attacks:   bluetoothAttacks,
		})
	}

	// WiFi scan
	wifiDevices, err := ad.wifiScanner.ScanWiFiNetworks()
	if err != nil {
		ad.logger.LogError("WiFi scan failed", err)
	} else {
		// Detect WiFi attacks
		wifiAttacks := ad.wifiScanner.DetectWiFiAttacks(wifiDevices)
		for _, attack := range wifiAttacks {
			ad.logAttack(attack)
		}

		ad.logger.LogScanResult("wifi", &models.ScanResult{
			Type:      "wifi",
			Timestamp: time.Now(),
			Devices:   []interface{}{wifiDevices},
			Attacks:   wifiAttacks,
		})
	}

	fmt.Print("\033[32mScan complete. Next scan in 60 seconds...\033[0m\r")
}

// PerformQuickScan performs a quick security assessment
func (ad *AttackDetector) PerformQuickScan() []models.Attack {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	var allAttacks []models.Attack

	// Network scan
	_, networkAttacks, err := ad.networkScanner.ScanNetwork()
	if err == nil {
		allAttacks = append(allAttacks, networkAttacks...)
	}

	// Port scan
	networkDevices, portAttacks, err := ad.networkScanner.ScanNetwork()
	ad.networkScanner.ScanPorts(networkDevices)
	if err == nil {
		allAttacks = append(allAttacks, portAttacks...)
	}

	// Bluetooth scan
	bluetoothDevices, err := ad.bluetoothScanner.ScanBluetoothDevices()
	if err == nil {
		bluetoothAttacks := ad.bluetoothScanner.DetectBluetoothAttacks(bluetoothDevices)
		allAttacks = append(allAttacks, bluetoothAttacks...)
	}

	// WiFi scan
	wifiDevices, err := ad.wifiScanner.ScanWiFiNetworks()
	if err == nil {
		wifiAttacks := ad.wifiScanner.DetectWiFiAttacks(wifiDevices)
		allAttacks = append(allAttacks, wifiAttacks...)
	}

	// Log all detected attacks
	for _, attack := range allAttacks {
		ad.logAttack(attack)
	}

	return allAttacks
}

// ListBluetoothDevices returns a list of nearby Bluetooth devices
func (ad *AttackDetector) ListBluetoothDevices() ([]models.BluetoothDevice, error) {
	return ad.bluetoothScanner.ScanBluetoothDevices()
}

// MonitorBluetoothDevices continuously monitors Bluetooth devices
func (ad *AttackDetector) MonitorBluetoothDevices() error {
	fmt.Println("\033[35mStarting Bluetooth Device Monitor...\033[0m")
	ad.logger.LogInfo("Starting Bluetooth Device Monitor")

	// Simple monitoring loop
	for {
		devices, err := ad.bluetoothScanner.ScanBluetoothDevices()
		if err != nil {
			ad.logger.LogError("Bluetooth monitoring error", err)
		} else {
			ad.displayBluetoothDevices(devices)
		}

		fmt.Println("\033[34mNext scan in 30 seconds...\033[0m")
		time.Sleep(30 * time.Second)
	}
}

// MonitorBluetoothConnections monitors Bluetooth connection attempts
func (ad *AttackDetector) MonitorBluetoothConnections() error {
	fmt.Println("\033[35mStarting Bluetooth Connection Monitor...\033[0m")
	ad.logger.LogInfo("Starting Bluetooth Connection Monitor")

	attackCh, err := ad.bluetoothScanner.MonitorBluetoothConnections()
	if err != nil {
		return err
	}

	for attack := range attackCh {
		ad.logAttack(attack)
	}

	return nil
}

// ListWiFiDevices returns a list of nearby WiFi networks
func (ad *AttackDetector) ListWiFiDevices() ([]models.WiFiDevice, error) {
	return ad.wifiScanner.ScanWiFiNetworks()
}

// PerformDemoAttack creates demo attack scenarios for testing
func (ad *AttackDetector) PerformDemoAttack() error {
	fmt.Println("\033[33mSetting up demo scenario...\033[0m")

	// Create demo network devices
	demoNetwork := []string{
		"192.168.1.10",  // Known
		"192.168.1.20",  // Known
		"192.168.1.30",  // Known
		"192.168.1.50",  // Unknown - will trigger alert
		"10.0.0.100",    // Unknown - will trigger alert
	}

	// Create demo Bluetooth devices
	demoBluetooth := []models.BluetoothDevice{
		{Address: "AA:BB:CC:DD:EE:FF", Name: "Test Device 1"}, // Known
		{Address: "11:22:33:44:55:66", Name: "Test Device 2"}, // Known
		{Address: "FF:EE:DD:CC:BB:AA", Name: "UNKNOWN_HACKER"}, // Unknown - will trigger alert
		{Address: "ATTACK_DEVICE_01", Name: "Attack Device"},   // Suspicious name - will trigger alert
	}

	// Save demo known devices (only first 3 network, first 2 Bluetooth)
	err := scanners.SaveKnownDevices(ad.config.KnownDevicesFile, demoNetwork[:3])
	if err != nil {
		return fmt.Errorf("failed to save demo network devices: %v", err)
	}

	err = scanners.SaveKnownBluetoothDevices(ad.config.BluetoothDevicesFile, demoBluetooth[:2])
	if err != nil {
		return fmt.Errorf("failed to save demo Bluetooth devices: %v", err)
	}

	fmt.Println("\033[32m✅ Demo scenario created!\033[0m")
	fmt.Println("\033[36m📋 Demo includes:\033[0m")
	fmt.Println("   • 3 known network devices")
	fmt.Println("   • 2 unknown network devices (will trigger alerts)")
	fmt.Println("   • 2 known Bluetooth devices")
	fmt.Println("   • 2 unknown/suspicious Bluetooth devices (will trigger alerts)")
	fmt.Printf("\n\033[32m🚀 Run the security monitoring to see attacks detected!\033[0m\n")

	return nil
}

// Helper methods

func (ad *AttackDetector) displayBluetoothDevices(devices []models.BluetoothDevice) {
	if len(devices) == 0 {
		fmt.Println("\033[33mNo Bluetooth devices found nearby.\033[0m")
		return
	}

	fmt.Printf("\n\033[32mFound %d Bluetooth device(s):\033[0m\n", len(devices))
	fmt.Println("\033[1mMAC Address         Device Name                    RSSI   Status\033[0m")
	fmt.Println(strings.Repeat("-", 70))

	for _, device := range devices {
		rssi := "N/A"
		if device.RSSI != 0 {
			rssi = fmt.Sprintf("%d", device.RSSI)
		}

		status := device.Status
		if status == "" {
			status = "Unknown"
		}

		fmt.Printf("%-18s %-30s %-6s %-10s\n",
			device.Address,
			device.Name,
			rssi,
			status)
	}
	fmt.Println()
}

func (ad *AttackDetector) updateAnomalyDetector(devices []models.NetworkDevice) {
	currentTime := time.Now()

	for _, device := range devices {
		ip := device.IP

		// Initialize or update device history
		if ad.anomalyDetector.DeviceHistory[ip] == nil {
			ad.anomalyDetector.DeviceHistory[ip] = &models.DeviceHistory{
				FirstSeen: currentTime,
				Count:     0,
			}
		}

		history := ad.anomalyDetector.DeviceHistory[ip]
		history.LastSeen = currentTime
		history.Count++

		// Track connection history
		ad.anomalyDetector.ConnectionHistory[ip] = append(
			ad.anomalyDetector.ConnectionHistory[ip],
			currentTime,
		)

		// Keep only recent connection history
		if len(ad.anomalyDetector.ConnectionHistory[ip]) > 20 {
			ad.anomalyDetector.ConnectionHistory[ip] = ad.anomalyDetector.ConnectionHistory[ip][1:]
		}
	}
}

func (ad *AttackDetector) updateBluetoothAnomalyDetector(devices []models.BluetoothDevice) {
	currentTime := time.Now()

	for _, device := range devices {
		mac := device.Address

		if ad.anomalyDetector.DeviceHistory[mac] == nil {
			ad.anomalyDetector.DeviceHistory[mac] = &models.DeviceHistory{
				FirstSeen: currentTime,
				Count:     0,
			}
		}

		history := ad.anomalyDetector.DeviceHistory[mac]
		history.LastSeen = currentTime
		history.Count++

		// Track RSSI history if available
		if device.RSSI != 0 {
			if ad.anomalyDetector.RSSIHistory[mac] == nil {
				ad.anomalyDetector.RSSIHistory[mac] = &models.RSSIHistory{}
			}

			rssiHist := ad.anomalyDetector.RSSIHistory[mac]
			rssiHist.Values = append(rssiHist.Values, device.RSSI)
			rssiHist.Times = append(rssiHist.Times, currentTime)

			// Keep only recent RSSI values
			if len(rssiHist.Values) > 10 {
				rssiHist.Values = rssiHist.Values[1:]
				rssiHist.Times = rssiHist.Times[1:]
			}
		}
	}
}

func (ad *AttackDetector) detectAIAnomalies() []models.Attack {
	var attacks []models.Attack

	// Check for unusual connection patterns
	for mac, history := range ad.anomalyDetector.ConnectionHistory {
		if len(history) >= 10 {
			// Check for too frequent connections
			if isUnusualConnectionPattern(history) {
				attacks = append(attacks, models.Attack{
					Type:        "AI_CONNECTION_ANOMALY",
					Severity:    models.SeverityHigh,
					Description: fmt.Sprintf("AI detected unusually frequent connections from device %s", mac),
					Target:      mac,
					Timestamp:   time.Now(),
				})
			}
		}
	}

	// Check for sudden RSSI changes
	for mac, rssiHist := range ad.anomalyDetector.RSSIHistory {
		if len(rssiHist.Values) >= 5 {
			if isUnusualRSSIPattern(rssiHist.Values) {
				attacks = append(attacks, models.Attack{
					Type:        "AI_RSSI_ANOMALY",
					Severity:    models.SeverityMedium,
					Description: fmt.Sprintf("AI detected anomalous RSSI behavior for device %s", mac),
					Target:      mac,
					Timestamp:   time.Now(),
				})
			}
		}
	}

	// Check for mass device appearance
	recentDeviceCount := 0
	for _, history := range ad.anomalyDetector.DeviceHistory {
		if time.Since(history.LastSeen) < time.Minute {
			recentDeviceCount++
		}
	}

	if recentDeviceCount > 3 {
		attacks = append(attacks, models.Attack{
			Type:        "AI_MASS_DEVICE_ANOMALY",
			Severity:    models.SeverityHigh,
			Description: fmt.Sprintf("AI detected mass appearance of %d unknown devices - potential scanning attack", recentDeviceCount),
			Target:      "network",
			Timestamp:   time.Now(),
		})
	}

	return attacks
}

func (ad *AttackDetector) logAttack(attack models.Attack) {
	ad.attackLog = append(ad.attackLog, attack)
	ad.logger.LogAttack(&attack)
	ad.consoleLogger.DisplayAttack(&attack)
}

// GetAttackCount returns the total number of detected attacks
func (ad *AttackDetector) GetAttackCount() int {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	return len(ad.attackLog)
}

// GetRecentAttacks returns the most recent attacks
func (ad *AttackDetector) GetRecentAttacks(limit int) []models.Attack {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	start := len(ad.attackLog) - limit
	if start < 0 {
		start = 0
	}

	return ad.attackLog[start:]
}

// Close shuts down the attack detector and cleans up resources
func (ad *AttackDetector) Close() error {
	return ad.logger.Close()
}

// Utility functions

func isUnusualConnectionPattern(timestamps []time.Time) bool {
	if len(timestamps) < 2 {
		return false
	}

	// Calculate average interval between connections
	totalInterval := timestamps[len(timestamps)-1].Sub(timestamps[0])
	avgInterval := totalInterval / time.Duration(len(timestamps)-1)

	// Flag if connections are too frequent (less than 10 seconds average)
	return avgInterval < 10*time.Second
}

func isUnusualRSSIPattern(rssiValues []int) bool {
	if len(rssiValues) < 2 {
		return false
	}

	// Simple heuristic: check for rapid changes
	recent := rssiValues[len(rssiValues)-1]
	previous := rssiValues[len(rssiValues)-2]

	// Flag sudden change of more than 20 dBm
	diff := recent - previous
	if diff < 0 {
		diff = -diff
	}

	return diff > 20
}
