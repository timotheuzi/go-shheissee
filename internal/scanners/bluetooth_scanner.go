package scanners

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/boboTheFoff/shheissee-go/internal/models"
)

// BluetoothScanner handles Bluetooth device discovery and attack detection
type BluetoothScanner struct {
	knownDevices map[string]bool
}

// NewBluetoothScanner creates a new Bluetooth scanner
func NewBluetoothScanner(knownDevices []models.BluetoothDevice) *BluetoothScanner {
	knownMap := make(map[string]bool)
	for _, device := range knownDevices {
		knownMap[device.Address] = true
	}
	return &BluetoothScanner{
		knownDevices: knownMap,
	}
}

// ScanBluetoothDevices discovers nearby Bluetooth devices
func (bs *BluetoothScanner) ScanBluetoothDevices() ([]models.BluetoothDevice, error) {
	if !isCommandAvailable("bluetoothctl") {
		// Try other methods or return empty
		return []models.BluetoothDevice{}, fmt.Errorf("bluetoothctl not available")
	}

	// Use bluetoothctl to scan for devices
	devices, err := bs.scanWithBluetoothctl()
	if err != nil {
		// Fallback to other methods if available
		devices, err = bs.scanWithHcitool()
		if err != nil {
			return nil, fmt.Errorf("no Bluetooth scanning method available: %v", err)
		}
	}

	return devices, nil
}

// scanWithBluetoothctl uses bluetoothctl to scan for devices
func (bs *BluetoothScanner) scanWithBluetoothctl() ([]models.BluetoothDevice, error) {
	// Start scan
	scanCmd := exec.Command("bluetoothctl", "scan", "on")
	scanCmd.Start()

	// Wait for scanning to start
	time.Sleep(2 * time.Second)

	// Stop scan and list devices
	stopScanCmd := exec.Command("bluetoothctl", "scan", "off")
	stopScanCmd.Run()

	// Get device list
	listCmd := exec.Command("bluetoothctl", "devices")
	output, err := listCmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return bs.parseBluetoothctlOutput(string(output)), nil
}

// scanWithHcitool uses hcitool as alternative
func (bs *BluetoothScanner) scanWithHcitool() ([]models.BluetoothDevice, error) {
	if !isCommandAvailable("hcitool") {
		return nil, fmt.Errorf("hcitool not available")
	}

	// Scan for devices
	cmd := exec.Command("hcitool", "scan", "--flush")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return bs.parseHcitoolOutput(string(output)), nil
}

// parseBluetoothctlOutput parses bluetoothctl devices output
func (bs *BluetoothScanner) parseBluetoothctlOutput(output string) []models.BluetoothDevice {
	var devices []models.BluetoothDevice

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Device ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				mac := parts[1]
				name := strings.Join(parts[2:], " ")

				device := models.BluetoothDevice{
					Address: mac,
					Name:    name,
				}

				// Determine status
				if bs.knownDevices[mac] {
					device.Status = "Known"
				} else {
					device.Status = "Unknown"
				}

				devices = append(devices, device)
			}
		}
	}

	return devices
}

// parseHcitoolOutput parses hcitool scan output
func (bs *BluetoothScanner) parseHcitoolOutput(output string) []models.BluetoothDevice {
	var devices []models.BluetoothDevice

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		// Skip header line
		if strings.HasPrefix(line, "\t") || strings.Contains(line, "Scanning") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			mac := parts[0]
			name := strings.Join(parts[1:], " ")

			device := models.BluetoothDevice{
				Address: mac,
				Name:    name,
			}

			// Determine status
			if bs.knownDevices[mac] {
				device.Status = "Known"
			} else {
				device.Status = "Unknown"
			}

			devices = append(devices, device)
		}
	}

	return devices
}

// DetectBluetoothAttacks analyzes Bluetooth devices for attack patterns
func (bs *BluetoothScanner) DetectBluetoothAttacks(devices []models.BluetoothDevice) []models.Attack {
	var attacks []models.Attack

	// KNOB Attack Detection - Very close proximity devices
	for _, device := range devices {
		rssi := device.RSSI
		if rssi > -20 { // Very close devices
			attacks = append(attacks, models.Attack{
				Type:        "KNOB_ATTACK",
				Severity:    models.SeverityHigh,
				Description: fmt.Sprintf("Potential KNOB attack: Device extremely close (%s, RSSI: %d)", device.Name, rssi),
				Target:      device.Address,
				Timestamp:   time.Now(),
			})
		}
	}

	// BIAS Attack Detection - Duplicate device names
	nameCounts := make(map[string][]string)
	for _, device := range devices {
		if device.Name != "" {
			nameCounts[device.Name] = append(nameCounts[device.Name], device.Address)
		}
	}

	for name, addresses := range nameCounts {
		if len(addresses) > 1 {
			attacks = append(attacks, models.Attack{
				Type:        "BIAS_ATTACK",
				Severity:    models.SeverityHigh,
				Description: fmt.Sprintf("Potential BIAS attack: Multiple devices with same name '%s' (%d devices)", name, len(addresses)),
				Target:      strings.Join(addresses, ", "),
				Timestamp:   time.Now(),
			})
		}
	}

	// Mass Scanning Detection
	if len(devices) > 20 {
		attacks = append(attacks, models.Attack{
			Type:        "BLUETOOTH_MASS_SCANNING",
			Severity:    models.SeverityMedium,
			Description: fmt.Sprintf("Mass scanning detected: %d Bluetooth devices found (unusual activity)", len(devices)),
			Target:      "bluetooth_network",
			Timestamp:   time.Now(),
		})
	}

	// BLE Relay Attack Detection - Weak signals
	for _, device := range devices {
		if device.RSSI < -80 { // Very weak signal
			attacks = append(attacks, models.Attack{
				Type:        "BLE_RELAY_ATTACK",
				Severity:    models.SeverityMedium,
				Description: fmt.Sprintf("Potential BLE relay attack: Weak signal device (%s, RSSI: %d)", device.Name, device.RSSI),
				Target:      device.Address,
				Timestamp:   time.Now(),
			})
		}
	}

	// BlueBorne Vulnerability Detection
	vulnerablePatterns := map[string]string{
		"android": "Android device - check for BlueBorne vulnerabilities",
		"ios":     "iOS device - check for BlueBorne vulnerabilities",
		"linux":   "Linux device - check for BlueBorne vulnerabilities",
		"windows": "Windows device - check for BlueBorne vulnerabilities",
	}

	for _, device := range devices {
		nameLower := strings.ToLower(device.Name)
		for pattern, desc := range vulnerablePatterns {
			if strings.Contains(nameLower, pattern) {
				attacks = append(attacks, models.Attack{
					Type:        "BLUEBORNE_VULNERABILITY",
					Severity:    models.SeverityHigh,
					Description: fmt.Sprintf("Potential BlueBorne vulnerable device: %s (%s) - %s", device.Name, device.Address, desc),
					Target:      device.Address,
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	// Proximity Attack Detection
	for _, device := range devices {
		if device.RSSI > -30 { // Too close
			attacks = append(attacks, models.Attack{
				Type:        "BLUETOOTH_PROXIMITY",
				Severity:    models.SeverityMedium,
				Description: fmt.Sprintf("Device too close (possible attack): %s (%s, RSSI: %d)", device.Name, device.Address, device.RSSI),
				Target:      device.Address,
				Timestamp:   time.Now(),
			})
		}
	}

	// Spoofing Detection
	suspiciousNames := []string{"attack", "hack", "exploit", "test", "spoof", "evil", "malware", "virus"}
	for _, device := range devices {
		nameLower := strings.ToLower(device.Name)
		for _, suspicious := range suspiciousNames {
			if strings.Contains(nameLower, suspicious) {
				attacks = append(attacks, models.Attack{
					Type:        "BLUETOOTH_SPOOFING",
					Severity:    models.SeverityHigh,
					Description: fmt.Sprintf("Suspicious Bluetooth device name: %s (%s)", device.Name, device.Address),
					Target:      device.Address,
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	// BLE Flooding Detection
	bleDevices := 0
	for _, device := range devices {
		if strings.HasPrefix(device.Address, "00:") ||
		   strings.HasPrefix(device.Address, "01:") ||
		   strings.HasPrefix(device.Address, "02:") {
			bleDevices++
		}
	}
	if bleDevices > 10 {
		attacks = append(attacks, models.Attack{
			Type:        "BLE_FLOODING",
			Severity:    models.SeverityMedium,
			Description: fmt.Sprintf("BLE flooding attack suspected: %d BLE devices detected", bleDevices),
			Target:      "ble_network",
			Timestamp:   time.Now(),
		})
	}

	// Man-in-the-Middle Detection
	mitmPatterns := map[string]string{
		"proxy":    "proxy",
		"gateway":  "gateway",
		"bridge":   "bridge",
		"intercept": "intercept",
	}

	for _, device := range devices {
		nameLower := strings.ToLower(device.Name)
		for pattern, desc := range mitmPatterns {
			if strings.Contains(nameLower, pattern) {
				attacks = append(attacks, models.Attack{
					Type:        "BLUETOOTH_MITM",
					Severity:    models.SeverityHigh,
					Description: fmt.Sprintf("Potential Man-in-the-Middle device: %s (%s) - appears to be %s", device.Name, device.Address, desc),
					Target:      device.Address,
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	// Unknown Device Detection
	for _, device := range devices {
		if !bs.knownDevices[device.Address] {
			attacks = append(attacks, models.Attack{
				Type:        "UNKNOWN_BLUETOOTH",
				Severity:    models.SeverityHigh,
				Description: fmt.Sprintf("Unknown Bluetooth device: %s (%s)", device.Name, device.Address),
				Target:      device.Address,
				Timestamp:   time.Now(),
			})
		}
	}

	return attacks
}

// MonitorBluetoothConnections monitors Bluetooth connection attempts
func (bs *BluetoothScanner) MonitorBluetoothConnections() (<-chan models.Attack, error) {
	if !isCommandAvailable("bluetoothctl") {
		return nil, fmt.Errorf("bluetoothctl not available for connection monitoring")
	}

	attackCh := make(chan models.Attack, 100)

	go func() {
		defer close(attackCh)

		// Start bluetoothctl monitor
		cmd := exec.Command("bluetoothctl", "--monitor")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return
		}

		if err := cmd.Start(); err != nil {
			return
		}

		scanner := bufio.NewScanner(stdout)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			timestamp := time.Now()

			// Connection events
			if strings.Contains(line, "Device connected") {
				if mac := bs.extractMAC(line); mac != "" {
					attackCh <- models.Attack{
						Type:        "BLUETOOTH_CONNECTION_ATTEMPT",
						Severity:    models.SeverityMedium,
						Description: fmt.Sprintf("Bluetooth connection/pairing attempt from device (%s)", mac),
						Target:      mac,
						Timestamp:   timestamp,
					}
				}
			}

			// Pairing events
			if strings.Contains(line, "PIN") || strings.Contains(line, "Passkey") {
				if mac := bs.extractMAC(line); mac != "" {
					attackCh <- models.Attack{
						Type:        "BLUETOOTH_AUTH_ATTEMPT",
						Severity:    models.SeverityHigh,
						Description: fmt.Sprintf("Bluetooth authentication attempt from device (%s)", mac),
						Target:      mac,
						Timestamp:   timestamp,
					}
				}
			}
		}
	}()

	return attackCh, nil
}

// Helper functions

func (bs *BluetoothScanner) extractMAC(text string) string {
	// Extract MAC address from text like "Device AA:BB:CC:DD:EE:FF connected"
	macRegex := regexp.MustCompile(`([A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2})`)
	matches := macRegex.FindStringSubmatch(text)
	if len(matches) > 1 {
		return strings.ToUpper(matches[1])
	}
	return ""
}

// LoadKnownBluetoothDevices loads known Bluetooth devices from file
func LoadKnownBluetoothDevices(filename string) ([]models.BluetoothDevice, error) {
	var devices []models.BluetoothDevice

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// Create empty file
			devices = []models.BluetoothDevice{}
			data, _ := json.MarshalIndent(devices, "", "  ")
			_ = os.WriteFile(filename, data, 0644)
			return devices, nil
		}
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&devices)
	return devices, err
}

// SaveKnownBluetoothDevices saves known Bluetooth devices to file
func SaveKnownBluetoothDevices(filename string, devices []models.BluetoothDevice) error {
	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return err
	}

	// Create directory if needed
	os.MkdirAll(strings.TrimSuffix(filename, "/"+strings.Split(filename, "/")[len(strings.Split(filename, "/"))-1]), 0755)

	return os.WriteFile(filename, data, 0644)
}

// parseRSSI parses RSSI value from string
func parseRSSI(rssiStr string) int {
	if val, err := strconv.Atoi(strings.TrimSpace(rssiStr)); err == nil {
		return val
	}
	return 0
}
