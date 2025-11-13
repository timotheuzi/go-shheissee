package monitors

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// runCommandOrSudo attempts to run a command first as regular user, then with sudo if it fails with permission errors
func runCommandOrSudo(cmd *exec.Cmd, expectedErrorPatterns []string) (*exec.Cmd, []byte, error) {
	// First try without sudo
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if this is a permission error by looking for common sudo-required error patterns
		errorStr := string(output) + err.Error()
		needsSudo := false

		// Check for permission-related errors
		sudoIndicators := []string{
			"Permission denied",
			"Operation not permitted",
			"Device or resource busy",
			"interface not in monitor mode",
			"no such device",
			"rtl_power: failed to open rtl",
		}

		// Add any command-specific error patterns
		for _, pattern := range expectedErrorPatterns {
			sudoIndicators = append(sudoIndicators, pattern)
		}

		for _, indicator := range sudoIndicators {
			if strings.Contains(errorStr, indicator) {
				needsSudo = true
				break
			}
		}

		if needsSudo {
			log.Printf("Permission error detected, retrying with sudo: %v", cmd.Args)
			// Retry with sudo, but first check if sudo is available
			if sudoPath, sudoErr := exec.LookPath("sudo"); sudoErr == nil {
				sudoCmd := exec.Command(sudoPath)
				sudoCmd.Args = append([]string{sudoPath}, cmd.Args...)
				sudoOutput, sudoErr := sudoCmd.CombinedOutput()
				return sudoCmd, sudoOutput, sudoErr
			} else {
				// Sudo not available, return original error
				return cmd, output, err
			}
		}
	}
	return cmd, output, err
}

type WifiAP struct {
	BSSID   string `json:"bssid"`
	PWR     int    `json:"pwr"`
	Beacons int    `json:"beacons"`
	ENC     string `json:"enc"`
	ESSID   string `json:"essid"`
}

type WifiClient struct {
	MAC     string `json:"mac"`
	APMAC   string `json:"apmac"`
	PWR     int    `json:"pwr"`
	Lost    int    `json:"lost"`
}

type BluetoothDevice struct {
	Address string `json:"address"`
	Name    string `json:"name"`
}

type BLEDevice struct {
	Address string `json:"address"`
	Data    string `json:"data"`
	RSSI    int    `json:"rssi"`
}

type Attack struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Target      string    `json:"target"`
	Timestamp   time.Time `json:"timestamp"`
}

type RadioInfo struct {
	HasSDR                  bool     `json:"has_sdr"`
	SDRDevices              []string `json:"sdr_devices"`
	SubGHzSignalsDetected   bool     `json:"sub_ghz_signals_detected"`
	MonitoredFreq           []string `json:"monitored_freq"`
}

type NetworkInfo struct {
	Online       bool   `json:"online"`
	AvgLatency   string `json:"avg_latency"`
}

type ServiceStatus struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // "running", "error", "idle"
	LastUpdate  string `json:"last_update"`
	ErrorMsg    string `json:"error_msg,omitempty"`
	LogEntries  []string `json:"log_entries"`
}

var (
	WifiAPs []WifiAP
	WifiClients []WifiClient
	BtDevices []BluetoothDevice
	BleDevices []BLEDevice
	RadioInfoVar   RadioInfo
	NetworkInfoVar NetworkInfo
	ServiceStatuses map[string]*ServiceStatus
	Attacks         []Attack
	WifiMu  sync.RWMutex
	BtMu    sync.RWMutex
	BleMu   sync.RWMutex
	RadioMu sync.RWMutex
	NetMu   sync.RWMutex
	StatusMu sync.RWMutex
	AttackMu sync.RWMutex
)

func MonitorWifi() {
	StatusMu.Lock()
	if ServiceStatuses == nil {
		ServiceStatuses = make(map[string]*ServiceStatus)
	}
	if ServiceStatuses["wifi"] == nil {
		ServiceStatuses["wifi"] = &ServiceStatus{
			Name:        "WiFi Monitoring",
			Status:      "running",
			LastUpdate:  time.Now().Format("2006-01-02 15:04:05"),
			LogEntries:  []string{},
		}
	}
	StatusMu.Unlock()

	// Enhanced logging for debugging
	logToFile("WiFi monitoring started", "INFO")

	// Check if airodump-ng is available
	if _, err := exec.LookPath("airodump-ng"); err != nil {
		StatusMu.Lock()
		ServiceStatuses["wifi"].Status = "error"
		ServiceStatuses["wifi"].ErrorMsg = "airodump-ng not installed"
		ServiceStatuses["wifi"].LastUpdate = time.Now().Format("2006-01-02 15:04:05")
		ServiceStatuses["wifi"].LogEntries = append(ServiceStatuses["wifi"].LogEntries, fmt.Sprintf("[%s] airodump-ng not found", time.Now().Format("15:04:05")))
		StatusMu.Unlock()
		log.Printf("airodump-ng not found")
		return
	}

	// Find a WiFi interface in monitor mode or create one
	monitorInterface, err := getOrCreateMonitorInterface()
	if err != nil {
		StatusMu.Lock()
		ServiceStatuses["wifi"].Status = "error"
		ServiceStatuses["wifi"].ErrorMsg = fmt.Sprintf("Error setting up monitor interface: %v", err)
		ServiceStatuses["wifi"].LastUpdate = time.Now().Format("2006-01-02 15:04:05")
		ServiceStatuses["wifi"].LogEntries = append(ServiceStatuses["wifi"].LogEntries, fmt.Sprintf("[%s] ERROR: %v", time.Now().Format("15:04:05"), err))
		StatusMu.Unlock()
		log.Printf("Error setting up monitor interface: %v", err)

		// Try simple iw dev scan as fallback if monitor mode fails
		fallbackScanWifi()
		return
	}

	StatusMu.Lock()
	ServiceStatuses["wifi"].Status = "running"
	ServiceStatuses["wifi"].ErrorMsg = ""
	ServiceStatuses["wifi"].LastUpdate = time.Now().Format("2006-01-02 15:04:05")
	ServiceStatuses["wifi"].LogEntries = append(ServiceStatuses["wifi"].LogEntries, fmt.Sprintf("[%s] Using WiFi interface: %s", time.Now().Format("15:04:05"), monitorInterface))
	StatusMu.Unlock()

	// Skip airodump-ng for now and go directly to fallback WiFi scanning
	log.Printf("Using WiFi interface for scanning: %s", monitorInterface)
	fallbackScanWifi()
	return
}

func MonitorNetwork() {
	StatusMu.Lock()
	if ServiceStatuses == nil {
		ServiceStatuses = make(map[string]*ServiceStatus)
	}
	if ServiceStatuses["network"] == nil {
		ServiceStatuses["network"] = &ServiceStatus{
			Name:        "Network Monitoring",
			Status:      "running",
			LastUpdate:  time.Now().Format("2006-01-02 15:04:05"),
			LogEntries:  []string{},
		}
	}
	StatusMu.Unlock()

	cmd := exec.Command("ping", "-c", "3", "-i", "0.2", "8.8.8.8")
	output, err := cmd.Output()
	if err != nil {
		StatusMu.Lock()
		ServiceStatuses["network"].Status = "error"
		ServiceStatuses["network"].ErrorMsg = "Network is offline"
		ServiceStatuses["network"].LastUpdate = time.Now().Format("2006-01-02 15:04:05")
		ServiceStatuses["network"].LogEntries = append(ServiceStatuses["network"].LogEntries, fmt.Sprintf("[%s] Network offline", time.Now().Format("15:04:05")))
		if len(ServiceStatuses["network"].LogEntries) > 10 {
			ServiceStatuses["network"].LogEntries = ServiceStatuses["network"].LogEntries[len(ServiceStatuses["network"].LogEntries)-10:]
		}
		StatusMu.Unlock()

		log.Printf("Network monitoring: offline")
		NetMu.Lock()
		NetworkInfoVar = NetworkInfo{Online: false, AvgLatency: "N/A"}
		NetMu.Unlock()
		return
	}

	outputStr := string(output)
	var rttAvg string
	var rttMin string
	lines := strings.Split(outputStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "rtt min/avg/max/mdev") {
			rttMin = strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
			break
		}
	}
	parts := strings.Split(rttMin, "/")
	if len(parts) >= 2 {
		rttAvg = parts[1] + "ms"
	} else {
		rttAvg = "Unknown"
	}

	StatusMu.Lock()
	ServiceStatuses["network"].Status = "running"
	ServiceStatuses["network"].ErrorMsg = ""
	ServiceStatuses["network"].LastUpdate = time.Now().Format("2006-01-02 15:04:05")
	ServiceStatuses["network"].LogEntries = append(ServiceStatuses["network"].LogEntries, fmt.Sprintf("[%s] Online, latency: %s", time.Now().Format("15:04:05"), rttAvg))
	if len(ServiceStatuses["network"].LogEntries) > 10 {
		ServiceStatuses["network"].LogEntries = ServiceStatuses["network"].LogEntries[len(ServiceStatuses["network"].LogEntries)-10:]
	}
	StatusMu.Unlock()

	NetMu.Lock()
	NetworkInfoVar = NetworkInfo{Online: true, AvgLatency: rttAvg}
	NetMu.Unlock()

	log.Printf("Network monitoring: online, average latency %s", rttAvg)
}

func MonitorBluetooth() {
	StatusMu.Lock()
	if ServiceStatuses == nil {
		ServiceStatuses = make(map[string]*ServiceStatus)
	}
	if ServiceStatuses["bluetooth"] == nil {
		ServiceStatuses["bluetooth"] = &ServiceStatus{
			Name:        "Bluetooth Monitoring",
			Status:      "running",
			LastUpdate:  time.Now().Format("2006-01-02 15:04:05"),
			LogEntries:  []string{},
		}
	}
	StatusMu.Unlock()

	// Try multiple Bluetooth scanning methods for better compatibility
	var cmd *exec.Cmd
	var output []byte
	var err error

	// Method 1: Try hcitool scan first (legacy method)
	cmd = exec.Command("timeout", "10", "hcitool", "scan")
	cmd, output, err = runCommandOrSudo(cmd, []string{"Operation not permitted", "Permission denied"})

	// Method 2: If hcitool fails, try btmgmt (modern method)
	if err != nil {
		log.Printf("hcitool scan failed, trying btmgmt find...")
		cmd = exec.Command("timeout", "10", "btmgmt", "find")
		cmd, output, err = runCommandOrSudo(cmd, []string{"Operation not permitted", "Permission denied"})
	}

	// Method 3: If both fail, try bluetoothctl (another modern method)
	if err != nil {
		log.Printf("btmgmt failed, trying bluetoothctl...")
		cmd = exec.Command("timeout", "10", "bluetoothctl", "devices")
		cmd, output, err = runCommandOrSudo(cmd, []string{"No default controller available"})
	}

	if err != nil {
		StatusMu.Lock()
		ServiceStatuses["bluetooth"].Status = "error"
		ServiceStatuses["bluetooth"].ErrorMsg = fmt.Sprintf("All Bluetooth scanning methods failed: %v", err)
		ServiceStatuses["bluetooth"].LastUpdate = time.Now().Format("2006-01-02 15:04:05")
		ServiceStatuses["bluetooth"].LogEntries = append(ServiceStatuses["bluetooth"].LogEntries, fmt.Sprintf("[%s] ERROR: All Bluetooth scanning methods failed", time.Now().Format("15:04:05")))
		if len(ServiceStatuses["bluetooth"].LogEntries) > 10 {
			ServiceStatuses["bluetooth"].LogEntries = ServiceStatuses["bluetooth"].LogEntries[len(ServiceStatuses["bluetooth"].LogEntries)-10:]
		}
		StatusMu.Unlock()
		log.Printf("All Bluetooth scanning methods failed: %v", err)
		return
	}

	lines := strings.Split(string(output), "\n")
	BtMu.Lock()
	BtDevices = []BluetoothDevice{}
	BtMu.Unlock()

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Handle different Bluetooth tool outputs

		// hcitool scan output format: "AA:BB:CC:DD:EE:FF Device Name"
		if strings.Contains(trimmed, "\t") && !strings.HasPrefix(trimmed, "Scanning") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				device := BluetoothDevice{
					Address: parts[0],
					Name:    strings.Join(parts[1:], " "),
				}
				BtMu.Lock()
				BtDevices = append(BtDevices, device)
				BtMu.Unlock()
			}
		}
		// bluetoothctl devices output format: "Device AA:BB:CC:DD:EE:FF Device Name"
		if strings.HasPrefix(trimmed, "Device ") && strings.Contains(trimmed, " ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				address := parts[1]
				name := strings.Join(parts[2:], " ")
				device := BluetoothDevice{
					Address: address,
					Name:    name,
				}
				BtMu.Lock()
				BtDevices = append(BtDevices, device)
				BtMu.Unlock()
			}
		}
	}

	StatusMu.Lock()
	ServiceStatuses["bluetooth"].Status = "running"
	ServiceStatuses["bluetooth"].ErrorMsg = ""
	ServiceStatuses["bluetooth"].LastUpdate = time.Now().Format("2006-01-02 15:04:05")
	ServiceStatuses["bluetooth"].LogEntries = append(ServiceStatuses["bluetooth"].LogEntries, fmt.Sprintf("[%s] Monitored %d Bluetooth devices", time.Now().Format("15:04:05"), len(BtDevices)))
	if len(ServiceStatuses["bluetooth"].LogEntries) > 10 {
		ServiceStatuses["bluetooth"].LogEntries = ServiceStatuses["bluetooth"].LogEntries[len(ServiceStatuses["bluetooth"].LogEntries)-10:]
	}
	StatusMu.Unlock()

	log.Printf("Monitored %d Bluetooth devices", len(BtDevices))

	// Detect Bluetooth attacks
	BtMu.RLock()
	btAttacks := DetectBluetoothAttacks(BtDevices)
	BtMu.RUnlock()

	for _, attack := range btAttacks {
		AddAttack(attack)
		log.Printf("Bluetooth Attack Detected: %s - %s", attack.Type, attack.Description)
	}
}

func MonitorAirTag() {
	StatusMu.Lock()
	if ServiceStatuses == nil {
		ServiceStatuses = make(map[string]*ServiceStatus)
	}
	if ServiceStatuses["airtag"] == nil {
		ServiceStatuses["airtag"] = &ServiceStatus{
			Name:        "AirTag/BLE Monitoring",
			Status:      "running",
			LastUpdate:  time.Now().Format("2006-01-02 15:04:05"),
			LogEntries:  []string{},
		}
	}
	StatusMu.Unlock()

	// Try multiple BLE scanning methods for better compatibility
	var cmd *exec.Cmd
	var output []byte
	var err error

	// Method 1: Try hcitool lescan first (legacy method)
	cmd = exec.Command("timeout", "10", "hcitool", "lescan", "--dup")
	cmd, output, err = runCommandOrSudo(cmd, []string{"Set scan parameters failed", "Operation not permitted"})

	// Method 2: If hcitool fails, try bluetoothctl (modern method)
	if err != nil {
		log.Printf("hcitool lescan failed, trying bluetoothctl...")
		cmd = exec.Command("timeout", "10", "bluetoothctl", "scan", "on")
		cmd, output, err = runCommandOrSudo(cmd, []string{"Failed to start discovery", "No default controller available"})

		// If bluetoothctl scan on works, wait a bit then scan off
		if err == nil {
			time.Sleep(3 * time.Second)
			offCmd := exec.Command("timeout", "5", "bluetoothctl", "scan", "off")
			offCmd.Run() // Don't check error for scan off
		}
	}

	// Method 3: If both fail, try btmgmt (another modern method)
	if err != nil {
		log.Printf("bluetoothctl failed, trying btmgmt find...")
		cmd = exec.Command("timeout", "10", "btmgmt", "find")
		cmd, output, err = runCommandOrSudo(cmd, []string{"Operation not permitted", "Permission denied"})

		// Method 4: If btmgmt fails, try hcitool scan as last resort (different from lescan)
		if err != nil {
			log.Printf("btmgmt failed, trying hcitool scan as last resort...")
			cmd = exec.Command("timeout", "8", "hcitool", "scan")
			cmd, output, err = runCommandOrSudo(cmd, []string{"Operation not permitted", "Permission denied"})
		}
	}

	// If all methods fail, report error but don't return empty results
	if err != nil && !strings.Contains(string(output), "exit status 124") { // 124 is timeout
		StatusMu.Lock()
		ServiceStatuses["airtag"].Status = "error"
		ServiceStatuses["airtag"].ErrorMsg = fmt.Sprintf("All BLE scanning methods failed. hcitool: %v, bluetoothctl: %v, btmgmt: %v", err, err, err)
		ServiceStatuses["airtag"].LastUpdate = time.Now().Format("2006-01-02 15:04:05")
		ServiceStatuses["airtag"].LogEntries = append(ServiceStatuses["airtag"].LogEntries, fmt.Sprintf("[%s] ERROR: All BLE scanning methods failed", time.Now().Format("15:04:05")))
		if len(ServiceStatuses["airtag"].LogEntries) > 10 {
			ServiceStatuses["airtag"].LogEntries = ServiceStatuses["airtag"].LogEntries[len(ServiceStatuses["airtag"].LogEntries)-10:]
		}
		StatusMu.Unlock()
		log.Printf("All BLE scanning methods failed: %v", err)
		return
	}

	lines := strings.Split(string(output), "\n")
	BleMu.Lock()
	BleDevices = []BLEDevice{}
	BleMu.Unlock()

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// LE Scan ...
		if strings.Contains(trimmed, ":") && !strings.HasPrefix(trimmed, "LE Scan") && trimmed != "" {
			parts := strings.Split(trimmed, " ")
			if len(parts) >= 2 && strings.Contains(parts[0], ":") && strings.HasSuffix(parts[0], ":") {
				addr := parts[0]
				data := strings.Join(parts[1:], " ")
				// Flag if Apple device (manufacturer 004C)
				isAirTagCandidate := false
				if strings.Contains(data, "Apple") || strings.Contains(data, "004C") {
					isAirTagCandidate = true
				}
				device := BLEDevice{
					Address: addr,
					Data:    data + (map[bool]string{true: " (Potential AirTag)", false: ""})[isAirTagCandidate],
				}
				BleMu.Lock()
				BleDevices = append(BleDevices, device)
				BleMu.Unlock()
			}
		}
	}

	StatusMu.Lock()
	ServiceStatuses["airtag"].Status = "running"
	ServiceStatuses["airtag"].ErrorMsg = ""
	ServiceStatuses["airtag"].LastUpdate = time.Now().Format("2006-01-02 15:04:05")
	ServiceStatuses["airtag"].LogEntries = append(ServiceStatuses["airtag"].LogEntries, fmt.Sprintf("[%s] Monitored %d BLE devices", time.Now().Format("15:04:05"), len(BleDevices)))
	if len(ServiceStatuses["airtag"].LogEntries) > 10 {
		ServiceStatuses["airtag"].LogEntries = ServiceStatuses["airtag"].LogEntries[len(ServiceStatuses["airtag"].LogEntries)-10:]
	}
	StatusMu.Unlock()

	log.Printf("Monitored %d BLE devices", len(BleDevices))
}

func MonitorRadio() {
	StatusMu.Lock()
	if ServiceStatuses == nil {
		ServiceStatuses = make(map[string]*ServiceStatus)
	}
	if ServiceStatuses["radio"] == nil {
		ServiceStatuses["radio"] = &ServiceStatus{
			Name:        "Radio Frequency Monitoring",
			Status:      "running",
			LastUpdate:  time.Now().Format("2006-01-02 15:04:05"),
			LogEntries:  []string{},
		}
	}
	StatusMu.Unlock()

	// Check for external USB SDR devices
	usbCmd := exec.Command("sh", "-c", "lsusb | grep -i rtl || lsusb | grep -i 'hackrf' || lsusb | grep -i 'blade' || true")
	usbOutput, usbErr := usbCmd.Output()

	var sdrDevs []string
	hasSDR := false

	if usbErr == nil {
		foundLines := strings.Split(string(usbOutput), "\n")
		for _, line := range foundLines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && trimmed != "true" {
				sdrDevs = append(sdrDevs, trimmed)
				hasSDR = true
			}
		}
	}

	// Check for built-in WiFi cards that might support monitor mode
	wifiInterfaces, wifiErr := getWifiInterfaces()
	builtinCapable := false
	var builtinCards []string

	if wifiErr == nil {
		for _, iface := range wifiInterfaces {
			// Check if interface supports monitor mode (most modern WiFi cards do)
			checkCmd := exec.Command("iwconfig", iface)
			if _, checkErr := checkCmd.Output(); checkErr == nil {
				builtinCapable = true
				builtinCards = append(builtinCards, iface+" (built-in WiFi card)")
			}
		}
	}

	// Combine external and built-in devices
	allDevices := append(sdrDevs, builtinCards...)

	subGHzDetected := false
	if hasSDR {
		// Use rtl_power for sub-GHz scanning with external SDR
		cmdSub := exec.Command("timeout", "5", "rtl_power", "-f", "300M:488M:2M", "-g", "20", "-i", "1", "-1", "-d", "0")
		_, subOutput, err := runCommandOrSudo(cmdSub, []string{"rtl_power: failed to open rtl"})
		if err == nil && len(strings.TrimSpace(string(subOutput))) > 50 {
			subGHzDetected = true
		}
		log.Printf("Sub-GHz scan completed: signals detected %v", subGHzDetected)
	}

	// Enhanced frequency list with explanations
	var monitoredFreq []string
	if hasSDR {
		monitoredFreq = []string{
			"300-488MHz Sub-GHz (IoT sensors, remotes)",
			"433MHz (Wireless sensors, doorbells)",
			"868MHz (Security systems, alarm sensors)",
			"2.4GHz (WiFi, Bluetooth, Zigbee)",
			"5GHz (WiFi 5/6, surveillance cameras)",
		}
	} else if builtinCapable {
		monitoredFreq = []string{
			"2.4GHz (WiFi channels via built-in card)",
			"5GHz (WiFi channels via built-in card)",
			"*External SDR needed for Sub-GHz",
		}
	} else {
		monitoredFreq = []string{
			"No radio monitoring hardware detected",
			"Built-in WiFi card: Not found",
			"External SDR: Not found",
		}
	}

	RadioMu.Lock()
	RadioInfoVar = RadioInfo{
		HasSDR:                hasSDR,
		SDRDevices:            allDevices,
		SubGHzSignalsDetected: subGHzDetected,
		MonitoredFreq:         monitoredFreq,
	}
	RadioMu.Unlock()

	StatusMu.Lock()
	ServiceStatuses["radio"].Status = "running"
	ServiceStatuses["radio"].ErrorMsg = ""
	ServiceStatuses["radio"].LastUpdate = time.Now().Format("2006-01-02 15:04:05")
	if hasSDR {
		ServiceStatuses["radio"].LogEntries = append(ServiceStatuses["radio"].LogEntries, fmt.Sprintf("[%s] External SDR detected: %v, sub-GHz signals: %v", time.Now().Format("15:04:05"), hasSDR, subGHzDetected))
	} else if builtinCapable {
		ServiceStatuses["radio"].LogEntries = append(ServiceStatuses["radio"].LogEntries, fmt.Sprintf("[%s] Built-in WiFi cards detected: %v (limited to WiFi bands)", time.Now().Format("15:04:05"), len(builtinCards)))
	} else {
		ServiceStatuses["radio"].LogEntries = append(ServiceStatuses["radio"].LogEntries, fmt.Sprintf("[%s] No SDR hardware detected", time.Now().Format("15:04:05")))
	}
	if len(ServiceStatuses["radio"].LogEntries) > 10 {
		ServiceStatuses["radio"].LogEntries = ServiceStatuses["radio"].LogEntries[len(ServiceStatuses["radio"].LogEntries)-10:]
	}
	StatusMu.Unlock()

	if hasSDR {
		log.Printf("Radio monitoring: External SDR detected: %v, sub-GHz signals: %v, devices: %v", hasSDR, subGHzDetected, sdrDevs)
	} else if builtinCapable {
		log.Printf("Radio monitoring: Built-in WiFi cards detected: %v (limited to WiFi bands)", builtinCards)
	} else {
		log.Printf("Radio monitoring: No SDR hardware detected. Built-in WiFi: %v, External SDR: %v", builtinCapable, hasSDR)
	}
}

// getOrCreateMonitorInterface finds a WiFi interface in monitor mode or creates one
func getOrCreateMonitorInterface() (string, error) {
	// First, check if there's already a monitor mode interface
	cmd := exec.Command("iwconfig")
	output, err := cmd.Output()
	if err == nil {
		interfaces := parseIwconfigOutput(string(output))
		for _, iface := range interfaces {
			if iface.Mode == "Monitor" {
				return iface.Name, nil
			}
		}
	}

	// No monitor interface found, try to create one
	// First get available WiFi interfaces
	wifiInterfaces, err := getWifiInterfaces()
	if err != nil || len(wifiInterfaces) == 0 {
		return "", fmt.Errorf("no WiFi interfaces found")
	}

	// Try to put the first WiFi interface into monitor mode
	targetInterface := wifiInterfaces[0]
	log.Printf("Attempting to put interface %s into monitor mode", targetInterface)

	// Bring interface down
	cmd = exec.Command("ifconfig", targetInterface, "down")
	err = cmd.Run()
	if err != nil {
		log.Printf("Warning: Could not bring down interface %s: %v", targetInterface, err)
	}

	// Set interface to monitor mode
	cmd = exec.Command("iwconfig", targetInterface, "mode", "monitor")
	err = cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to set monitor mode on %s: %v", targetInterface, err)
	}

	// Bring interface back up
	cmd = exec.Command("ifconfig", targetInterface, "up")
	err = cmd.Run()
	if err != nil {
		log.Printf("Warning: Could not bring up interface %s: %v", targetInterface, err)
	}

	log.Printf("Successfully put %s into monitor mode", targetInterface)
	return targetInterface, nil
}

// InterfaceInfo represents WiFi interface information
type InterfaceInfo struct {
	Name string
	Mode string
}

// parseIwconfigOutput parses the output of iwconfig command
func parseIwconfigOutput(output string) []InterfaceInfo {
	var interfaces []InterfaceInfo
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "IEEE") {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				ifaceName := strings.TrimSuffix(parts[0], ":")
				mode := "Managed" // default mode

				// Look for mode in the line
				if strings.Contains(line, "Mode:") {
					modeParts := strings.Split(line, "Mode:")
					if len(modeParts) >= 2 {
						mode = strings.TrimSpace(strings.Split(modeParts[1], " ")[0])
					}
				}

				interfaces = append(interfaces, InterfaceInfo{
					Name: ifaceName,
					Mode: mode,
				})
			}
		}
	}

	return interfaces
}

// getWifiInterfaces returns a list of available WiFi interfaces
func getWifiInterfaces() ([]string, error) {
	var wifiInterfaces []string

	// Check for wireless interfaces in /proc/net/wireless
	cmd := exec.Command("cat", "/proc/net/wireless")
	output, err := cmd.Output()
	if err != nil {
		// Fallback: try iwconfig to find wireless interfaces
		cmd = exec.Command("iwconfig")
		output, err = cmd.Output()
		if err != nil {
			return nil, err
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "IEEE") {
				parts := strings.Fields(line)
				if len(parts) >= 1 {
					ifaceName := strings.TrimSuffix(parts[0], ":")
					wifiInterfaces = append(wifiInterfaces, ifaceName)
				}
			}
		}
	} else {
		lines := strings.Split(string(output), "\n")
		for i, line := range lines {
			if i == 0 {
				continue // Skip header
			}
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				ifaceName := strings.TrimSpace(parts[0])
				ifaceName = strings.TrimSuffix(ifaceName, ":")
				if ifaceName != "" {
					wifiInterfaces = append(wifiInterfaces, ifaceName)
				}
			}
		}
	}

	// Remove duplicates and filter out non-WiFi interfaces
	var uniqueInterfaces []string
	seen := make(map[string]bool)
	for _, iface := range wifiInterfaces {
		if !seen[iface] && strings.HasPrefix(iface, "wlan") {
			seen[iface] = true
			uniqueInterfaces = append(uniqueInterfaces, iface)
		}
	}

	return uniqueInterfaces, nil
}

// fallbackScanWifi attempts a basic WiFi scan when airodump-ng fails
func fallbackScanWifi() {
	log.Printf("Attempting fallback WiFi scan with iw dev scan")

	// Get available WiFi interfaces
	interfaces, err := getWifiInterfaces()
	if err != nil || len(interfaces) == 0 {
		StatusMu.Lock()
		ServiceStatuses["wifi"].Status = "error"
		ServiceStatuses["wifi"].ErrorMsg = "No wireless interfaces found"
		ServiceStatuses["wifi"].LastUpdate = time.Now().Format("2006-01-02 15:04:05")
		StatusMu.Unlock()
		return
	}

	// Use first available interface
	iface := interfaces[0]

	// Run iw dev wlan0 scan
	cmd := exec.Command("timeout", "8", "iw", "dev", iface, "scan")
	output, err := cmd.CombinedOutput()
	if err != nil {
		StatusMu.Lock()
		ServiceStatuses["wifi"].Status = "error"
		ServiceStatuses["wifi"].ErrorMsg = fmt.Sprintf("iw scan failed: %v", err)
		ServiceStatuses["wifi"].LastUpdate = time.Now().Format("2006-01-02 15:04:05")
		ServiceStatuses["wifi"].LogEntries = append(ServiceStatuses["wifi"].LogEntries, fmt.Sprintf("[%s] Fallback scan failed", time.Now().Format("15:04:05")))
		if len(ServiceStatuses["wifi"].LogEntries) > 10 {
			ServiceStatuses["wifi"].LogEntries = ServiceStatuses["wifi"].LogEntries[len(ServiceStatuses["wifi"].LogEntries)-10:]
		}
		StatusMu.Unlock()
		return
	}

	// Parse basic iw scan output (limited parsing for fallback)
	lines := strings.Split(string(output), "\n")

	var aps []WifiAP
	var currentBSSID string
	var currentSSID string
	var currentPWR int

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "BSS ") {
			// Save previous AP if we have one
			if currentBSSID != "" {
				aps = append(aps, WifiAP{
					BSSID: currentBSSID,
					PWR:   currentPWR,
					ESSID: currentSSID,
					ENC:   "WPA2", // default assumption
				})
			}

			// Parse new BSSID
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentBSSID = strings.TrimSpace(parts[1])
				currentSSID = ""
				currentPWR = 0
			}
		} else if strings.Contains(line, "signal: ") {
			// Parse signal strength
			parts := strings.Split(line, "signal: ")
			if len(parts) >= 2 {
				signalStr := strings.TrimSpace(parts[1])
				if strings.HasSuffix(signalStr, " dBm") {
					signalStr = strings.TrimSuffix(signalStr, " dBm")
				}
				pwr, _ := strconv.Atoi(signalStr)
				currentPWR = pwr
			}
		} else if strings.Contains(line, "SSID: ") {
			// Parse SSID
			parts := strings.Split(line, "SSID: ")
			if len(parts) >= 2 {
				currentSSID = strings.TrimSpace(parts[1])
			}
		}
	}

	// Save last AP
	if currentBSSID != "" {
		aps = append(aps, WifiAP{
			BSSID: currentBSSID,
			PWR:   currentPWR,
			ESSID: currentSSID,
			ENC:   "WPA2",
		})
	}

	// Update global wifi access points
	WifiMu.Lock()
	WifiAPs = aps
	WifiClients = []WifiClient{} // No client info from iw scan
	WifiMu.Unlock()

	StatusMu.Lock()
	ServiceStatuses["wifi"].Status = "running"
	ServiceStatuses["wifi"].ErrorMsg = ""
	ServiceStatuses["wifi"].LastUpdate = time.Now().Format("2006-01-02 15:04:05")
	ServiceStatuses["wifi"].LogEntries = append(ServiceStatuses["wifi"].LogEntries, fmt.Sprintf("[%s] Fallback scan found %d access points", time.Now().Format("15:04:05"), len(aps)))
	if len(ServiceStatuses["wifi"].LogEntries) > 10 {
		ServiceStatuses["wifi"].LogEntries = ServiceStatuses["wifi"].LogEntries[len(ServiceStatuses["wifi"].LogEntries)-10:]
	}
	StatusMu.Unlock()

	log.Printf("Fallback WiFi scan completed: found %d access points", len(aps))
}

// logToFile writes structured logs to file for better error research
func logToFile(message, level string) {
	// Get current working directory
	wd, err := os.Getwd()
	if err != nil {
		log.Printf("Error getting working directory: %v", err)
		return
	}

	// Create logs directory if it doesn't exist
	logsDir := filepath.Join(wd, "logs")
	if _, err := os.Stat(logsDir); os.IsNotExist(err) {
		os.Mkdir(logsDir, 0755)
	}

	// Create log file with timestamp
	timestamp := time.Now().Format("2006-01-02")
	logFile := filepath.Join(logsDir, fmt.Sprintf("shimmy-%s.log", timestamp))

	// Open file in append mode, create if doesn't exist
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("Error opening log file: %v", err)
		return
	}
	defer file.Close()

	// Write structured log entry
	logEntry := fmt.Sprintf("[%s] [%s] %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		level,
		message)

	if _, err := file.WriteString(logEntry); err != nil {
		log.Printf("Error writing to log file: %v", err)
	}
}

// DetectWiFiAttacks analyzes WiFi networks for attack patterns
func DetectWiFiAttacks(devices []WifiAP) []Attack {
	var attacks []Attack

	// Evil Twin Detection - Duplicate SSIDs
	ssidCounts := make(map[string][]string)
	for _, device := range devices {
		if device.ESSID != "" && device.ESSID != "Hidden" {
			ssidCounts[device.ESSID] = append(ssidCounts[device.ESSID], device.BSSID)
		}
	}

	for ssid, bssids := range ssidCounts {
		if len(bssids) > 1 {
			attacks = append(attacks, Attack{
				Type:        "EVIL_TWIN",
				Severity:    "High",
				Description: fmt.Sprintf("Potential evil twin attack: SSID '%s' appears %d times", ssid, len(bssids)),
				Target:      ssid,
				Timestamp:   time.Now(),
			})
		}
	}

	// Rogue Access Point Detection
	roguePatterns := []string{"free", "public", "hack", "test", "evil", "wifi", "guest", "default"}
	for _, device := range devices {
		ssidLower := strings.ToLower(device.ESSID)
		for _, pattern := range roguePatterns {
			if strings.Contains(ssidLower, pattern) {
				attacks = append(attacks, Attack{
					Type:        "ROGUE_AP",
					Severity:    "High",
					Description: fmt.Sprintf("Potentially rogue access point detected: %s", device.ESSID),
					Target:      device.ESSID,
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	// Weak Encryption Detection
	for _, device := range devices {
		if strings.Contains(strings.ToLower(device.ENC), "wep") {
			attacks = append(attacks, Attack{
				Type:        "WEAK_ENCRYPTION",
				Severity:    "High",
				Description: fmt.Sprintf("Weak encryption (WEP) detected on network: %s", device.ESSID),
				Target:      device.ESSID,
				Timestamp:   time.Now(),
			})
		}
	}

	return attacks
}

// DetectBluetoothAttacks analyzes Bluetooth devices for attack patterns
func DetectBluetoothAttacks(devices []BluetoothDevice) []Attack {
	var attacks []Attack

	// Mass Scanning Detection
	if len(devices) > 20 {
		attacks = append(attacks, Attack{
			Type:        "BLUETOOTH_MASS_SCANNING",
			Severity:    "Medium",
			Description: fmt.Sprintf("Mass scanning detected: %d Bluetooth devices found (unusual activity)", len(devices)),
			Target:      "bluetooth_network",
			Timestamp:   time.Now(),
		})
	}

	// Spoofing Detection
	suspiciousNames := []string{"attack", "hack", "exploit", "test", "spoof", "evil", "malware", "virus"}
	for _, device := range devices {
		nameLower := strings.ToLower(device.Name)
		for _, suspicious := range suspiciousNames {
			if strings.Contains(nameLower, suspicious) {
				attacks = append(attacks, Attack{
					Type:        "BLUETOOTH_SPOOFING",
					Severity:    "High",
					Description: fmt.Sprintf("Suspicious Bluetooth device name: %s (%s)", device.Name, device.Address),
					Target:      device.Address,
					Timestamp:   time.Now(),
				})
				break
			}
		}
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
				attacks = append(attacks, Attack{
					Type:        "BLUETOOTH_MITM",
					Severity:    "High",
					Description: fmt.Sprintf("Potential Man-in-the-Middle device: %s (%s) - appears to be %s", device.Name, device.Address, desc),
					Target:      device.Address,
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	return attacks
}

// DetectNetworkAttacks analyzes network for intrusion patterns
func DetectNetworkAttacks() []Attack {
	var attacks []Attack

	// Check for suspicious open ports using nmap if available
	if _, err := exec.LookPath("nmap"); err == nil {
		cmd := exec.Command("nmap", "-p", "21,23,3389,445", "--open", "192.168.1.0/24")
		output, err := cmd.CombinedOutput()
		if err == nil {
			outputStr := string(output)

			// Check for dangerous ports
			dangerousPorts := map[string]string{
				"21/tcp":    "FTP",
				"23/tcp":    "Telnet",
				"3389/tcp":  "RDP",
				"445/tcp":   "SMB",
			}

			for port, service := range dangerousPorts {
				if strings.Contains(outputStr, port) && strings.Contains(outputStr, "open") {
					attacks = append(attacks, Attack{
						Type:        "SUSPICIOUS_PORT",
						Severity:    "Medium",
						Description: fmt.Sprintf("Suspicious open port detected: %s (%s)", port, service),
						Target:      "network",
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}

	return attacks
}

// GetRecentAttacks returns the most recent attacks
func GetRecentAttacks(limit int) []Attack {
	AttackMu.RLock()
	defer AttackMu.RUnlock()

	if limit <= 0 || limit > len(Attacks) {
		return Attacks
	}

	// Return most recent attacks
	start := len(Attacks) - limit
	if start < 0 {
		start = 0
	}
	return Attacks[start:]
}

// AddAttack adds a new attack to the global attacks list
func AddAttack(attack Attack) {
	AttackMu.Lock()
	defer AttackMu.Unlock()

	Attacks = append(Attacks, attack)

	// Keep only last 1000 attacks to prevent memory issues
	if len(Attacks) > 1000 {
		Attacks = Attacks[len(Attacks)-1000:]
	}
}
