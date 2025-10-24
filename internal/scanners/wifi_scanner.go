package scanners

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/boboTheFoff/shheissee-go/internal/models"
)

// WiFiScanner handles WiFi network scanning and attack detection
type WiFiScanner struct{}

// NewWiFiScanner creates a new WiFi scanner
func NewWiFiScanner() *WiFiScanner {
	return &WiFiScanner{}
}

// ScanWiFiNetworks discovers nearby WiFi access points and devices
func (ws *WiFiScanner) ScanWiFiNetworks() ([]models.WiFiDevice, error) {
	devices, err := ws.scanWithIwlist()
	if err != nil {
		devices, err = ws.scanWithNmcli()
		if err != nil {
			return nil, fmt.Errorf("no WiFi scanning method available: %v", err)
		}
	}
	return devices, nil
}

// scanWithIwlist uses iwlist to scan for WiFi networks
func (ws *WiFiScanner) scanWithIwlist() ([]models.WiFiDevice, error) {
	if !isCommandAvailable("iwlist") {
		return nil, fmt.Errorf("iwlist not available")
	}

	cmd := exec.Command("iwlist", "scan")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return ws.parseIwlistOutput(string(output)), nil
}

// scanWithNmcli uses nmcli as alternative
func (ws *WiFiScanner) scanWithNmcli() ([]models.WiFiDevice, error) {
	if !isCommandAvailable("nmcli") {
		return nil, fmt.Errorf("nmcli not available")
	}

	cmd := exec.Command("nmcli", "device", "wifi", "list")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return ws.parseNmcliOutput(string(output)), nil
}

// parseIwlistOutput parses iwlist scan output
func (ws *WiFiScanner) parseIwlistOutput(output string) []models.WiFiDevice {
	var devices []models.WiFiDevice
	var currentDevice models.WiFiDevice

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// New cell/cell starts
		if strings.HasPrefix(line, "Cell ") || strings.Contains(line, "Address:") {
			if currentDevice.Address != "" {
				devices = append(devices, currentDevice)
			}
			currentDevice = models.WiFiDevice{}
		}

		// Extract BSSID/MAC address
		if strings.Contains(line, "Address:") {
			parts := strings.Split(line, "Address:")
			if len(parts) == 2 {
				currentDevice.Address = strings.TrimSpace(parts[1])
			}
		}

		// Extract SSID
		if strings.HasPrefix(line, "ESSID:") {
			ssid := strings.Trim(line, "ESSID:\"")
			ssid = strings.TrimSuffix(ssid, "\"")
			currentDevice.SSID = ssid
		}

		// Extract signal level
		if strings.Contains(line, "Signal level=") {
			signalRegex := regexp.MustCompile(`Signal level=(-\d+) dBm`)
			matches := signalRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				if signal, err := strconv.Atoi(matches[1]); err == nil {
					currentDevice.Signal = fmt.Sprintf("%d dBm", signal)
				}
			}
		}

		// Extract channel
		if strings.HasPrefix(line, "Channel:") {
			parts := strings.Split(line, "Channel:")
			if len(parts) == 2 {
				currentDevice.Channel = strings.TrimSpace(parts[1])
			}
		}
	}

	// Add the last device
	if currentDevice.Address != "" {
		devices = append(devices, currentDevice)
	}

	return devices
}

// parseNmcliOutput parses nmcli wifi list output
func (ws *WiFiScanner) parseNmcliOutput(output string) []models.WiFiDevice {
	var devices []models.WiFiDevice

	scanner := bufio.NewScanner(strings.NewReader(output))
	// Skip header line
	if scanner.Scan() {
		// Header line
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse nmcli format: "* SSID BSSID MODE CHAN RATE SIGNAL BARS SECURITY"
		// This is approximate parsing - real nmcli output may vary
		parts := strings.Fields(line)
		if len(parts) >= 6 {
			device := models.WiFiDevice{
				SSID:   parts[1],
				Address: parts[2],
				Channel: parts[4],
				Signal: fmt.Sprintf("%s dBm", parts[6]), // Adjust based on actual output
				Status: "Unknown",
			}
			devices = append(devices, device)
		}
	}

	return devices
}

// DetectWiFiAttacks analyzes WiFi networks for attack patterns
func (ws *WiFiScanner) DetectWiFiAttacks(devices []models.WiFiDevice) []models.Attack {
	var attacks []models.Attack

	// Evil Twin Detection - Duplicate SSIDs
	ssidCounts := make(map[string][]string)
	for _, device := range devices {
		if device.SSID != "" && device.SSID != "Hidden" {
			ssidCounts[device.SSID] = append(ssidCounts[device.SSID], device.Address)
		}
	}

	for ssid, addresses := range ssidCounts {
		if len(addresses) > 1 {
			attacks = append(attacks, models.Attack{
				Type:        "EVIL_TWIN",
				Severity:    models.SeverityHigh,
				Description: fmt.Sprintf("Potential evil twin attack: SSID '%s' appears %d times", ssid, len(addresses)),
				Target:      ssid,
				Timestamp:   time.Now(),
			})
		}
	}

	// Rogue Access Point Detection
	roguePatterns := []string{"free", "public", "hack", "test", "evil", "wifi", "guest", "default"}
	for _, device := range devices {
		ssidLower := strings.ToLower(device.SSID)
		for _, pattern := range roguePatterns {
			if strings.Contains(ssidLower, pattern) {
				attacks = append(attacks, models.Attack{
					Type:        "ROGUE_AP",
					Severity:    models.SeverityHigh,
					Description: fmt.Sprintf("Potentially rogue access point detected: %s", device.SSID),
					Target:      device.SSID,
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	// Open Network Detection
	for _, device := range devices {
		// In iwlist, check for "Encryption key:off"
		// For simplicity, we'll note suspicious SSIDs that might indicate open networks
		if device.SSID != "" && strings.Contains(strings.ToLower(device.SSID), "open") {
			attacks = append(attacks, models.Attack{
				Type:        "OPEN_NETWORK",
				Severity:    models.SeverityMedium,
				Description: fmt.Sprintf("Open WiFi network detected: %s", device.SSID),
				Target:      device.SSID,
				Timestamp:   time.Now(),
			})
		}
	}

	// Weak Encryption Detection
	for _, device := range devices {
		// Look for indicators of WEP encryption in SSID or capabilities
		if strings.Contains(strings.ToLower(device.SSID), "wep") ||
		   (device.Address != "" && isWEPMAC(device.Address)) {
			attacks = append(attacks, models.Attack{
				Type:        "WEAK_ENCRYPTION",
				Severity:    models.SeverityHigh,
				Description: fmt.Sprintf("Weak encryption (WEP) detected on network: %s", device.SSID),
				Target:      device.SSID,
				Timestamp:   time.Now(),
			})
		}
	}

	// WPS Vulnerability Detection
	if ws.checkWPSVulnerabilities(devices) {
		attacks = append(attacks, models.Attack{
			Type:        "WPS_VULNERABILITY",
			Severity:    models.SeverityMedium,
			Description: "WPS-enabled networks detected - vulnerable to pixie dust and brute force attacks",
			Target:      "wifi_network",
			Timestamp:   time.Now(),
		})
	}

	return attacks
}

// checkWPSVulnerabilities checks for WPS-enabled networks
func (ws *WiFiScanner) checkWPSVulnerabilities(devices []models.WiFiDevice) bool {
	if !isCommandAvailable("wash") { // Requires reaver tools
		return false
	}

	cmd := exec.Command("wash", "-i", "wlan0", "-s") // This would require wireless interface
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}

	// Check for WPS in output
	if strings.Contains(string(output), "WPS") || strings.Contains(string(output), "Version") {
		return true
	}

	return false
}

// DetectDeauthenticationAttacks detects WiFi deauth attacks using airodump-ng
func (ws *WiFiScanner) DetectDeauthenticationAttacks() []models.Attack {
	var attacks []models.Attack

	if !isCommandAvailable("airodump-ng") {
		return attacks
	}

	// Run airodump-ng for a short period to collect data
	cmd := exec.Command("timeout", "10", "airodump-ng", "--output-format", "csv", "-w", "/tmp/wifi_scan")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return attacks
	}

	// Parse output for deauthentication patterns
	outputStr := string(output)
	deauthCount := strings.Count(outputStr, "DEAUTH")

	if deauthCount > 5 { // Threshold for attack detection
		attacks = append(attacks, models.Attack{
			Type:        "WIFI_DEAUTH_ATTACK",
			Severity:    models.SeverityHigh,
			Description: fmt.Sprintf("Deauthentication attack detected: %d deauth packets observed", deauthCount),
			Target:      "wifi_network",
			Timestamp:   time.Now(),
		})
	}

	// Clean up temp file
	exec.Command("rm", "-f", "/tmp/wifi_scan-01.csv", "/tmp/wifi_scan-01.cap").Run()

	return attacks
}

// CheckWiFiInterfaceStatus checks the status of wireless interfaces
func (ws *WiFiScanner) CheckWiFiInterfaceStatus() []models.Attack {
	var attacks []models.Attack

	if !isCommandAvailable("iwconfig") {
		return attacks
	}

	cmd := exec.Command("iwconfig")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return attacks
	}

	outputStr := string(output)

	// Check for monitoring mode interfaces (indicating active monitoring)
	if strings.Contains(outputStr, "Mode:Monitor") {
		attacks = append(attacks, models.Attack{
			Type:        "WIFI_MONITORING",
			Severity:    models.SeverityLow,
			Description: "WiFi monitoring active - checking for attacks",
			Target:      "wifi",
			Timestamp:   time.Now(),
		})
	}

	return attacks
}

// Helper functions

// isWEPMAC makes a rough guess about WEP encryption based on MAC characteristics
// This is not reliable but provides basic detection
func isWEPMAC(mac string) bool {
	// Very basic heuristic - not accurate but provides some detection
	// In a real implementation, you would need to examine the actual capabilities
	return false // Placeholder - would need actual capability parsing
}

// MonitorWiFiAttacks continuously monitors for WiFi attacks
func (ws *WiFiScanner) MonitorWiFiAttacks() (<-chan models.Attack, error) {
	attackCh := make(chan models.Attack, 100)

	go func() {
		defer close(attackCh)

		for {
			// Check for deauth attacks
			if attacks := ws.DetectDeauthenticationAttacks(); len(attacks) > 0 {
				for _, attack := range attacks {
					attackCh <- attack
				}
			}

			// Check interface status
			if attacks := ws.CheckWiFiInterfaceStatus(); len(attacks) > 0 {
				for _, attack := range attacks {
					attackCh <- attack
				}
			}

			time.Sleep(30 * time.Second)
		}
	}()

	return attackCh, nil
}
