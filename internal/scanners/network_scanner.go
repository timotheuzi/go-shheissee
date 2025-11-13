package scanners

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/boboTheFoff/shheissee-go/internal/models"
)

// NetworkScanner handles network device discovery and port scanning
type NetworkScanner struct {
	knownDevices map[string]bool
}

// NewNetworkScanner creates a new network scanner
func NewNetworkScanner(knownDevices []string) *NetworkScanner {
	knownMap := make(map[string]bool)
	for _, device := range knownDevices {
		knownMap[device] = true
	}
	return &NetworkScanner{
		knownDevices: knownMap,
	}
}

// ScanNetwork discovers devices on the network using various methods
func (ns *NetworkScanner) ScanNetwork() ([]models.NetworkDevice, []models.Attack, error) {
	var devices []models.NetworkDevice
	var attacks []models.Attack

	// Try different scanning methods in order of preference
	deviceLists := []func() ([]models.NetworkDevice, error){
		ns.scanWithNmap,
		ns.scanWithPing,
		ns.scanWithNetdiscover,
	}

	for _, scanMethod := range deviceLists {
		devList, err := scanMethod()
		if err == nil && len(devList) > 0 {
			devices = devList
			break
		}
	}

	// Check for unknown devices
	for _, device := range devices {
		if !ns.knownDevices[device.IP] {
			attacks = append(attacks, models.Attack{
				Type:        "UNKNOWN_DEVICE",
				Severity:    models.SeverityHigh,
				Description: fmt.Sprintf("Unknown device detected: %s", device.IP),
				Target:      device.IP,
				Timestamp:   time.Now(),
			})
		}
	}

	return devices, attacks, nil
}

// scanWithNmap uses nmap to scan for devices
func (ns *NetworkScanner) scanWithNmap() ([]models.NetworkDevice, error) {
	if !isCommandAvailable("nmap") {
		return nil, fmt.Errorf("nmap not available")
	}

	cmd := exec.Command("nmap", "-sn", "192.168.1.0/24")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return ns.parseNmapOutput(string(output)), nil
}

// scanWithPing uses ping to discover devices
func (ns *NetworkScanner) scanWithPing() ([]models.NetworkDevice, error) {
	if !isCommandAvailable("fping") {
		return nil, fmt.Errorf("fping not available")
	}

	cmd := exec.Command("fping", "-a", "-g", "192.168.1.0/24", "-r", "1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return ns.parseFpingOutput(string(output)), nil
}

// scanWithNetdiscover uses a custom script if available
func (ns *NetworkScanner) scanWithNetdiscover() ([]models.NetworkDevice, error) {
	scripts := []string{
		"./scripts/netdiscover.sh",
		"../scripts/netdiscover.sh",
		"netdiscover.sh",
	}

	var scriptPath string
	for _, path := range scripts {
		if _, err := os.Stat(path); err == nil {
			scriptPath = path
			break
		}
	}

	if scriptPath == "" {
		return nil, fmt.Errorf("netdiscover script not found")
	}

	cmd := exec.Command("/bin/bash", scriptPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return ns.parseNetdiscoverOutput(string(output)), nil
}

// parseNmapOutput parses nmap scan output
func (ns *NetworkScanner) parseNmapOutput(output string) []models.NetworkDevice {
	var devices []models.NetworkDevice

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "Nmap scan report for") {
			ipRegex := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
			matches := ipRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				devices = append(devices, models.NetworkDevice{
					IP:    matches[1],
					State: "up",
				})
			}
		}
	}

	return devices
}

// parseFpingOutput parses fping output
func (ns *NetworkScanner) parseFpingOutput(output string) []models.NetworkDevice {
	var devices []models.NetworkDevice

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if net.ParseIP(line) != nil {
			devices = append(devices, models.NetworkDevice{
				IP:    line,
				State: "up",
			})
		}
	}

	return devices
}

// parseNetdiscoverOutput parses netdiscover script output
func (ns *NetworkScanner) parseNetdiscoverOutput(output string) []models.NetworkDevice {
	return ns.parseNmapOutput(output) // Use same parser for now
}

// ScanPorts scans for open ports on discovered devices
func (ns *NetworkScanner) ScanPorts(devices []models.NetworkDevice) ([]models.NetworkDevice, []models.Attack, error) {
	var attacks []models.Attack

	for i, device := range devices {
		ports, err := ns.scanDevicePorts(device.IP)
		if err != nil {
			continue
		}

		devices[i].Ports = ports

		// Check for suspicious ports
		for _, port := range ports {
			suspiciousPorts := map[int]string{
				21:  "FTP",
				23:  "Telnet",
				3389: "RDP",
				445: "SMB",
			}

			if port.State == "open" {
				if service, exists := suspiciousPorts[port.Number]; exists {
					attacks = append(attacks, models.Attack{
						Type:        "SUSPICIOUS_PORT",
						Severity:    models.SeverityMedium,
						Description: fmt.Sprintf("Suspicious open port detected: %s:%d (%s)", device.IP, port.Number, service),
						Target:      device.IP,
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}

	return devices, attacks, nil
}

// scanDevicePorts scans ports on a specific device
func (ns *NetworkScanner) scanDevicePorts(ip string) ([]models.Port, error) {
	if !isCommandAvailable("nmap") {
		return nil, fmt.Errorf("nmap not available for port scanning")
	}

	cmd := exec.Command("nmap", "-p", "21,22,23,25,53,80,110,143,443,993,995,3389,445", "--open", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return ns.parsePortScanOutput(string(output)), nil
}

// parsePortScanOutput parses nmap port scan output
func (ns *NetworkScanner) parsePortScanOutput(output string) []models.Port {
	var ports []models.Port

	scanner := bufio.NewScanner(strings.NewReader(output))
	inPortSection := false

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "PORT") && strings.Contains(line, "STATE") && strings.Contains(line, "SERVICE") {
			inPortSection = true
			continue
		}

		if inPortSection && strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "MAC") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				ports = append(ports, models.Port{
					Number: parsePortNumber(parts[0]),
					Protocol: parseProtocol(parts[0]),
					State:   parts[1],
					Service: parts[2],
				})
			}
		}

		if strings.Contains(line, "Nmap done") {
			break
		}
	}

	return ports
}

// Helper functions

func isCommandAvailable(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func parsePortNumber(portStr string) int {
	parts := strings.Split(portStr, "/")
	if len(parts) > 0 {
		if portNum, err := fmt.Sscanf(parts[0], "%d"); err == nil {
			return portNum
		}
	}
	return 0
}

func parseProtocol(portStr string) string {
	parts := strings.Split(portStr, "/")
	if len(parts) > 1 {
		return parts[1]
	}
	return "tcp"
}

// LoadKnownDevices loads known network devices from file
func LoadKnownDevices(filename string) ([]string, error) {
	var devices []string

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// Create empty file
			devices = []string{}
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

// SaveKnownDevices saves known network devices to file
func SaveKnownDevices(filename string, devices []string) error {
	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return err
	}

	dir := strings.TrimSuffix(filename, "/"+filename[strings.LastIndex(filename, "/")+1:][:strings.LastIndex(filename[strings.LastIndex(filename, "/")+1:], "/")+1])
	if dir != "" {
		os.MkdirAll(dir, 0755)
	}

	return os.WriteFile(filename, data, 0644)
}
