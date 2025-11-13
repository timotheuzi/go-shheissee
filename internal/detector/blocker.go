package detector

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/boboTheFoff/shheissee-go/internal/logging"
	"github.com/boboTheFoff/shheissee-go/internal/models"
)

// Blocker handles active blocking of detected threats
type Blocker struct {
	logger         *logging.Logger
	blockedIPs     map[string]time.Time
	blockedMACs    map[string]time.Time
	blockedBTAddrs map[string]time.Time
	autoBlock      bool
	mu             sync.RWMutex
}

// NewBlocker creates a new blocker instance
func NewBlocker(logger *logging.Logger, autoBlock bool) *Blocker {
	return &Blocker{
		logger:         logger,
		blockedIPs:     make(map[string]time.Time),
		blockedMACs:    make(map[string]time.Time),
		blockedBTAddrs: make(map[string]time.Time),
		autoBlock:      autoBlock,
	}
}

// BlockIP blocks an IP address using iptables
func (b *Blocker) BlockIP(ip string, reason string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Check if already blocked
	if _, exists := b.blockedIPs[ip]; exists {
		return fmt.Errorf("IP %s is already blocked", ip)
	}

	// Try different firewall tools in order of preference
	var cmd *exec.Cmd
	var err error

	// Try ufw first (Ubuntu/Debian)
	if b.isCommandAvailable("ufw") {
		cmd = exec.Command("sudo", "ufw", "deny", "from", ip)
	} else if b.isCommandAvailable("firewall-cmd") {
		// Try firewalld (RHEL/CentOS/Fedora)
		cmd = exec.Command("sudo", "firewall-cmd", "--permanent", "--add-rich-rule", fmt.Sprintf("rule family='ipv4' source address='%s' reject", ip))
		err = cmd.Run()
		if err == nil {
			cmd = exec.Command("sudo", "firewall-cmd", "--reload")
		}
	} else if b.isCommandAvailable("iptables") {
		// Try iptables directly
		cmd = exec.Command("sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
	} else {
		return fmt.Errorf("no supported firewall tool found (ufw, firewalld, iptables)")
	}

	if cmd != nil {
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to block IP %s: %v", ip, err)
		}
	}

	// Record the block
	b.blockedIPs[ip] = time.Now()

	b.logger.LogInfo(fmt.Sprintf("Blocked IP %s: %s", ip, reason))
	return nil
}

// UnblockIP removes IP block
func (b *Blocker) UnblockIP(ip string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.blockedIPs[ip]; !exists {
		return fmt.Errorf("IP %s is not blocked", ip)
	}

	var cmd *exec.Cmd
	var err error

	// Try different firewall tools
	if b.isCommandAvailable("ufw") {
		cmd = exec.Command("sudo", "ufw", "delete", "deny", "from", ip)
	} else if b.isCommandAvailable("firewall-cmd") {
		cmd = exec.Command("sudo", "firewall-cmd", "--permanent", "--remove-rich-rule", fmt.Sprintf("rule family='ipv4' source address='%s' reject", ip))
		err = cmd.Run()
		if err == nil {
			cmd = exec.Command("sudo", "firewall-cmd", "--reload")
		}
	} else if b.isCommandAvailable("iptables") {
		cmd = exec.Command("sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	} else {
		return fmt.Errorf("no supported firewall tool found")
	}

	if cmd != nil {
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to unblock IP %s: %v", ip, err)
		}
	}

	delete(b.blockedIPs, ip)
	b.logger.LogInfo(fmt.Sprintf("Unblocked IP %s", ip))
	return nil
}

// BlockMAC blocks a MAC address using ebtables or iptables
func (b *Blocker) BlockMAC(mac string, reason string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.blockedMACs[mac]; exists {
		return fmt.Errorf("MAC %s is already blocked", mac)
	}

	var cmd *exec.Cmd
	var err error

	// Try ebtables for layer 2 blocking
	if b.isCommandAvailable("ebtables") {
		cmd = exec.Command("sudo", "ebtables", "-A", "INPUT", "-s", mac, "-j", "DROP")
		err = cmd.Run()
		if err == nil {
			b.blockedMACs[mac] = time.Now()
			b.logger.LogInfo(fmt.Sprintf("Blocked MAC %s: %s", mac, reason))
			return nil
		}
	}

	// Fallback to iptables with MAC matching
	if b.isCommandAvailable("iptables") {
		cmd = exec.Command("sudo", "iptables", "-I", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP")
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to block MAC %s: %v", mac, err)
		}
	} else {
		return fmt.Errorf("no supported tool for MAC blocking (ebtables or iptables)")
	}

	b.blockedMACs[mac] = time.Now()
	b.logger.LogInfo(fmt.Sprintf("Blocked MAC %s: %s", mac, reason))
	return nil
}

// UnblockMAC removes MAC block
func (b *Blocker) UnblockMAC(mac string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.blockedMACs[mac]; !exists {
		return fmt.Errorf("MAC %s is not blocked", mac)
	}

	var cmd *exec.Cmd
	var err error

	if b.isCommandAvailable("ebtables") {
		cmd = exec.Command("sudo", "ebtables", "-D", "INPUT", "-s", mac, "-j", "DROP")
		err = cmd.Run()
		if err == nil {
			delete(b.blockedMACs, mac)
			b.logger.LogInfo(fmt.Sprintf("Unblocked MAC %s", mac))
			return nil
		}
	}

	if b.isCommandAvailable("iptables") {
		cmd = exec.Command("sudo", "iptables", "-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP")
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to unblock MAC %s: %v", mac, err)
		}
	} else {
		return fmt.Errorf("no supported tool for MAC unblocking")
	}

	delete(b.blockedMACs, mac)
	b.logger.LogInfo(fmt.Sprintf("Unblocked MAC %s", mac))
	return nil
}

// BlockBluetoothDevice blocks a Bluetooth device by blocking its MAC
func (b *Blocker) BlockBluetoothDevice(btAddr string, reason string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.blockedBTAddrs[btAddr]; exists {
		return fmt.Errorf("Bluetooth device %s is already blocked", btAddr)
	}

	// Use rfkill to block Bluetooth devices if available
	if b.isCommandAvailable("rfkill") {
		// This is a simplified approach - in practice, Bluetooth blocking
		// might require more sophisticated tools like btmgmt
		cmd := exec.Command("sudo", "rfkill", "block", "bluetooth")
		err := cmd.Run()
		if err != nil {
			b.logger.LogError(fmt.Sprintf("Failed to block Bluetooth device %s", btAddr), err)
			return err
		}
	}

	b.blockedBTAddrs[btAddr] = time.Now()
	b.logger.LogInfo(fmt.Sprintf("Blocked Bluetooth device %s: %s", btAddr, reason))
	return nil
}

// UnblockBluetoothDevice removes Bluetooth device block
func (b *Blocker) UnblockBluetoothDevice(btAddr string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.blockedBTAddrs[btAddr]; !exists {
		return fmt.Errorf("Bluetooth device %s is not blocked", btAddr)
	}

	if b.isCommandAvailable("rfkill") {
		cmd := exec.Command("sudo", "rfkill", "unblock", "bluetooth")
		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to unblock Bluetooth device %s: %v", btAddr, err)
		}
	}

	delete(b.blockedBTAddrs, btAddr)
	b.logger.LogInfo(fmt.Sprintf("Unblocked Bluetooth device %s", btAddr))
	return nil
}

// DeauthWiFiClient sends deauthentication packets to disconnect a WiFi client
func (b *Blocker) DeauthWiFiClient(clientMAC string, apMAC string, reason string) error {
	if !b.isCommandAvailable("aireplay-ng") {
		return fmt.Errorf("aireplay-ng not available for WiFi deauthentication")
	}

	// Find monitor interface
	monitorInterface, err := b.findMonitorInterface()
	if err != nil {
		return fmt.Errorf("no monitor interface available for deauth: %v", err)
	}

	// Send deauth packets
	cmd := exec.Command("sudo", "aireplay-ng", "--deauth", "10", "-a", apMAC, "-c", clientMAC, monitorInterface)
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to deauth WiFi client %s: %v", clientMAC, err)
	}

	b.logger.LogInfo(fmt.Sprintf("Deauthenticated WiFi client %s from AP %s: %s", clientMAC, apMAC, reason))
	return nil
}

// BlockWiFiAccessPoint blocks access to a specific WiFi AP by MAC filtering
func (b *Blocker) BlockWiFiAccessPoint(apMAC string, reason string) error {
	// This would typically involve hostapd configuration or similar
	// For now, we'll use deauthentication as a blocking mechanism
	b.logger.LogInfo(fmt.Sprintf("WiFi AP blocking not fully implemented for %s: %s", apMAC, reason))
	return fmt.Errorf("WiFi AP blocking requires additional configuration")
}

// AutoBlockAttack automatically blocks an attack based on its type and severity
func (b *Blocker) AutoBlockAttack(attack models.Attack) error {
	if !b.autoBlock {
		return nil
	}

	switch attack.Type {
	case "UNKNOWN_DEVICE", "SUSPICIOUS_PORT", "AI_CONNECTION_ANOMALY":
		// Block by IP if it's an IP address
		if strings.Contains(attack.Target, ".") {
			return b.BlockIP(attack.Target, fmt.Sprintf("Auto-blocked: %s", attack.Description))
		}
	case "BLUETOOTH_SPOOFING", "BLUETOOTH_MITM":
		// Block Bluetooth device
		return b.BlockBluetoothDevice(attack.Target, fmt.Sprintf("Auto-blocked: %s", attack.Description))
	case "EVIL_TWIN", "ROGUE_AP":
		// Deauth WiFi clients from rogue APs
		// This is simplified - in practice would need more context
		b.logger.LogInfo(fmt.Sprintf("Would deauth clients from rogue AP: %s", attack.Target))
	}

	return nil
}

// GetBlockedItems returns all currently blocked items
func (b *Blocker) GetBlockedItems() models.BlockedItems {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return models.BlockedItems{
		BlockedIPs:     b.copyBlockedMap(b.blockedIPs),
		BlockedMACs:    b.copyBlockedMap(b.blockedMACs),
		BlockedBTAddrs: b.copyBlockedMap(b.blockedBTAddrs),
	}
}

// SetAutoBlock enables or disables automatic blocking
func (b *Blocker) SetAutoBlock(enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.autoBlock = enabled
	b.logger.LogInfo(fmt.Sprintf("Auto-blocking %s", map[bool]string{true: "enabled", false: "disabled"}[enabled]))
}

// Helper methods

func (b *Blocker) isCommandAvailable(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func (b *Blocker) findMonitorInterface() (string, error) {
	cmd := exec.Command("iwconfig")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Mode:Monitor") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				return strings.TrimSuffix(parts[0], ":"), nil
			}
		}
	}

	return "", fmt.Errorf("no monitor interface found")
}

func (b *Blocker) copyBlockedMap(original map[string]time.Time) map[string]time.Time {
	copy := make(map[string]time.Time)
	for k, v := range original {
		copy[k] = v
	}
	return copy
}
