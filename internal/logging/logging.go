package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/boboTheFoff/shheissee-go/internal/models"
)

// Logger wraps log.Logger with additional functionality
type Logger struct {
	*log.Logger
	logFile *os.File
}

// NewLogger creates a new logger instance
func NewLogger(logFile string) (*Logger, error) {
	// Ensure directory exists
	dir := filepath.Dir(logFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	// Open log file
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	// Create multi-writer: both console and file
	multiWriter := io.MultiWriter(os.Stdout, file)

	// Create logger with timestamp format
	logger := log.New(multiWriter, "", log.LstdFlags)

	return &Logger{
		Logger:  logger,
		logFile: file,
	}, nil
}

// LogAttack logs attack information to the log file
func (l *Logger) LogAttack(attack *models.Attack) {
	// Log to file with severity
	l.Printf("[%s] %s: %s (Target: %s)",
		attack.Severity.String(),
		attack.Type,
		attack.Description,
		attack.Target)

	// Also log structured format for machine reading
	l.Printf("ATTACK_DETAILS: TYPE=%s|SEVERITY=%s|TARGET=%s|TIME=%s|DESC=%s",
		attack.Type,
		attack.Severity.String(),
		attack.Target,
		attack.Timestamp.Format(time.RFC3339),
		strings.ReplaceAll(attack.Description, "|", "\\|"))
}

// LogInfo logs informational message
func (l *Logger) LogInfo(message string) {
	l.Printf("INFO: %s", message)
}

// LogWarning logs warning message
func (l *Logger) LogWarning(message string) {
	l.Printf("WARNING: %s", message)
}

// LogError logs error message
func (l *Logger) LogError(message string, err error) {
	if err != nil {
		l.Printf("ERROR: %s - %v", message, err)
	} else {
		l.Printf("ERROR: %s", message)
	}
}

// LogDeviceDiscovery logs device discovery events
func (l *Logger) LogDeviceDiscovery(deviceType string, devices []interface{}) {
	l.Printf("DISCOVERY: Found %d %s devices", len(devices), deviceType)
}

// LogScanResult logs scan results
func (l *Logger) LogScanResult(scanType string, result *models.ScanResult) {
	if result.Error != "" {
		l.Printf("SCAN_FAILED: %s scan failed - %s", scanType, result.Error)
		return
	}

	attacks := len(result.Attacks)
	devices := len(result.Devices)
	l.Printf("SCAN_COMPLETE: %s scan finished - %d devices found, %d attacks detected",
		scanType, devices, attacks)
}

// Close closes the log file
func (l *Logger) Close() error {
	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// getSeverityColor returns ANSI color code for severity
func getSeverityColor(severity models.Severity) string {
	switch severity {
	case models.SeverityHigh:
		return models.ColorRed + models.ColorBold
	case models.SeverityMedium:
		return models.ColorYellow + models.ColorBold
	case models.SeverityLow:
		return models.ColorBlue + models.ColorBold
	default:
		return models.ColorWhite
	}
}

// ConsoleLogger provides colored console output for attacks
type ConsoleLogger struct{}

// NewConsoleLogger creates a new console logger
func NewConsoleLogger() *ConsoleLogger {
	return &ConsoleLogger{}
}

// DisplayAttack displays an attack with colors to console
func (c *ConsoleLogger) DisplayAttack(attack *models.Attack) {
	severityColor := getSeverityColor(attack.Severity)
	resetColor := models.ColorReset

	fmt.Printf("\n%s%s[%s] %s%s\n", severityColor, models.ColorBold,
		attack.Severity.String(), attack.Type, resetColor)
	fmt.Printf("%sDescription:%s %s\n", models.ColorBold, resetColor, attack.Description)
	fmt.Printf("%sTarget:%s %s\n", models.ColorBold, resetColor, attack.Target)
	fmt.Printf("%sTime:%s %s\n", models.ColorBold, resetColor,
		attack.Timestamp.Format("2006-01-02 15:04:05"))
}

// DisplayStatus displays current monitoring status
func (c *ConsoleLogger) DisplayStatus(devices int, bluetoothDevices int, totalAttacks int) {
	art := `
--mmmm  m    m m    m mmmmmm mmmmm   mmmm   mmmm  mmmmmm mmmmmm
 #"   " #    # #    # #        #    #"   " #"   " #      #
 "#mmm  #mmmm# #mmmm# #mmmmm   #    "#mmm  "#mmm  #mmmmm #mmmmm
     "# #    # #    # #        #        "#     "# #      #
 "mmm#" #    # #    # #mmmmm mm#mm  "mmm#" "mmm#" #mmmmm #mmmmm
        `
	fmt.Printf("\n%s%s%s", models.ColorPurple, models.ColorBold, art)
	fmt.Printf("%sThe Alley Monitoring Status: %sACTIVE%s\n", models.ColorGreen, models.ColorBold, models.ColorReset)
	fmt.Printf("Known Network Devices: %d\n", devices)
	fmt.Printf("Known Bluetooth Devices: %d\n", bluetoothDevices)
	fmt.Printf("Total Attacks Detected: %d\n", totalAttacks)
	fmt.Printf("%sPress Ctrl+C to stop monitoring%s\n\n",
		models.ColorBlue, models.ColorReset)
}

// DisplayMenu displays the main menu
func (c *ConsoleLogger) DisplayMenu() {
	art := `
 _____  _                       _____
/\___ \(_)_ __   ___  _ __   ___ /\___ \
\/___//\ \| '_ \ / _ \| '_ \ / _ \\/___//
  / /_/_|> | | | | (_) | | | |  __/  __/
 / / / /|_> |_| |_|\___/|_| |_|_| |_| \__\
 \// /_/     __ / \__ \ __ _\ \__ \ __ _   __ _/ |
  \/__/     /__ \   /_//__ _ \  / //__(_)/__/ |_|  (_)
                  \_/  |_____/  \/ \___| \__/ \____/|____/
    `
	fmt.Printf("\n%s%s%s", models.ColorPurple, models.ColorBold, art)
	fmt.Printf("%s%s          The Alley Intrusion Detection%s\n",
		models.ColorPurple, models.ColorBold, models.ColorReset)
	fmt.Printf("%s%s=====================================%s\n",
		models.ColorPurple, models.ColorBold, models.ColorReset)
	fmt.Printf("%sAvailable Options:%s\n", models.ColorBlue, models.ColorReset)
	fmt.Printf("  1. %sRun Full Security Monitoring%s\n",
		models.ColorGreen, models.ColorReset)
	fmt.Printf("  2. %sList Nearby Bluetooth Devices%s\n",
		models.ColorGreen, models.ColorReset)
	fmt.Printf("  3. %sMonitor Bluetooth Devices Continuously%s\n",
		models.ColorGreen, models.ColorReset)
	fmt.Printf("  4. %sMonitor Bluetooth Connection Attempts%s\n",
		models.ColorGreen, models.ColorReset)
	fmt.Printf("  5. %sPerform Quick Security Scan%s\n",
		models.ColorGreen, models.ColorReset)
	fmt.Printf("  6. %sList Nearby WiFi Devices%s\n",
		models.ColorGreen, models.ColorReset)
	fmt.Printf("  7. %sExit%s\n",
		models.ColorRed, models.ColorReset)
	fmt.Printf("%s==========================================%s\n",
		models.ColorPurple, models.ColorBold, models.ColorReset)
}
