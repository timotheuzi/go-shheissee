package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/boboTheFoff/shheissee-go/internal/config"
	"github.com/boboTheFoff/shheissee-go/internal/detector"
	"github.com/boboTheFoff/shheissee-go/internal/logging"
	"github.com/boboTheFoff/shheissee-go/internal/models"
	"github.com/boboTheFoff/shheissee-go/internal/web"
)

func main() {
	if len(os.Args) > 1 {
		handleCommand(os.Args[1:])
		return
	}

	// Initialize configuration and directories
	cfg := models.DefaultConfig()
	if err := config.EnsureDirectories(cfg); err != nil {
		fmt.Printf("%sError setting up directories: %v%s\n", models.ColorRed, err, models.ColorReset)
		os.Exit(1)
	}

	// Create logger for startup messages
	startupLogger, err := logging.NewLogger(cfg.LogFile)
	if err != nil {
		fmt.Printf("%sError creating logger: %v%s\n", models.ColorRed, err, models.ColorReset)
		os.Exit(1)
	}
	defer startupLogger.Close()

	// Initialize attack detector
	attackDetector, err := detector.NewAttackDetector(cfg)
	if err != nil {
		fmt.Printf("%sError initializing attack detector: %v%s\n", models.ColorRed, err, models.ColorReset)
		startupLogger.LogError("Failed to initialize attack detector", err)
		os.Exit(1)
	}
	defer attackDetector.Close()

	consoleLogger := logging.NewConsoleLogger()
	startupLogger.LogInfo("Go-Shheissee Security Monitor initialized")

	// Initialize web server
	webServer := web.NewWebServer(cfg.WebServerPort, "web", startupLogger)
	webServer.SetDetector(attackDetector)

	// Start web server in background
	go func() {
		if err := webServer.Start(); err != nil {
			startupLogger.LogError("Web server failed", err)
		}
	}()

	// Start web interface update goroutine
	go func() {
		for {
			attackCount := attackDetector.GetAttackCount()
			if attackCount > 0 {
				recentAttacks := attackDetector.GetRecentAttacks(50)
				webServer.UpdateAttacks(recentAttacks)
			}
		}
	}()

	// Display welcome message
	fmt.Printf("%sGo-Shheissee Security Monitor initialized successfully!%s\n", models.ColorGreen, models.ColorReset)
	fmt.Printf("%sWeb interface available at: http://localhost:%d%s\n", models.ColorBlue, cfg.WebServerPort, models.ColorReset)

	// Run main menu loop
	runMainMenu(attackDetector, consoleLogger, startupLogger)
}

func handleCommand(args []string) {
	command := strings.ToLower(args[0])

	switch command {
	case "monitor", "start":
		runMonitoring()
	case "scan":
		runQuickScan()
	case "bluetooth":
		runBluetoothMonitor()
	case "demo":
		runDemo()
	case "web":
		runWebServer()
	case "help", "-h", "--help":
		showHelp()
	default:
		fmt.Printf("%sUnknown command: %s%s\n", models.ColorRed, command, models.ColorReset)
		showHelp()
		os.Exit(1)
	}
}

func runMonitoring() {
	cfg := models.DefaultConfig()
	config.EnsureDirectories(cfg)

	attackDetector, err := detector.NewAttackDetector(cfg)
	if err != nil {
		fmt.Printf("%sError initializing detector: %v%s\n", models.ColorRed, err, models.ColorReset)
		os.Exit(1)
	}
	defer attackDetector.Close()

	// Initialize web server
	logger, _ := logging.NewLogger(cfg.LogFile)
	webServer := web.NewWebServer(cfg.WebServerPort, "web", logger)

	go func() {
		webServer.Start()
	}()

	fmt.Printf("%sStarting continuous security monitoring...%s\n", models.ColorGreen, models.ColorReset)
	fmt.Printf("%sWeb interface: http://localhost:%d%s\n", models.ColorBlue, cfg.WebServerPort, models.ColorReset)

	attackDetector.StartMonitoring()
}

func runQuickScan() {
	cfg := models.DefaultConfig()
	config.EnsureDirectories(cfg)

	attackDetector, err := detector.NewAttackDetector(cfg)
	if err != nil {
		fmt.Printf("%sError initializing detector: %v%s\n", models.ColorRed, err, models.ColorReset)
		os.Exit(1)
	}
	defer attackDetector.Close()

	consoleLogger := logging.NewConsoleLogger()

	fmt.Printf("%sPerforming quick security scan...%s\n", models.ColorBlue, models.ColorReset)

	attacks := attackDetector.PerformQuickScan()

	if len(attacks) > 0 {
		fmt.Printf("%sFound %d potential security threats:%s\n", models.ColorYellow, len(attacks), models.ColorReset)
		for _, attack := range attacks {
			consoleLogger.DisplayAttack(&attack)
		}
	} else {
		fmt.Printf("%s✅ No threats detected in quick scan.%s\n", models.ColorGreen, models.ColorReset)
	}
}

func runBluetoothMonitor() {
	cfg := models.DefaultConfig()
	config.EnsureDirectories(cfg)

	attackDetector, err := detector.NewAttackDetector(cfg)
	if err != nil {
		fmt.Printf("%sError initializing detector: %v%s\n", models.ColorRed, err, models.ColorReset)
		os.Exit(1)
	}
	defer attackDetector.Close()

	err = attackDetector.MonitorBluetoothDevices()
	if err != nil {
		fmt.Printf("%sBluetooth monitoring error: %v%s\n", models.ColorRed, err, models.ColorReset)
	}
}

func runDemo() {
	cfg := models.DefaultConfig()
	config.EnsureDirectories(cfg)

	attackDetector, err := detector.NewAttackDetector(cfg)
	if err != nil {
		fmt.Printf("%sError initializing detector: %v%s\n", models.ColorRed, err, models.ColorReset)
		os.Exit(1)
	}
	defer attackDetector.Close()

	err = attackDetector.PerformDemoAttack()
	if err != nil {
		fmt.Printf("%sDemo setup failed: %v%s\n", models.ColorRed, err, models.ColorReset)
	}
}

func runWebServer() {
	cfg := models.DefaultConfig()
	config.EnsureDirectories(cfg)

	logger, _ := logging.NewLogger(cfg.LogFile)
	webServer := web.NewWebServer(cfg.WebServerPort, "web", logger)

	fmt.Printf("%sStarting web server on port %d...%s\n", models.ColorGreen, cfg.WebServerPort, models.ColorReset)
	fmt.Printf("%sWeb interface: http://localhost:%d%s\n", models.ColorBlue, cfg.WebServerPort, models.ColorReset)

	if err := webServer.Start(); err != nil {
		fmt.Printf("%sWeb server error: %v%s\n", models.ColorRed, err, models.ColorReset)
		os.Exit(1)
	}
}

func runMainMenu(ad *detector.AttackDetector, consoleLogger *logging.ConsoleLogger, logger *logging.Logger) {
	for {
		consoleLogger.DisplayMenu()

		var choice string
		fmt.Print("\033[34mSelect an option (1-7): \033[0m")
		fmt.Scanln(&choice)

		switch choice {
		case "1":
			fmt.Println("\033[32mStarting full security monitoring...\033[0m")
			ad.StartMonitoring()
			return // Exit after monitoring mode

		case "2":
			fmt.Println("\033[32mListing nearby Bluetooth devices...\033[0m")
			devices, err := ad.ListBluetoothDevices()
			if err != nil {
				fmt.Printf("\033[31mError: %v\033[0m\n", err)
			} else {
				fmt.Printf("\n\033[32mFound %d Bluetooth device(s):\033[0m\n", len(devices))
				if len(devices) > 0 {
					fmt.Println("\033[1mMAC Address         Device Name                    RSSI   Status\033[0m")
					fmt.Println("-" + strings.Repeat("-", 69))
					for _, device := range devices {
						rssi := "N/A"
						if device.RSSI != 0 {
							rssi = strconv.Itoa(device.RSSI)
						}
						status := device.Status
						if status == "" {
							status = "Unknown"
						}
						fmt.Printf("%-18s %-30s %-6s %-10s\n",
							device.Address, device.Name, rssi, status)
					}
				}
				fmt.Println()
			}
			waitForEnter()

		case "3":
			fmt.Println("\033[32mStarting Bluetooth device monitor...\033[0m")
			ad.MonitorBluetoothDevices()
			return

		case "4":
			fmt.Println("\033[32mStarting Bluetooth connection monitor...\033[0m")
			ad.MonitorBluetoothConnections()
			return

		case "5":
			fmt.Println("\033[33mPerforming quick security scan...\033[0m")
			attacks := ad.PerformQuickScan()
			if len(attacks) > 0 {
				fmt.Printf("\033[33mScan found %d potential issues:\033[0m\n", len(attacks))
			} else {
				fmt.Println("\033[32m✅ Quick scan complete - no threats detected.\033[0m")
			}
			waitForEnter()

		case "6":
			fmt.Println("\033[32mListing nearby WiFi devices...\033[0m")
			devices, err := ad.ListWiFiDevices()
			if err != nil {
				fmt.Printf("\033[31mError: %v\033[0m\n", err)
			} else {
				fmt.Printf("\n\033[32mFound %d WiFi device(s)/network(s):\033[0m\n", len(devices))
				if len(devices) > 0 {
					fmt.Println("\033[1mMAC Address         SSID                           Signal Ch Status\033[0m")
					fmt.Println("-" + strings.Repeat("-", 83))
					for _, device := range devices {
						status := device.Status
						if status == "" {
							status = "Unknown"
						}
						fmt.Printf("%-18s %-30s %-6s %-2s %-10s\n",
							device.Address, device.SSID, device.Signal, device.Channel, status)
					}
				}
				fmt.Println()
			}
			waitForEnter()

		case "7":
			fmt.Println("\033[32mExiting Go-Shheissee Security Monitor. Goodbye!\033[0m")
			logger.LogInfo("Go-Shheissee Security Monitor shutdown by user")
			return

		default:
			fmt.Println("\033[31mInvalid choice. Please select 1-7.\033[0m")
			waitForEnter()
		}
	}
}

func waitForEnter() {
	fmt.Print("\033[34mPress Enter to continue...\033[0m")
	fmt.Scanln()
}

func showHelp() {
	fmt.Println("Go-Shheissee Security Monitor")
	fmt.Println("Usage: go-shheissee [command]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  monitor, start    Start continuous security monitoring")
	fmt.Println("  scan              Perform quick security scan")
	fmt.Println("  bluetooth         Start Bluetooth device monitor")
	fmt.Println("  demo              Set up demo attack scenario")
	fmt.Println("  web               Start web server only")
	fmt.Println("  help, -h, --help  Show this help message")
	fmt.Println()
	fmt.Println("Running without arguments starts the interactive menu.")
}
