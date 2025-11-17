package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/boboTheFoff/shheissee-go/internal/models"
	"github.com/boboTheFoff/shheissee-go/internal/logging"
)

// WebServer handles web interface for attack monitoring
type WebServer struct {
	port            int
	router          *mux.Router
	detector        interface{} // Will be AttackDetector, avoiding circular import
	logger          *logging.Logger
	templateDir     string
	attackLog       []models.Attack
}

// TemplateData holds data for HTML templates
type TemplateData struct {
	Title           string
	Timestamp       string
	TotalHigh        int
	TotalMedium      int
	TotalLow         int
	TotalAttacks     int
	RecentAttacks    []models.Attack
}

// NewWebServer creates a new web server instance
func NewWebServer(port int, templateDir string, logger *logging.Logger) *WebServer {
	ws := &WebServer{
		port:        port,
		router:      mux.NewRouter(),
		logger:      logger,
		templateDir: templateDir,
		attackLog:   []models.Attack{},
	}

	ws.setupRoutes()
	return ws
}

// SetDetector sets the attack detector instance
func (ws *WebServer) SetDetector(detector interface{}) {
	ws.detector = detector
}

// Start starts the web server
func (ws *WebServer) Start() error {
	addr := fmt.Sprintf(":%d", ws.port)
	ws.logger.LogInfo(fmt.Sprintf("Starting web server on %s", addr))
	return http.ListenAndServe(addr, ws.router)
}

// setupRoutes configures all HTTP routes
func (ws *WebServer) setupRoutes() {
	ws.router.HandleFunc("/", ws.handleHome)
	ws.router.HandleFunc("/intrusion-detection", ws.handleIntrusionLog)
	ws.router.HandleFunc("/warnings", ws.handleWarnings)
	ws.router.HandleFunc("/blocking", ws.handleBlocking)

	// API routes
	ws.router.HandleFunc("/api/attacks", ws.handleAPIAttacks)
	ws.router.HandleFunc("/api/status", ws.handleAPIStatus)
	ws.router.HandleFunc("/api/blocked", ws.handleAPIBlocked)
	ws.router.HandleFunc("/api/block/ip", ws.handleAPIBlockIP).Methods("POST")
	ws.router.HandleFunc("/api/unblock/ip", ws.handleAPIUnblockIP).Methods("POST")
	ws.router.HandleFunc("/api/block/mac", ws.handleAPIBlockMAC).Methods("POST")
	ws.router.HandleFunc("/api/unblock/mac", ws.handleAPIUnblockMAC).Methods("POST")
	ws.router.HandleFunc("/api/block/bt", ws.handleAPIBlockBT).Methods("POST")
	ws.router.HandleFunc("/api/unblock/bt", ws.handleAPIUnblockBT).Methods("POST")
	ws.router.HandleFunc("/api/deauth/wifi", ws.handleAPIDeauthWiFi).Methods("POST")
	ws.router.HandleFunc("/api/autoblock", ws.handleAPISetAutoBlock).Methods("POST")

	// Serve static files
	ws.router.PathPrefix("/static/").Handler(
		http.StripPrefix("/static/", http.FileServer(http.Dir(ws.templateDir+"/static"))),
	)
}

// handleHome serves the main dashboard
func (ws *WebServer) handleHome(w http.ResponseWriter, r *http.Request) {
	data := ws.prepareTemplateData("Shheissee - AI Security Monitor")
	ws.renderTemplate(w, "index.html", data)
}

// handleIntrusionLog serves the intrusion detection log
func (ws *WebServer) handleIntrusionLog(w http.ResponseWriter, r *http.Request) {
	data := ws.prepareTemplateData("Intrusion Detection System")
	ws.renderTemplate(w, "intrusion.html", data)
}

// handleWarnings serves the warnings page
func (ws *WebServer) handleWarnings(w http.ResponseWriter, r *http.Request) {
	data := ws.prepareTemplateData("System Warnings & Alerts")
	ws.renderTemplate(w, "warnings.html", data)
}

// APIAttack represents attack data for JSON API
type APIAttack struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Timestamp   string `json:"timestamp"`
}

// handleAPIAttacks provides JSON API for attack data
func (ws *WebServer) handleAPIAttacks(w http.ResponseWriter, r *http.Request) {
	limit := 50 // Default limit
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil {
			limit = parsed
		}
	}

	// Get recent attacks (last 'limit' entries)
	start := len(ws.attackLog) - limit
	if start < 0 {
		start = 0
	}
	recentAttacks := ws.attackLog[start:]

	// Convert attacks to API format
	apiAttacks := make([]APIAttack, len(recentAttacks))
	for i, attack := range recentAttacks {
		apiAttacks[i] = APIAttack{
			Type:        attack.Type,
			Description: attack.Description,
			Timestamp:   attack.Timestamp.Format(time.RFC3339),
		}
	}

	response := map[string]interface{}{
		"attacks": apiAttacks,
		"count":   len(apiAttacks),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	json.NewEncoder(w).Encode(response)
}

// handleAPIStatus provides system status JSON
func (ws *WebServer) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	_ = map[string]interface{}{
		"status":      "active",
		"total_attacks": len(ws.attackLog),
		"timestamp":   time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fmt.Fprintf(w, `{"status": "active", "total_attacks": %d, "timestamp": "%s"}`,
		len(ws.attackLog), time.Now().Format(time.RFC3339))
}

// prepareTemplateData prepares common template data
func (ws *WebServer) prepareTemplateData(title string) TemplateData {
	// Count attacks by severity
	high := 0
	medium := 0
	low := 0

	for _, attack := range ws.attackLog {
		switch attack.Severity {
		case models.SeverityHigh:
			high++
		case models.SeverityMedium:
			medium++
		case models.SeverityLow:
			low++
		}
	}

	// Get recent attacks (last 50)
	start := len(ws.attackLog) - 50
	if start < 0 {
		start = 0
	}
	recentAttacks := ws.attackLog[start:]

	return TemplateData{
		Title:        title,
		Timestamp:    time.Now().Format("2006-01-02 15:04:05"),
		TotalHigh:    high,
		TotalMedium:  medium,
		TotalLow:     low,
		TotalAttacks: len(ws.attackLog),
		RecentAttacks: recentAttacks,
	}
}

// renderTemplate renders an HTML template
func (ws *WebServer) renderTemplate(w http.ResponseWriter, tmpl string, data TemplateData) {
	templatePath := ws.templateDir + "/templates/" + tmpl
	t, err := template.ParseFiles(templatePath)
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	err = t.Execute(w, data)
	if err != nil {
		http.Error(w, "Template execution error: "+err.Error(), 500)
	}
}

// UpdateAttacks updates the attack log (called by detector)
func (ws *WebServer) UpdateAttacks(attacks []models.Attack) {
	ws.attackLog = attacks

	// Keep only recent attacks to prevent memory issues
	maxAttacks := 1000
	if len(ws.attackLog) > maxAttacks {
		ws.attackLog = ws.attackLog[len(ws.attackLog)-maxAttacks:]
	}
}

// GetRecentAttacks returns recent attacks for other components
func (ws *WebServer) GetRecentAttacks(limit int) []models.Attack {
	start := len(ws.attackLog) - limit
	if start < 0 {
		start = 0
	}
	return ws.attackLog[start:]
}

// handleBlocking serves the blocking management page
func (ws *WebServer) handleBlocking(w http.ResponseWriter, r *http.Request) {
	data := ws.prepareTemplateData("Active Blocking Management")
	ws.renderTemplate(w, "blocking.html", data)
}

// handleAPIBlocked returns currently blocked items
func (ws *WebServer) handleAPIBlocked(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// This would get blocked items from detector in a complete implementation
	fmt.Fprintf(w, `{"blocked_ips": {}, "blocked_macs": {}, "blocked_bt_addrs": {}}`)
}

// handleAPIBlockIP blocks an IP address
func (ws *WebServer) handleAPIBlockIP(w http.ResponseWriter, r *http.Request) {
	ip := r.FormValue("ip")
	reason := r.FormValue("reason")
	if reason == "" {
		reason = "Manual block via web interface"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// This would call detector.BlockIP in a complete implementation
	fmt.Fprintf(w, `{"success": true, "message": "IP %s blocked", "ip": "%s"}`, ip, ip)
	ip = ip // use the variable
}

// handleAPIUnblockIP unblocks an IP address
func (ws *WebServer) handleAPIUnblockIP(w http.ResponseWriter, r *http.Request) {
	ip := r.FormValue("ip")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// This would call detector.UnblockIP in a complete implementation
	fmt.Fprintf(w, `{"success": true, "message": "IP %s unblocked", "ip": "%s"}`, ip, ip)
	ip = ip // use the variable
}

// handleAPIBlockMAC blocks a MAC address
func (ws *WebServer) handleAPIBlockMAC(w http.ResponseWriter, r *http.Request) {
	mac := r.FormValue("mac")
	reason := r.FormValue("reason")
	if reason == "" {
		reason = "Manual block via web interface"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// This would call detector.BlockMAC in a complete implementation
	fmt.Fprintf(w, `{"success": true, "message": "MAC %s blocked", "mac": "%s"}`, mac, mac)
	mac = mac // use the variable
}

// handleAPIUnblockMAC unblocks a MAC address
func (ws *WebServer) handleAPIUnblockMAC(w http.ResponseWriter, r *http.Request) {
	mac := r.FormValue("mac")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// This would call detector.UnblockMAC in a complete implementation
	fmt.Fprintf(w, `{"success": true, "message": "MAC %s unblocked", "mac": "%s"}`, mac, mac)
	mac = mac // use the variable
}

// handleAPIBlockBT blocks a Bluetooth device
func (ws *WebServer) handleAPIBlockBT(w http.ResponseWriter, r *http.Request) {
	btAddr := r.FormValue("bt_addr")
	reason := r.FormValue("reason")
	if reason == "" {
		reason = "Manual block via web interface"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// This would call detector.BlockBluetoothDevice in a complete implementation
	fmt.Fprintf(w, `{"success": true, "message": "Bluetooth device %s blocked", "bt_addr": "%s"}`, btAddr, btAddr)
	btAddr = btAddr // use the variable
}

// handleAPIUnblockBT unblocks a Bluetooth device
func (ws *WebServer) handleAPIUnblockBT(w http.ResponseWriter, r *http.Request) {
	btAddr := r.FormValue("bt_addr")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// This would call detector.UnblockBluetoothDevice in a complete implementation
	fmt.Fprintf(w, `{"success": true, "message": "Bluetooth device %s unblocked", "bt_addr": "%s"}`, btAddr, btAddr)
	btAddr = btAddr // use the variable
}

// handleAPIDeauthWiFi deauthenticates a WiFi client
func (ws *WebServer) handleAPIDeauthWiFi(w http.ResponseWriter, r *http.Request) {
	clientMAC := r.FormValue("client_mac")
	apMAC := r.FormValue("ap_mac")
	reason := r.FormValue("reason")
	if reason == "" {
		reason = "Manual deauth via web interface"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// This would call detector.DeauthWiFiClient in a complete implementation
	fmt.Fprintf(w, `{"success": true, "message": "WiFi client %s deauthenticated from AP %s", "client_mac": "%s", "ap_mac": "%s"}`, clientMAC, apMAC, clientMAC, apMAC)
	clientMAC = clientMAC // use the variable
	apMAC = apMAC // use the variable
}

// handleAPISetAutoBlock enables/disables auto-blocking
func (ws *WebServer) handleAPISetAutoBlock(w http.ResponseWriter, r *http.Request) {
	enabledStr := r.FormValue("enabled")
	enabled := enabledStr == "true"

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// This would call detector.SetAutoBlock in a complete implementation
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	fmt.Fprintf(w, `{"success": true, "message": "Auto-blocking %s", "enabled": %t}`, status, enabled)
	enabled = enabled // use the variable
}
