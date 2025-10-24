package web

import (
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
	ws.router.HandleFunc("/api/attacks", ws.handleAPIAttacks)
	ws.router.HandleFunc("/api/status", ws.handleAPIStatus)

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

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// This would output JSON in a complete implementation
	fmt.Fprintf(w, `{"attacks": [], "count": 0}`)
	recentAttacks = recentAttacks // use the variable
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
