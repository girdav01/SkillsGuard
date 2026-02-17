// Package api provides the REST API server for SkillGuard.
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/girdav01/skillguard/internal/core"
	"github.com/girdav01/skillguard/internal/engines"
	"github.com/girdav01/skillguard/internal/governance"
	"github.com/girdav01/skillguard/internal/intelligence"
	"github.com/girdav01/skillguard/internal/monitoring"
	"github.com/girdav01/skillguard/internal/reporting"
)

const maxRequestBodySize = 1 << 20 // 1 MB
const maxScanResults = 10000

// Server holds the API state.
type Server struct {
	mu             sync.RWMutex
	rulesDir       string
	allowedBaseDir string
	policyEngine   *governance.PolicyEngine
	rbac           *governance.RBACManager
	auditLog       *governance.AuditLog
	community      *intelligence.CommunityVerdicts
	threatDB       *intelligence.ThreatIntelDB
	mitre          *intelligence.MITREMapper
	scanResults    map[string]*core.ScanResult
	driftDetector  *monitoring.DriftDetector
}

// StartServer starts the API server.
func StartServer(port int, rulesDir string) error {
	cwd, _ := os.Getwd()
	s := &Server{
		rulesDir:       rulesDir,
		allowedBaseDir: cwd,
		policyEngine:   governance.NewPolicyEngine(),
		rbac:           governance.NewRBACManager(),
		auditLog:       governance.NewAuditLog(),
		community:      intelligence.NewCommunityVerdicts(),
		threatDB:       intelligence.NewThreatIntelDB(),
		mitre:          intelligence.NewMITREMapper(),
		scanResults:    make(map[string]*core.ScanResult),
		driftDetector:  monitoring.NewDriftDetector(),
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.SetHeader("Content-Type", "application/json"))
	r.Use(bodySizeLimiter)

	// Health
	r.Get("/health", s.handleHealth)

	// Scan routes
	r.Post("/api/v1/scan", s.handleScan)
	r.Get("/api/v1/scan/{scanID}", s.handleGetScan)

	// Rules routes
	r.Get("/api/v1/rules", s.handleListRules)

	// Policy routes
	r.Get("/api/v1/policies", s.handleListPolicies)
	r.Post("/api/v1/policies", s.handleAddPolicy)
	r.Delete("/api/v1/policies/{policyID}", s.handleDeletePolicy)
	r.Post("/api/v1/policies/evaluate/{scanID}", s.handleEvaluatePolicy)

	// Community routes
	r.Get("/api/v1/community/{sha256}", s.handleGetReputation)
	r.Post("/api/v1/community/{sha256}/verdict", s.handleAddVerdict)
	r.Post("/api/v1/community/{sha256}/comment", s.handleAddComment)

	// Inventory routes
	r.Get("/api/v1/ai-bom/{scanID}", s.handleGetAIBOM)
	r.Post("/api/v1/sbom", s.handleGenerateSBOM)
	r.Get("/api/v1/audit", s.handleGetAudit)
	r.Get("/api/v1/audit/verify", s.handleVerifyAudit)
	r.Get("/api/v1/audit/export", s.handleExportAudit)

	// Monitor routes
	r.Post("/api/v1/monitor/baseline", s.handleCaptureBaseline)
	r.Post("/api/v1/monitor/drift", s.handleCheckDrift)

	addr := fmt.Sprintf(":%d", port)
	return http.ListenAndServe(addr, r)
}

// bodySizeLimiter limits request body size to prevent DoS via large payloads.
func bodySizeLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
		}
		next.ServeHTTP(w, r)
	})
}

// sanitizePath validates and resolves a user-provided path, ensuring it doesn't
// escape the allowed base directory. Returns the cleaned absolute path or an error.
func (s *Server) sanitizePath(userPath string) (string, error) {
	if userPath == "" {
		return "", fmt.Errorf("path is required")
	}

	// Reject obvious traversal attempts
	if strings.Contains(userPath, "..") {
		return "", fmt.Errorf("path must not contain '..'")
	}

	// Resolve to absolute path
	absPath, err := filepath.Abs(userPath)
	if err != nil {
		return "", fmt.Errorf("invalid path")
	}

	// Resolve symlinks to prevent symlink-based traversal
	resolvedPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		// Path might not exist yet (e.g., baseline capture)
		// Fall back to the cleaned absolute path
		resolvedPath = absPath
	}

	// Verify the resolved path is within the allowed base directory
	if !strings.HasPrefix(resolvedPath, s.allowedBaseDir) {
		return "", fmt.Errorf("path is outside the allowed directory")
	}

	// Verify the path exists and is a directory
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return "", fmt.Errorf("path not found")
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path must be a directory")
	}

	return resolvedPath, nil
}

// storeScanResult stores a scan result with bounded cache eviction.
func (s *Server) storeScanResult(result *core.ScanResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.scanResults) >= maxScanResults {
		// Evict oldest entry
		for k := range s.scanResults {
			delete(s.scanResults, k)
			break
		}
	}
	s.scanResults[result.ScanID] = result
}

// getScanResult retrieves a scan result safely.
func (s *Server) getScanResult(scanID string) (*core.ScanResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.scanResults[scanID]
	return r, ok
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "healthy",
		"version": "0.3.0",
		"service": "skillguard-go",
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SkillPath string `json:"skill_path"`
		GitURL    string `json:"git_url"`
		ScanType  string `json:"scan_type"`
		Platform  string `json:"platform"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.SkillPath == "" && req.GitURL == "" {
		writeError(w, http.StatusBadRequest, "skill_path or git_url required")
		return
	}
	if req.ScanType == "" {
		req.ScanType = "full"
	}
	if req.Platform == "" {
		req.Platform = "generic"
	}

	// Validate and sanitize the skill path to prevent path traversal
	if req.SkillPath != "" {
		safePath, err := s.sanitizePath(req.SkillPath)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid skill_path: "+err.Error())
			return
		}
		req.SkillPath = safePath
	}

	request := core.ScanRequest{
		SkillPath: req.SkillPath,
		GitURL:    req.GitURL,
		ScanType:  req.ScanType,
		Platform:  core.SkillPlatform(req.Platform),
	}

	allEngines := buildEngineList(s.rulesDir)
	orchestrator := core.NewScanOrchestrator(allEngines, s.threatDB)
	result, err := orchestrator.Scan(request)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "scan failed")
		return
	}

	s.storeScanResult(result)
	s.auditLog.Log("scan", "api", map[string]string{
		"scan_id": result.ScanID,
		"skill":   result.SkillName,
		"verdict": string(result.Verdict),
	})

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "scanID")
	result, ok := s.getScanResult(scanID)
	if !ok {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	engineF := r.URL.Query().Get("engine")
	rules, _ := core.LoadRules(s.rulesDir, engineF, category, true)
	writeJSON(w, http.StatusOK, map[string]any{
		"rules": rules,
		"total": len(rules),
	})
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies := s.policyEngine.ListPolicies()
	writeJSON(w, http.StatusOK, map[string]any{
		"policies": policies,
		"total":    len(policies),
	})
}

func (s *Server) handleAddPolicy(w http.ResponseWriter, r *http.Request) {
	var policy governance.Policy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy")
		return
	}
	s.policyEngine.AddPolicy(policy)
	s.auditLog.Log("policy_add", "api", map[string]string{"policy_id": policy.ID})
	writeJSON(w, http.StatusCreated, policy)
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "policyID")
	if s.policyEngine.RemovePolicy(policyID) {
		s.auditLog.Log("policy_delete", "api", map[string]string{"policy_id": policyID})
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	} else {
		writeError(w, http.StatusNotFound, "policy not found")
	}
}

func (s *Server) handleEvaluatePolicy(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "scanID")
	result, ok := s.getScanResult(scanID)
	if !ok {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	results := s.policyEngine.Evaluate(result)
	writeJSON(w, http.StatusOK, map[string]any{
		"scan_id": scanID,
		"results": results,
	})
}

func (s *Server) handleGetReputation(w http.ResponseWriter, r *http.Request) {
	sha256 := chi.URLParam(r, "sha256")
	rep := s.community.GetReputation(sha256)
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleAddVerdict(w http.ResponseWriter, r *http.Request) {
	sha256 := chi.URLParam(r, "sha256")
	var req struct {
		Verdict string `json:"verdict"`
		Analyst string `json:"analyst"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	s.community.AddVerdict(sha256, req.Verdict, req.Analyst)
	s.auditLog.Log("community_verdict", req.Analyst, map[string]string{"sha256": sha256, "verdict": req.Verdict})
	writeJSON(w, http.StatusCreated, map[string]string{"status": "added"})
}

func (s *Server) handleAddComment(w http.ResponseWriter, r *http.Request) {
	sha256 := chi.URLParam(r, "sha256")
	var req struct {
		Author string `json:"author"`
		Text   string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	s.community.AddComment(sha256, req.Author, req.Text)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "added"})
}

func (s *Server) handleGetAIBOM(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "scanID")
	result, ok := s.getScanResult(scanID)
	if !ok {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	bom := reporting.GenerateAIBOM(result)
	writeJSON(w, http.StatusOK, bom)
}

func (s *Server) handleGenerateSBOM(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SkillPath     string `json:"skill_path"`
		IncludeScanID string `json:"include_scan_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.SkillPath == "" {
		writeError(w, http.StatusBadRequest, "skill_path required")
		return
	}

	// Validate and sanitize the skill path to prevent path traversal
	safePath, err := s.sanitizePath(req.SkillPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid skill_path: "+err.Error())
		return
	}

	var scanResult *core.ScanResult
	if req.IncludeScanID != "" {
		scanResult, _ = s.getScanResult(req.IncludeScanID)
	}

	sbom, err := reporting.GenerateSkillSBOM(safePath, scanResult)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SBOM generation failed")
		return
	}
	writeJSON(w, http.StatusOK, sbom)
}

func (s *Server) handleGetAudit(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	actor := r.URL.Query().Get("actor")
	entries := s.auditLog.Query(action, actor, 100)
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"total":   len(entries),
	})
}

func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	valid, idx := s.auditLog.VerifyIntegrity()
	result := map[string]any{
		"valid": valid,
	}
	if !valid {
		result["tampered_at"] = idx
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleExportAudit(w http.ResponseWriter, r *http.Request) {
	data, err := s.auditLog.Export()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "export failed")
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=audit_log.json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (s *Server) handleCaptureBaseline(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	// Validate and sanitize the path to prevent path traversal
	safePath, err := s.sanitizePath(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}

	if err := s.driftDetector.CaptureBaseline(safePath); err != nil {
		writeError(w, http.StatusInternalServerError, "baseline capture failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "baseline captured"})
}

func (s *Server) handleCheckDrift(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	// Validate and sanitize the path to prevent path traversal
	safePath, err := s.sanitizePath(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}

	drift := s.driftDetector.CheckDrift(safePath)
	writeJSON(w, http.StatusOK, drift)
}

func buildEngineList(rulesDir string) []core.EngineScanner {
	return []core.EngineScanner{
		engines.NewRegexScanner(rulesDir),
		engines.NewYaraScanner(),
		engines.NewSecretDetector(),
		engines.NewMLClassifier(),
		engines.NewVectorSearchEngine(),
		engines.NewToolPoisoningDetector(),
		engines.NewToolShadowingDetector(),
		engines.NewMCPConfigScanner(),
		engines.NewBehaviorAnalyzer(),
		engines.NewSchemaValidator(),
		engines.NewPermissionAnalyzer(),
		engines.NewObfuscationDetector(),
	}
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// Ensure imports are used
var _ = strings.Contains
var _ = io.Discard
var _ = filepath.Base
var _ = os.Getwd
