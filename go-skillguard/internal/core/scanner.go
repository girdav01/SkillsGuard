package core

import (
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"sync"
	"time"
)

// EngineScanner is the interface for scan engines (defined here to avoid import cycle).
type EngineScanner interface {
	Name() string
	Version() string
	Scan(skillFiles []SkillFile, rules []DetectionRule) (*EngineResult, error)
	HealthCheck() bool
}

// ThreatIntel provides threat intelligence lookups.
type ThreatIntel interface {
	IsMaliciousHash(sha256 string) bool
}

// ScanOrchestrator coordinates parallel execution of all scanning engines.
type ScanOrchestrator struct {
	Engines     []EngineScanner
	ThreatIntel ThreatIntel
}

// NewScanOrchestrator creates a new ScanOrchestrator.
func NewScanOrchestrator(engines []EngineScanner, threatIntel ThreatIntel) *ScanOrchestrator {
	return &ScanOrchestrator{
		Engines:     engines,
		ThreatIntel: threatIntel,
	}
}

// Scan executes the full scan pipeline:
// 1. Parse & normalize skill structure
// 2. Hash all components
// 3. Check threat intelligence
// 4. Run all engines in parallel
// 5. Aggregate verdicts into composite score
func (o *ScanOrchestrator) Scan(request ScanRequest) (*ScanResult, error) {
	scanID := generateScanID()
	scanStarted := time.Now().UTC()

	if request.SkillPath == "" {
		return nil, ErrSkillPathRequired
	}

	skillFiles, err := ParseSkillDirectory(request.SkillPath)
	if err != nil {
		return nil, err
	}

	if len(skillFiles) == 0 {
		scanCompleted := time.Now().UTC()
		return &ScanResult{
			ScanID:             scanID,
			SkillName:          inferSkillName(request),
			SkillSHA256:        "",
			Platform:           request.Platform,
			ScanStarted:        scanStarted,
			ScanCompleted:      scanCompleted,
			CompositeScore:     0,
			Verdict:            VerdictClean,
			EngineResults:      []EngineResult{},
			TotalFindings:      0,
			FindingsBySeverity: map[string]int{},
			FilesScanned:       0,
		}, nil
	}

	// Compute composite hash
	fileHashes := make([]FileHash, len(skillFiles))
	for i, sf := range skillFiles {
		fileHashes[i] = FileHash{Path: sf.Path, SHA256: sf.SHA256}
	}
	skillSHA256 := HashSkill(fileHashes)

	// Check threat intelligence
	threatIntelMatch := false
	if o.ThreatIntel != nil {
		threatIntelMatch = o.ThreatIntel.IsMaliciousHash(skillSHA256)
	}

	// Run all engines in parallel
	engineResults := o.runEngines(skillFiles)

	// Calculate risk score
	score, verdict := CalculateRiskScore(engineResults, threatIntelMatch, false)

	scanCompleted := time.Now().UTC()

	totalFindings := 0
	for _, er := range engineResults {
		totalFindings += len(er.Findings)
	}

	return &ScanResult{
		ScanID:             scanID,
		SkillName:          inferSkillName(request),
		SkillSHA256:        skillSHA256,
		Platform:           request.Platform,
		ScanStarted:        scanStarted,
		ScanCompleted:      scanCompleted,
		CompositeScore:     score,
		Verdict:            verdict,
		EngineResults:      engineResults,
		TotalFindings:      totalFindings,
		FindingsBySeverity: AggregateFindingsBySeverity(engineResults),
		FilesScanned:       len(skillFiles),
		OWASPCoverage:      CollectOWASPCoverage(engineResults),
	}, nil
}

func (o *ScanOrchestrator) runEngines(skillFiles []SkillFile) []EngineResult {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var results []EngineResult

	for _, engine := range o.Engines {
		wg.Add(1)
		go func(e EngineScanner) {
			defer wg.Done()
			result, err := e.Scan(skillFiles, nil)
			if err != nil || result == nil {
				return
			}
			mu.Lock()
			results = append(results, *result)
			mu.Unlock()
		}(engine)
	}
	wg.Wait()

	if results == nil {
		results = []EngineResult{}
	}
	return results
}

// HealthCheck checks the health of all engines.
func (o *ScanOrchestrator) HealthCheck() map[string]bool {
	results := make(map[string]bool)
	for _, engine := range o.Engines {
		results[engine.Name()] = engine.HealthCheck()
	}
	return results
}

func generateScanID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func inferSkillName(request ScanRequest) string {
	if request.SkillPath != "" {
		return filepath.Base(request.SkillPath)
	}
	if request.GitURL != "" {
		parts := splitLast(request.GitURL, "/")
		return parts
	}
	return "unknown"
}

func splitLast(s, sep string) string {
	idx := len(s) - 1
	for idx >= 0 && string(s[idx]) != sep {
		idx--
	}
	if idx < 0 {
		return s
	}
	return s[idx+1:]
}

// ErrSkillPathRequired is returned when no skill path is provided.
var ErrSkillPathRequired = &ScanError{Msg: "skill_path is required (git_url not yet supported)"}

// ScanError is a custom error type.
type ScanError struct {
	Msg string
}

func (e *ScanError) Error() string {
	return e.Msg
}
