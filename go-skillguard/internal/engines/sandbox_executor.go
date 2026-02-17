package engines

import (
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

// SandboxExecutor is a placeholder for sandbox-based dynamic analysis.
// In the Go version, dynamic sandbox execution is not implemented;
// use BehaviorAnalyzer for static behavioral detection.
type SandboxExecutor struct{}

func NewSandboxExecutor() *SandboxExecutor { return &SandboxExecutor{} }

func (s *SandboxExecutor) Name() string    { return "sandbox_executor" }
func (s *SandboxExecutor) Version() string { return "0.3.0" }

func (s *SandboxExecutor) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	elapsed := time.Since(start).Milliseconds()
	return &core.EngineResult{
		EngineName:    s.Name(),
		EngineVersion: s.Version(),
		Verdict:       core.EngineVerdictClean,
		Confidence:    0.0,
		Findings:      []core.Finding{},
		DurationMs:    elapsed,
	}, nil
}

func (s *SandboxExecutor) HealthCheck() bool { return false }
