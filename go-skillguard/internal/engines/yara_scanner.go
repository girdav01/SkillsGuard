package engines

import (
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

// YaraScanner is a YARA rule-based scanning engine.
// In the Go version, YARA support is a placeholder — returns clean when no YARA library is available.
type YaraScanner struct{}

func NewYaraScanner() *YaraScanner { return &YaraScanner{} }

func (y *YaraScanner) Name() string    { return "yara_scanner" }
func (y *YaraScanner) Version() string { return "0.1.0" }

func (y *YaraScanner) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	elapsed := time.Since(start).Milliseconds()
	return &core.EngineResult{
		EngineName:    y.Name(),
		EngineVersion: y.Version(),
		Verdict:       core.EngineVerdictClean,
		Confidence:    0.0,
		Findings:      []core.Finding{},
		DurationMs:    elapsed,
	}, nil
}

func (y *YaraScanner) HealthCheck() bool { return false }
