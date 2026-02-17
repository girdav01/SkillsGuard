// Package engines provides the scanning engine interface and all engine implementations.
package engines

import "github.com/girdav01/skillguard/internal/core"

// ScanEngine is the interface all scanning engines must implement.
type ScanEngine interface {
	// Name returns the unique engine name.
	Name() string
	// Version returns the engine version string.
	Version() string
	// Scan scans skill files and returns results.
	Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error)
	// HealthCheck checks if the engine is operational.
	HealthCheck() bool
}
