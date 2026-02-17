// Package monitoring provides file watching and drift detection.
package monitoring

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/girdav01/skillguard/internal/core"
)

// DriftResult contains the results of a drift check.
type DriftResult struct {
	HasDrift     bool     `json:"has_drift"`
	AddedFiles   []string `json:"added_files,omitempty"`
	RemovedFiles []string `json:"removed_files,omitempty"`
	ModifiedFiles []string `json:"modified_files,omitempty"`
}

// DriftDetector captures baselines and detects file drift.
type DriftDetector struct {
	mu       sync.Mutex
	baseline map[string]string // path -> sha256
}

// NewDriftDetector creates a new DriftDetector.
func NewDriftDetector() *DriftDetector {
	return &DriftDetector{}
}

// CaptureBaseline captures the current state of a directory.
func (d *DriftDetector) CaptureBaseline(dirPath string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.baseline = make(map[string]string)
	skipDirs := map[string]bool{".git": true, "__pycache__": true, "node_modules": true, ".venv": true, "venv": true}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(dirPath, path)
		rel = filepath.ToSlash(rel)

		// Check parent dirs
		parts := strings.Split(rel, "/")
		for _, p := range parts[:len(parts)-1] {
			if skipDirs[p] {
				return nil
			}
		}

		hash, err := core.HashFile(path)
		if err != nil {
			return nil
		}
		d.baseline[rel] = hash
		return nil
	})
	return err
}

// CheckDrift compares the current state against the baseline.
func (d *DriftDetector) CheckDrift(dirPath string) DriftResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.baseline == nil {
		return DriftResult{}
	}

	current := make(map[string]string)
	skipDirs := map[string]bool{".git": true, "__pycache__": true, "node_modules": true, ".venv": true, "venv": true}

	filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(dirPath, path)
		rel = filepath.ToSlash(rel)
		parts := strings.Split(rel, "/")
		for _, p := range parts[:len(parts)-1] {
			if skipDirs[p] {
				return nil
			}
		}
		hash, _ := core.HashFile(path)
		current[rel] = hash
		return nil
	})

	result := DriftResult{}

	// Check for added and modified
	for path, hash := range current {
		baseHash, exists := d.baseline[path]
		if !exists {
			result.AddedFiles = append(result.AddedFiles, path)
			result.HasDrift = true
		} else if hash != baseHash {
			result.ModifiedFiles = append(result.ModifiedFiles, path)
			result.HasDrift = true
		}
	}

	// Check for removed
	for path := range d.baseline {
		if _, exists := current[path]; !exists {
			result.RemovedFiles = append(result.RemovedFiles, path)
			result.HasDrift = true
		}
	}

	return result
}
