package core

import "testing"

func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityInfo, "info"},
	}
	for _, tt := range tests {
		if string(tt.sev) != tt.want {
			t.Errorf("Severity %v = %q, want %q", tt.sev, string(tt.sev), tt.want)
		}
	}
}

func TestVerdictConstants(t *testing.T) {
	tests := []struct {
		v    Verdict
		want string
	}{
		{VerdictClean, "clean"},
		{VerdictLowRisk, "low_risk"},
		{VerdictSuspicious, "suspicious"},
		{VerdictHighRisk, "high_risk"},
		{VerdictMalicious, "malicious"},
	}
	for _, tt := range tests {
		if string(tt.v) != tt.want {
			t.Errorf("Verdict %v = %q, want %q", tt.v, string(tt.v), tt.want)
		}
	}
}

func TestNewScanRequest(t *testing.T) {
	req := NewScanRequest("/path/to/skill")
	if req.SkillPath != "/path/to/skill" {
		t.Errorf("SkillPath = %q, want %q", req.SkillPath, "/path/to/skill")
	}
	if req.ScanType != "full" {
		t.Errorf("ScanType = %q, want %q", req.ScanType, "full")
	}
	if req.Platform != PlatformGeneric {
		t.Errorf("Platform = %q, want %q", req.Platform, PlatformGeneric)
	}
}

func TestSeverityPoints(t *testing.T) {
	if SeverityPoints[SeverityCritical] != 40 {
		t.Error("CRITICAL should be 40 points")
	}
	if SeverityPoints[SeverityHigh] != 20 {
		t.Error("HIGH should be 20 points")
	}
	if SeverityPoints[SeverityMedium] != 10 {
		t.Error("MEDIUM should be 10 points")
	}
	if SeverityPoints[SeverityLow] != 3 {
		t.Error("LOW should be 3 points")
	}
	if SeverityPoints[SeverityInfo] != 0 {
		t.Error("INFO should be 0 points")
	}
}
