package engines

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

// Heuristic injection indicators with weights.
var injectionIndicators = []struct {
	Indicator string
	Weight    float64
}{
	{"ignore previous instructions", 0.35},
	{"ignore all previous", 0.35},
	{"disregard your", 0.30},
	{"disregard all", 0.30},
	{"forget everything", 0.30},
	{"override system", 0.30},
	{"new instructions:", 0.25},
	{"you are now", 0.20},
	{"act as", 0.15},
	{"pretend to be", 0.20},
	{"you are a", 0.10},
	{"your new role", 0.25},
	{"reveal your system prompt", 0.35},
	{"show me your instructions", 0.30},
	{"what are your rules", 0.20},
	{"repeat your system", 0.30},
	{"output your initial", 0.25},
	{"do anything now", 0.30},
	{"jailbreak", 0.25},
	{"developer mode", 0.20},
	{"no restrictions", 0.25},
	{"without any filters", 0.25},
	{"bypass safety", 0.30},
	{"</system>", 0.30},
	{"<|im_start|>", 0.35},
	{"[system]", 0.20},
	{"```system", 0.25},
	{"respond only with", 0.15},
	{"always output", 0.10},
	{"never mention", 0.15},
	{"do not reveal", 0.15},
	{"base64 decode", 0.20},
	{"eval(", 0.20},
	{"execute the following", 0.20},
}

const classificationThreshold = 0.7

// Classifiable file types.
var classifiableTypes = map[core.FileType]bool{
	core.FileTypeSkillMD:     true,
	core.FileTypeFrontmatter: true,
	core.FileTypeTemplate:    true,
}

// MLClassifier uses heuristic scoring for prompt injection detection.
// Falls back to heuristics since ONNX inference isn't available in Go without CGO bindings.
type MLClassifier struct{}

func NewMLClassifier() *MLClassifier { return &MLClassifier{} }

func (m *MLClassifier) Name() string    { return "ml_classifier" }
func (m *MLClassifier) Version() string { return "0.2.0" }

func (m *MLClassifier) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	var findings []core.Finding

	for _, sf := range skillFiles {
		if sf.Content == nil {
			continue
		}
		if !classifiableTypes[sf.FileType] {
			continue
		}
		fileFnds := classifyHeuristic(sf)
		findings = append(findings, fileFnds...)
	}

	elapsed := time.Since(start).Milliseconds()

	if len(findings) == 0 {
		return &core.EngineResult{
			EngineName:    m.Name(),
			EngineVersion: m.Version(),
			Verdict:       core.EngineVerdictClean,
			Confidence:    0.6,
			Findings:      []core.Finding{},
			DurationMs:    elapsed,
		}, nil
	}

	maxConf := 0.0
	for _, f := range findings {
		if f.Confidence > maxConf {
			maxConf = f.Confidence
		}
	}

	verdict := computeVerdict(findings)
	det := "Heuristic Prompt Injection"

	return &core.EngineResult{
		EngineName:    m.Name(),
		EngineVersion: m.Version(),
		Verdict:       verdict,
		Confidence:    maxConf,
		DetectionName: &det,
		Findings:      findings,
		DurationMs:    elapsed,
	}, nil
}

func (m *MLClassifier) HealthCheck() bool { return true }

func classifyHeuristic(sf core.SkillFile) []core.Finding {
	content := *sf.Content
	if strings.TrimSpace(content) == "" {
		return nil
	}

	var findings []core.Finding
	chunks := splitIntoChunks(content, 512)

	for _, chunk := range chunks {
		score := heuristicScore(chunk)
		if score >= classificationThreshold {
			severity := core.SeverityMedium
			if score >= 0.85 {
				severity = core.SeverityHigh
			}
			lineStart := estimateLine(content, chunk)
			snippet := chunk
			if len(snippet) > 300 {
				snippet = snippet[:300] + "..."
			}
			remediation := "Review and remove any content that attempts to override agent instructions, change roles, or bypass safety controls."
			roundedScore := math.Round(score*1000) / 1000
			findings = append(findings, core.Finding{
				RuleID:   "SG-ML-002",
				RuleName: "Heuristic Prompt Injection Detection",
				Severity: severity,
				Category: "prompt_injection",
				Description: fmt.Sprintf(
					"Heuristic classifier detected likely prompt injection with %.0f%% confidence. Multiple injection indicators found in content.",
					score*100,
				),
				FilePath:    sf.Path,
				LineStart:   lineStart,
				Snippet:     &snippet,
				OWASPLLM:    []string{"LLM01"},
				MITREAttack: []string{"T1059.006"},
				Confidence:  roundedScore,
				Remediation: &remediation,
			})
		}
	}
	return findings
}

func heuristicScore(text string) float64 {
	lower := strings.ToLower(text)
	total := 0.0
	for _, ind := range injectionIndicators {
		if strings.Contains(lower, ind.Indicator) {
			total += ind.Weight
		}
	}
	if total > 1.0 {
		total = 1.0
	}
	return total
}

func splitIntoChunks(text string, maxTokens int) []string {
	maxChars := maxTokens * 4
	if len(text) <= maxChars {
		if strings.TrimSpace(text) == "" {
			return nil
		}
		return []string{text}
	}

	paragraphs := strings.Split(text, "\n\n")
	var chunks []string
	currentChunk := ""

	for _, para := range paragraphs {
		if len(currentChunk)+len(para)+2 > maxChars {
			if strings.TrimSpace(currentChunk) != "" {
				chunks = append(chunks, strings.TrimSpace(currentChunk))
			}
			currentChunk = para
		} else {
			if currentChunk == "" {
				currentChunk = para
			} else {
				currentChunk += "\n\n" + para
			}
		}
	}
	if strings.TrimSpace(currentChunk) != "" {
		chunks = append(chunks, strings.TrimSpace(currentChunk))
	}
	return chunks
}

func estimateLine(fullContent, chunk string) *int {
	idx := strings.Index(fullContent, chunk[:min(100, len(chunk))])
	if idx < 0 {
		return nil
	}
	line := strings.Count(fullContent[:idx], "\n") + 1
	return &line
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
