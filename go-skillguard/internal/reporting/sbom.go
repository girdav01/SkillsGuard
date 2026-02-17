package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

// GenerateSkillSBOM generates a CycloneDX 1.5 SBOM from a skill directory.
func GenerateSkillSBOM(skillPath string, scanResult *core.ScanResult) (map[string]any, error) {
	files, err := core.ParseSkillDirectory(skillPath)
	if err != nil {
		return nil, err
	}

	skillName := filepath.Base(skillPath)
	skillRef := fmt.Sprintf("skill:%s", skillName)

	// Build file inventory
	inventory := buildFileInventory(files)

	// Extract dependencies
	deps := extractAllDependencies(files)

	// Extract metadata
	metadata := extractSkillMetadata(files)

	// Detect license
	license := detectLicense(files)

	// Extract external references
	externalRefs := extractExternalRefs(files)

	// Build components
	components := make([]map[string]any, 0)

	// Main skill component
	mainComponent := map[string]any{
		"type":    "application",
		"name":    skillName,
		"bom-ref": skillRef,
		"properties": []map[string]string{
			{"name": "skillguard:type", "value": "ai-skill"},
			{"name": "skillguard:files_count", "value": fmt.Sprintf("%d", len(files))},
		},
	}
	if metadata["version"] != "" {
		mainComponent["version"] = metadata["version"]
	}
	if metadata["description"] != "" {
		mainComponent["description"] = metadata["description"]
	}
	if license != "" {
		mainComponent["licenses"] = []map[string]any{
			{"license": map[string]string{"name": license}},
		}
	}
	if len(externalRefs) > 0 {
		mainComponent["externalReferences"] = externalRefs
	}
	components = append(components, mainComponent)

	// Dependency components
	depRefs := make([]string, 0)
	seenPurls := make(map[string]bool)
	for _, dep := range deps {
		purl := dep["purl"]
		if seenPurls[purl] {
			continue
		}
		seenPurls[purl] = true
		comp := map[string]any{
			"type":    "library",
			"name":    dep["name"],
			"bom-ref": purl,
			"purl":    purl,
		}
		if dep["version"] != "" {
			comp["version"] = dep["version"]
		}
		components = append(components, comp)
		depRefs = append(depRefs, purl)
	}

	// File components
	for _, fi := range inventory {
		comp := map[string]any{
			"type":    "file",
			"name":    fi["name"],
			"bom-ref": fmt.Sprintf("file:%s", fi["path"]),
			"hashes":  []map[string]string{{"alg": "SHA-256", "content": fi["sha256"]}},
			"properties": []map[string]string{
				{"name": "skillguard:file_type", "value": fi["file_type"]},
				{"name": "skillguard:size_bytes", "value": fi["size_bytes"]},
			},
		}
		components = append(components, comp)
	}

	// Build dependency graph
	dependencies := []map[string]any{
		{"ref": skillRef, "dependsOn": depRefs},
	}

	sbom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools": []map[string]string{
				{"name": "SkillGuard", "version": "0.3.0"},
			},
			"component": mainComponent,
		},
		"components":   components,
		"dependencies": dependencies,
	}

	// Add vulnerabilities from scan result
	if scanResult != nil && scanResult.TotalFindings > 0 {
		vulns := buildVulnerabilities(scanResult, skillRef)
		if len(vulns) > 0 {
			sbom["vulnerabilities"] = vulns
		}
	}

	return sbom, nil
}

// GenerateSkillSBOMJSON generates SBOM as JSON string.
func GenerateSkillSBOMJSON(skillPath string, scanResult *core.ScanResult) (string, error) {
	sbom, err := GenerateSkillSBOM(skillPath, scanResult)
	if err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func buildFileInventory(files []core.SkillFile) []map[string]string {
	var inventory []map[string]string
	for _, f := range files {
		inventory = append(inventory, map[string]string{
			"path":       f.Path,
			"name":       filepath.Base(f.Path),
			"file_type":  string(f.FileType),
			"sha256":     f.SHA256,
			"size_bytes": fmt.Sprintf("%d", f.SizeBytes),
		})
	}
	return inventory
}

func extractAllDependencies(files []core.SkillFile) []map[string]string {
	var deps []map[string]string
	for _, f := range files {
		if f.Content == nil {
			continue
		}
		name := strings.ToLower(filepath.Base(f.Path))
		switch name {
		case "requirements.txt":
			deps = append(deps, parseRequirementsTxt(*f.Content)...)
		case "package.json":
			deps = append(deps, parsePackageJSON(*f.Content)...)
		case "pyproject.toml":
			deps = append(deps, parsePyprojectTOML(*f.Content)...)
		}
	}
	return deps
}

func parseRequirementsTxt(content string) []map[string]string {
	var deps []map[string]string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Parse name[>=<~!]=version
		re := regexp.MustCompile(`^([A-Za-z0-9_.-]+)\s*(?:[><=~!]+\s*(.+))?$`)
		match := re.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		name := match[1]
		version := ""
		if match[2] != "" {
			version = strings.Split(match[2], ",")[0]
			version = strings.TrimSpace(version)
		}
		purl := fmt.Sprintf("pkg:pypi/%s", strings.ToLower(name))
		if version != "" {
			purl += "@" + version
		}
		deps = append(deps, map[string]string{"name": name, "version": version, "purl": purl, "type": "pypi"})
	}
	return deps
}

func parsePackageJSON(content string) []map[string]string {
	var data map[string]any
	if err := json.Unmarshal([]byte(content), &data); err != nil {
		return nil
	}

	var deps []map[string]string
	for _, field := range []string{"dependencies", "devDependencies"} {
		if depMap, ok := data[field].(map[string]any); ok {
			for name, ver := range depMap {
				version := ""
				if s, ok := ver.(string); ok {
					version = strings.TrimLeft(s, "^~>=<")
				}
				purl := fmt.Sprintf("pkg:npm/%s", name)
				if version != "" {
					purl += "@" + version
				}
				deps = append(deps, map[string]string{"name": name, "version": version, "purl": purl, "type": "npm"})
			}
		}
	}
	return deps
}

func parsePyprojectTOML(content string) []map[string]string {
	// Simple regex-based extraction for pyproject.toml dependencies
	var deps []map[string]string
	re := regexp.MustCompile(`"([A-Za-z0-9_.-]+)(?:\[.*?\])?(?:[><=~!]+.*?)?"`)
	// Look for dependencies section
	inDeps := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "dependencies") && strings.Contains(trimmed, "=") {
			inDeps = true
			continue
		}
		if inDeps {
			if trimmed == "]" {
				inDeps = false
				continue
			}
			matches := re.FindStringSubmatch(trimmed)
			if matches != nil {
				name := matches[1]
				purl := fmt.Sprintf("pkg:pypi/%s", strings.ToLower(name))
				deps = append(deps, map[string]string{"name": name, "version": "", "purl": purl, "type": "pypi"})
			}
		}
	}
	return deps
}

func extractSkillMetadata(files []core.SkillFile) map[string]string {
	metadata := map[string]string{}
	for _, f := range files {
		if f.Content == nil || f.FileType != core.FileTypeSkillMD {
			continue
		}
		fm, _ := core.ParseFrontmatter(*f.Content)
		if name, ok := fm["name"].(string); ok {
			metadata["name"] = name
		}
		if ver, ok := fm["version"].(string); ok {
			metadata["version"] = ver
		}
		if desc, ok := fm["description"].(string); ok {
			metadata["description"] = desc
		}
	}
	return metadata
}

func detectLicense(files []core.SkillFile) string {
	for _, f := range files {
		name := strings.ToLower(filepath.Base(f.Path))
		if !strings.HasPrefix(name, "license") {
			continue
		}
		if f.Content == nil {
			continue
		}
		content := strings.ToLower(*f.Content)
		switch {
		case strings.Contains(content, "mit license"):
			return "MIT"
		case strings.Contains(content, "apache license"):
			return "Apache-2.0"
		case strings.Contains(content, "gnu general public license"):
			return "GPL-3.0"
		case strings.Contains(content, "bsd"):
			return "BSD-3-Clause"
		case strings.Contains(content, "isc license"):
			return "ISC"
		}
	}
	return ""
}

func extractExternalRefs(files []core.SkillFile) []map[string]string {
	var refs []map[string]string
	urlRE := regexp.MustCompile(`https?://[^\s"'<>]+`)
	seen := make(map[string]bool)

	for _, f := range files {
		if f.Content == nil {
			continue
		}
		matches := urlRE.FindAllString(*f.Content, -1)
		for _, url := range matches {
			if seen[url] {
				continue
			}
			seen[url] = true
			refType := "website"
			if strings.Contains(url, "github.com") {
				refType = "vcs"
			} else if strings.Contains(url, "docs.") || strings.Contains(url, "documentation") {
				refType = "documentation"
			}
			refs = append(refs, map[string]string{"type": refType, "url": url})
		}
	}
	return refs
}

func buildVulnerabilities(result *core.ScanResult, skillRef string) []map[string]any {
	var vulns []map[string]any
	seen := make(map[string]bool)

	for _, er := range result.EngineResults {
		for _, f := range er.Findings {
			if seen[f.RuleID] {
				continue
			}
			seen[f.RuleID] = true

			vuln := map[string]any{
				"id":          f.RuleID,
				"description": f.Description,
				"source":      map[string]string{"name": er.EngineName},
				"ratings": []map[string]any{
					{"severity": string(f.Severity), "method": "other"},
				},
				"affects": []map[string]any{
					{"ref": skillRef},
				},
			}
			if f.CWE != nil {
				vuln["cwes"] = []string{*f.CWE}
			}
			vulns = append(vulns, vuln)
		}
	}
	return vulns
}

// GenerateAIBOM generates a CycloneDX AI-BOM from scan results.
func GenerateAIBOM(result *core.ScanResult) map[string]any {
	skillRef := fmt.Sprintf("skill:%s", result.SkillName)

	components := []map[string]any{
		{
			"type":    "application",
			"name":    result.SkillName,
			"bom-ref": skillRef,
			"hashes":  []map[string]string{{"alg": "SHA-256", "content": result.SkillSHA256}},
			"properties": []map[string]string{
				{"name": "skillguard:platform", "value": string(result.Platform)},
				{"name": "skillguard:composite_score", "value": fmt.Sprintf("%d", result.CompositeScore)},
				{"name": "skillguard:verdict", "value": string(result.Verdict)},
				{"name": "skillguard:files_scanned", "value": fmt.Sprintf("%d", result.FilesScanned)},
			},
		},
	}

	bom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]any{
			"timestamp": result.ScanCompleted.Format(time.RFC3339),
			"tools": []map[string]string{
				{"name": "SkillGuard", "version": "0.3.0"},
			},
		},
		"components": components,
	}

	vulns := buildVulnerabilities(result, skillRef)
	if len(vulns) > 0 {
		bom["vulnerabilities"] = vulns
	}

	return bom
}

// GenerateAIBOMJSON generates AI-BOM as JSON.
func GenerateAIBOMJSON(result *core.ScanResult) (string, error) {
	bom := GenerateAIBOM(result)
	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Ensure we use os for file operations
var _ = os.Stat
