package core

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxFileSize = 10 * 1024 * 1024 // 10 MB

var frontmatterRE = regexp.MustCompile(`(?s)^---\s*\n(.*?)\n---\s*\n`)

// Extension to FileType mapping.
var extMap = map[string]FileType{
	".py":    FileTypeScriptPython,
	".sh":    FileTypeScriptBash,
	".bash":  FileTypeScriptBash,
	".js":    FileTypeScriptJS,
	".mjs":   FileTypeScriptJS,
	".ts":    FileTypeScriptTS,
	".mts":   FileTypeScriptTS,
	".json":  FileTypeConfig,
	".yaml":  FileTypeConfig,
	".yml":   FileTypeConfig,
	".toml":  FileTypeConfig,
	".ini":   FileTypeConfig,
	".cfg":   FileTypeConfig,
	".j2":    FileTypeTemplate,
	".jinja": FileTypeTemplate,
	".jinja2": FileTypeTemplate,
	".tmpl":  FileTypeTemplate,
	".hbs":   FileTypeTemplate,
}

var skillMDNames = map[string]bool{
	"skill.md":        true,
	"readme.md":       true,
	"instructions.md": true,
	"prompt.md":       true,
	"system.md":       true,
}

var skipDirs = map[string]bool{
	".git":          true,
	"__pycache__":   true,
	"node_modules":  true,
	".venv":         true,
	"venv":          true,
}

// ClassifyFile determines the FileType for a given filename.
func ClassifyFile(name string) FileType {
	lower := strings.ToLower(filepath.Base(name))
	if skillMDNames[lower] {
		return FileTypeSkillMD
	}
	ext := strings.ToLower(filepath.Ext(name))
	if ft, ok := extMap[ext]; ok {
		return ft
	}
	return FileTypeOther
}

// ParseFrontmatter extracts YAML frontmatter and body from markdown content.
func ParseFrontmatter(content string) (map[string]any, string) {
	match := frontmatterRE.FindStringSubmatchIndex(content)
	if match == nil {
		return map[string]any{}, content
	}

	rawYAML := content[match[2]:match[3]]
	body := content[match[1]:]

	var fm map[string]any
	if err := yaml.Unmarshal([]byte(rawYAML), &fm); err != nil {
		return map[string]any{}, content
	}
	if fm == nil {
		return map[string]any{}, content
	}
	return fm, body
}

// ParseSkillDirectory parses a skill directory and returns all files with metadata.
func ParseSkillDirectory(skillPath string) ([]SkillFile, error) {
	info, err := os.Stat(skillPath)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		sf, err := parseSingleFile(skillPath, filepath.Dir(skillPath))
		if err != nil {
			return nil, err
		}
		if sf == nil {
			return []SkillFile{}, nil
		}
		return []SkillFile{*sf}, nil
	}

	var files []SkillFile
	err = filepath.Walk(skillPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		// Check if any parent is in skipDirs
		rel, _ := filepath.Rel(skillPath, path)
		parts := strings.Split(rel, string(filepath.Separator))
		for _, p := range parts[:len(parts)-1] {
			if skipDirs[p] {
				return nil
			}
		}

		sf, err := parseSingleFile(path, skillPath)
		if err == nil && sf != nil {
			files = append(files, *sf)
		}
		return nil
	})

	return files, err
}

func parseSingleFile(filePath, basePath string) (*SkillFile, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	size := info.Size()
	rel, _ := filepath.Rel(basePath, filePath)
	// Normalize to forward slashes for cross-platform consistency
	rel = filepath.ToSlash(rel)

	fileType := ClassifyFile(filePath)

	if size > maxFileSize {
		hash, err := HashFile(filePath)
		if err != nil {
			return nil, err
		}
		return &SkillFile{
			Path:      rel,
			FileType:  fileType,
			SHA256:    hash,
			SizeBytes: size,
			Content:   nil,
		}, nil
	}

	// Try reading as text
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	content := string(data)
	hash := HashContent(content)

	return &SkillFile{
		Path:      rel,
		FileType:  fileType,
		SHA256:    hash,
		SizeBytes: size,
		Content:   &content,
	}, nil
}
