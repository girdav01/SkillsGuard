package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyFile(t *testing.T) {
	tests := []struct {
		name string
		want FileType
	}{
		{"SKILL.md", FileTypeSkillMD},
		{"readme.md", FileTypeSkillMD},
		{"script.py", FileTypeScriptPython},
		{"run.sh", FileTypeScriptBash},
		{"app.js", FileTypeScriptJS},
		{"index.ts", FileTypeScriptTS},
		{"config.json", FileTypeConfig},
		{"config.yaml", FileTypeConfig},
		{"template.j2", FileTypeTemplate},
		{"random.xyz", FileTypeOther},
	}
	for _, tt := range tests {
		got := ClassifyFile(tt.name)
		if got != tt.want {
			t.Errorf("ClassifyFile(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestParseFrontmatter(t *testing.T) {
	content := `---
name: test-skill
version: "1.0"
---
# Body text here`

	fm, body := ParseFrontmatter(content)
	if fm["name"] != "test-skill" {
		t.Errorf("frontmatter name = %v, want test-skill", fm["name"])
	}
	if fm["version"] != "1.0" {
		t.Errorf("frontmatter version = %v, want 1.0", fm["version"])
	}
	if body != "# Body text here" {
		t.Errorf("body = %q, want '# Body text here'", body)
	}
}

func TestParseFrontmatterMissing(t *testing.T) {
	content := "# No frontmatter here"
	fm, body := ParseFrontmatter(content)
	if len(fm) != 0 {
		t.Error("Expected empty frontmatter")
	}
	if body != content {
		t.Errorf("body should be original content")
	}
}

func TestParseSkillDirectory(t *testing.T) {
	dir := t.TempDir()

	// Create test files
	os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: test\n---\n# Test"), 0644)
	os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('hello')"), 0644)
	os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0644)

	// Create a directory that should be skipped
	os.MkdirAll(filepath.Join(dir, ".git", "objects"), 0755)
	os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main"), 0644)

	files, err := ParseSkillDirectory(dir)
	if err != nil {
		t.Fatalf("ParseSkillDirectory error: %v", err)
	}

	if len(files) != 3 {
		t.Errorf("Got %d files, want 3", len(files))
	}

	// Check file types
	typeMap := make(map[string]FileType)
	for _, f := range files {
		typeMap[f.Path] = f.FileType
	}

	if typeMap["SKILL.md"] != FileTypeSkillMD {
		t.Error("SKILL.md should be FileTypeSkillMD")
	}
	if typeMap["main.py"] != FileTypeScriptPython {
		t.Error("main.py should be FileTypeScriptPython")
	}
	if typeMap["config.json"] != FileTypeConfig {
		t.Error("config.json should be FileTypeConfig")
	}

	// Ensure .git was skipped
	for _, f := range files {
		if filepath.Base(f.Path) == "HEAD" {
			t.Error(".git directory should have been skipped")
		}
	}
}

func TestParseSkillDirectorySingleFile(t *testing.T) {
	dir := t.TempDir()
	fpath := filepath.Join(dir, "test.py")
	os.WriteFile(fpath, []byte("x = 1"), 0644)

	files, err := ParseSkillDirectory(fpath)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("Got %d files, want 1", len(files))
	}
}

func TestParseSkillDirectoryNotExists(t *testing.T) {
	_, err := ParseSkillDirectory("/nonexistent/path")
	if err == nil {
		t.Error("Expected error for nonexistent path")
	}
}
