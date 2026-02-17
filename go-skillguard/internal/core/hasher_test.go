package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashContent(t *testing.T) {
	hash := HashContent("hello world")
	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hash != expected {
		t.Errorf("HashContent = %q, want %q", hash, expected)
	}
}

func TestHashContentEmpty(t *testing.T) {
	hash := HashContent("")
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hash != expected {
		t.Errorf("HashContent empty = %q, want %q", hash, expected)
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	fpath := filepath.Join(dir, "test.txt")
	os.WriteFile(fpath, []byte("hello world"), 0644)

	hash, err := HashFile(fpath)
	if err != nil {
		t.Fatalf("HashFile error: %v", err)
	}
	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hash != expected {
		t.Errorf("HashFile = %q, want %q", hash, expected)
	}
}

func TestHashSkill(t *testing.T) {
	files := []FileHash{
		{Path: "b.txt", SHA256: "hash_b"},
		{Path: "a.txt", SHA256: "hash_a"},
	}
	hash1 := HashSkill(files)

	// Same files in different order should produce same hash
	files2 := []FileHash{
		{Path: "a.txt", SHA256: "hash_a"},
		{Path: "b.txt", SHA256: "hash_b"},
	}
	hash2 := HashSkill(files2)

	if hash1 != hash2 {
		t.Errorf("HashSkill should be order-independent: %q != %q", hash1, hash2)
	}

	// Different files should produce different hash
	files3 := []FileHash{
		{Path: "a.txt", SHA256: "hash_c"},
	}
	hash3 := HashSkill(files3)
	if hash1 == hash3 {
		t.Error("Different files should produce different hash")
	}
}
