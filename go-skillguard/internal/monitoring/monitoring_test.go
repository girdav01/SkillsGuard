package monitoring

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDriftDetectorNoBaseline(t *testing.T) {
	d := NewDriftDetector()
	result := d.CheckDrift("/tmp")
	if result.HasDrift {
		t.Error("No baseline should mean no drift")
	}
}

func TestDriftDetectorNoDrift(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "file1.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(dir, "file2.txt"), []byte("world"), 0644)

	d := NewDriftDetector()
	if err := d.CaptureBaseline(dir); err != nil {
		t.Fatalf("CaptureBaseline error: %v", err)
	}

	result := d.CheckDrift(dir)
	if result.HasDrift {
		t.Error("No changes should mean no drift")
	}
}

func TestDriftDetectorModified(t *testing.T) {
	dir := t.TempDir()
	fpath := filepath.Join(dir, "file1.txt")
	os.WriteFile(fpath, []byte("hello"), 0644)

	d := NewDriftDetector()
	d.CaptureBaseline(dir)

	// Modify file
	os.WriteFile(fpath, []byte("modified"), 0644)

	result := d.CheckDrift(dir)
	if !result.HasDrift {
		t.Error("Modified file should cause drift")
	}
	if len(result.ModifiedFiles) != 1 {
		t.Errorf("Modified files = %d, want 1", len(result.ModifiedFiles))
	}
}

func TestDriftDetectorAdded(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "file1.txt"), []byte("hello"), 0644)

	d := NewDriftDetector()
	d.CaptureBaseline(dir)

	// Add new file
	os.WriteFile(filepath.Join(dir, "new_file.txt"), []byte("new"), 0644)

	result := d.CheckDrift(dir)
	if !result.HasDrift {
		t.Error("Added file should cause drift")
	}
	if len(result.AddedFiles) != 1 {
		t.Errorf("Added files = %d, want 1", len(result.AddedFiles))
	}
}

func TestDriftDetectorRemoved(t *testing.T) {
	dir := t.TempDir()
	fpath := filepath.Join(dir, "file1.txt")
	os.WriteFile(fpath, []byte("hello"), 0644)

	d := NewDriftDetector()
	d.CaptureBaseline(dir)

	// Remove file
	os.Remove(fpath)

	result := d.CheckDrift(dir)
	if !result.HasDrift {
		t.Error("Removed file should cause drift")
	}
	if len(result.RemovedFiles) != 1 {
		t.Errorf("Removed files = %d, want 1", len(result.RemovedFiles))
	}
}
