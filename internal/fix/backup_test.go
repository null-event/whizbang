package fix

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackupAndRestore(t *testing.T) {
	dir := t.TempDir()

	testFile := filepath.Join(dir, "test.json")
	os.WriteFile(testFile, []byte(`{"original": true}`), 0644)

	bm := NewBackupManager(dir)
	backup, err := bm.Create([]string{testFile})
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	if len(backup.Files) != 1 {
		t.Fatalf("expected 1 backed up file, got %d", len(backup.Files))
	}

	os.WriteFile(testFile, []byte(`{"modified": true}`), 0644)

	if err := backup.Restore(); err != nil {
		t.Fatalf("restore failed: %v", err)
	}

	data, _ := os.ReadFile(testFile)
	if string(data) != `{"original": true}` {
		t.Errorf("expected original content, got %s", string(data))
	}
}

func TestListBackups(t *testing.T) {
	dir := t.TempDir()

	testFile := filepath.Join(dir, "test.json")
	os.WriteFile(testFile, []byte(`{}`), 0644)

	bm := NewBackupManager(dir)
	bm.Create([]string{testFile})

	// Small delay to get different timestamps
	testFile2 := filepath.Join(dir, "test2.json")
	os.WriteFile(testFile2, []byte(`{}`), 0644)
	bm.Create([]string{testFile2})

	backups, err := ListBackups(dir)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(backups) < 1 {
		t.Errorf("expected at least 1 backup, got %d", len(backups))
	}
}

func TestListBackupsEmpty(t *testing.T) {
	dir := t.TempDir()

	backups, err := ListBackups(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(backups) != 0 {
		t.Errorf("expected 0 backups, got %d", len(backups))
	}
}
