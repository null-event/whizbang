package fix

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const backupDirName = ".whizbang-backup"

type BackupManager struct {
	basePath string
}

type Backup struct {
	Dir       string
	Timestamp string
	Files     []BackupFile
}

type BackupFile struct {
	OriginalPath string `json:"original_path"`
	BackupPath   string `json:"backup_path"`
	ProbeID      string `json:"probe_id,omitempty"`
}

type manifest struct {
	Timestamp string       `json:"timestamp"`
	Files     []BackupFile `json:"files"`
}

func NewBackupManager(basePath string) *BackupManager {
	return &BackupManager{basePath: basePath}
}

func (bm *BackupManager) Create(filePaths []string) (*Backup, error) {
	ts := time.Now().Format("20060102T150405")
	backupDir := filepath.Join(bm.basePath, backupDirName, ts)

	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return nil, fmt.Errorf("creating backup dir: %w", err)
	}

	backup := &Backup{
		Dir:       backupDir,
		Timestamp: ts,
	}

	for _, fp := range filePaths {
		data, err := os.ReadFile(fp)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", fp, err)
		}

		backupName := filepath.Base(fp) + ".bak"
		backupPath := filepath.Join(backupDir, backupName)
		if err := os.WriteFile(backupPath, data, 0600); err != nil {
			return nil, fmt.Errorf("writing backup %s: %w", backupPath, err)
		}

		backup.Files = append(backup.Files, BackupFile{
			OriginalPath: fp,
			BackupPath:   backupPath,
		})
	}

	m := manifest{Timestamp: ts, Files: backup.Files}
	mdata, _ := json.MarshalIndent(m, "", "  ")
	os.WriteFile(filepath.Join(backupDir, "manifest.json"), mdata, 0600)

	return backup, nil
}

func (b *Backup) Restore() error {
	for _, f := range b.Files {
		data, err := os.ReadFile(f.BackupPath)
		if err != nil {
			return fmt.Errorf("reading backup %s: %w", f.BackupPath, err)
		}
		if err := os.WriteFile(f.OriginalPath, data, 0644); err != nil {
			return fmt.Errorf("restoring %s: %w", f.OriginalPath, err)
		}
	}
	return nil
}

func ListBackups(basePath string) ([]Backup, error) {
	backupRoot := filepath.Join(basePath, backupDirName)
	entries, err := os.ReadDir(backupRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var backups []Backup
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		mpath := filepath.Join(backupRoot, e.Name(), "manifest.json")
		data, err := os.ReadFile(mpath)
		if err != nil {
			continue
		}
		var m manifest
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		backups = append(backups, Backup{
			Dir:       filepath.Join(backupRoot, e.Name()),
			Timestamp: m.Timestamp,
			Files:     m.Files,
		})
	}

	sort.Slice(backups, func(i, j int) bool {
		return backups[i].Timestamp > backups[j].Timestamp
	})

	return backups, nil
}
