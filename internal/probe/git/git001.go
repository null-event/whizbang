package git

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/nullevent/whizbang/internal/probe"
)

var requiredPatterns = []string{
	".env",
	".claude/",
}

type probe001 struct{}

func New001() probe.Probe {
	return &probe001{}
}

func (p *probe001) Info() probe.ProbeInfo {
	return probe.ProbeInfo{
		ID:          "GIT-001",
		Name:        "Missing .gitignore Secret Patterns",
		Category:    probe.CategoryGit,
		Severity:    probe.SeverityMedium,
		Description: "Detects missing .gitignore patterns for secrets and sensitive directories",
		Tags:        []string{"general"},
	}
}

func (p *probe001) Scan(ctx context.Context, target *probe.Target) ([]probe.Finding, error) {
	gitignorePath := filepath.Join(target.Path, ".gitignore")

	f, err := os.Open(gitignorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []probe.Finding{{
				ProbeID:     "GIT-001",
				ProbeName:   "Missing .gitignore",
				Category:    probe.CategoryGit,
				Severity:    probe.SeverityMedium,
				Description: "No .gitignore file found — secrets may be committed",
				Location:    probe.Location{File: ".gitignore"},
				Fixable:     true,
				Remediation: "Create .gitignore with patterns for .env, .claude/, and other sensitive files",
			}}, nil
		}
		return nil, err
	}
	defer f.Close()

	existing := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		existing[line] = true
		if strings.HasSuffix(line, "*") {
			existing[strings.TrimSuffix(line, "*")] = true
		}
	}

	var missing []string
	for _, pattern := range requiredPatterns {
		found := false
		if existing[pattern] {
			found = true
		}
		for k := range existing {
			if strings.Contains(k, strings.TrimSuffix(pattern, "/")) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, pattern)
		}
	}

	if len(missing) == 0 {
		return nil, nil
	}

	return []probe.Finding{{
		ProbeID:     "GIT-001",
		ProbeName:   "Missing .gitignore Secret Patterns",
		Category:    probe.CategoryGit,
		Severity:    probe.SeverityMedium,
		Description: "Missing .gitignore patterns: " + strings.Join(missing, ", "),
		Location:    probe.Location{File: ".gitignore"},
		Fixable:     true,
		Remediation: "Add missing patterns to .gitignore: " + strings.Join(missing, ", "),
	}}, nil
}

func (p *probe001) Fix(ctx context.Context, finding probe.Finding) (*probe.FixResult, error) {
	return nil, nil
}

func (p *probe001) CanFix() bool {
	return true
}
