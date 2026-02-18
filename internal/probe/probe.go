package probe

import "context"

type Probe interface {
	Info() ProbeInfo
	Scan(ctx context.Context, target *Target) ([]Finding, error)
	Fix(ctx context.Context, finding Finding) (*FixResult, error)
	CanFix() bool
}

type ProbeInfo struct {
	ID          string
	Name        string
	Category    Category
	Severity    Severity
	Description string
	Tags        []string
}

type FixResult struct {
	Finding      Finding
	FilesChanged []string
	Description  string
}
