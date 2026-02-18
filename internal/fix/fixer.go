package fix

import (
	"context"
	"fmt"

	"github.com/null-event/whizbang/internal/engine"
	"github.com/null-event/whizbang/internal/probe"
)

type Fixer struct{}

func NewFixer() *Fixer {
	return &Fixer{}
}

func (f *Fixer) ApplyAll(ctx context.Context, reg *engine.Registry, findings []probe.Finding) ([]*probe.FixResult, error) {
	var results []*probe.FixResult

	for _, finding := range findings {
		p := reg.ByID(finding.ProbeID)
		if p == nil || !p.CanFix() {
			continue
		}

		result, err := p.Fix(ctx, finding)
		if err != nil {
			return results, fmt.Errorf("fixing %s: %w", finding.ProbeID, err)
		}
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}
