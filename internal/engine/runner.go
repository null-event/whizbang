package engine

import (
	"context"
	"sync"

	"github.com/nullevent/whizbang/internal/probe"
)

type Runner struct {
	workers int
}

func NewRunner(workers int) *Runner {
	if workers < 1 {
		workers = 1
	}
	return &Runner{workers: workers}
}

func (r *Runner) Run(ctx context.Context, probes []probe.Probe, target *probe.Target, version string) *probe.Report {
	type result struct {
		findings []probe.Finding
		err      error
	}

	results := make(chan result, len(probes))
	sem := make(chan struct{}, r.workers)
	var wg sync.WaitGroup

	for _, p := range probes {
		wg.Add(1)
		go func(p probe.Probe) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results <- result{err: ctx.Err()}
				return
			}

			findings, err := p.Scan(ctx, target)
			results <- result{findings: findings, err: err}
		}(p)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var allFindings []probe.Finding
	for res := range results {
		if res.err != nil {
			continue
		}
		allFindings = append(allFindings, res.findings...)
	}

	return probe.NewReport(version, *target, allFindings)
}
