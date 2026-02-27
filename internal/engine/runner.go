package engine

import (
	"context"
	"sync"

	"github.com/null-event/whizbang/internal/probe"
)

// ProbeStatus indicates the outcome of a probe execution.
type ProbeStatus int

const (
	ProbeStatusStart ProbeStatus = iota
	ProbeStatusPass
	ProbeStatusFail
	ProbeStatusError
)

// ProbeEventFunc is called by the runner to report probe execution progress.
type ProbeEventFunc func(info probe.ProbeInfo, status ProbeStatus, err error)

type Runner struct {
	workers int
	OnProbe ProbeEventFunc
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

			info := p.Info()
			if r.OnProbe != nil {
				r.OnProbe(info, ProbeStatusStart, nil)
			}

			findings, err := p.Scan(ctx, target)

			if r.OnProbe != nil {
				switch {
				case err != nil:
					r.OnProbe(info, ProbeStatusError, err)
				case len(findings) > 0:
					r.OnProbe(info, ProbeStatusFail, nil)
				default:
					r.OnProbe(info, ProbeStatusPass, nil)
				}
			}

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
