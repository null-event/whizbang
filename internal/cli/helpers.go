package cli

import (
	"github.com/null-event/whizbang/internal/engine"
	"github.com/null-event/whizbang/internal/probe"
)

func selectProbes(reg *engine.Registry, categories []string, ids []string, exclude []string) []probe.Probe {
	if len(ids) > 0 {
		return reg.ByIDs(ids)
	}

	var probes []probe.Probe
	if len(categories) > 0 {
		for _, cat := range categories {
			probes = append(probes, reg.ByCategory(probe.Category(cat))...)
		}
	} else {
		probes = reg.All()
	}

	if len(exclude) > 0 {
		excludeMap := make(map[string]bool)
		for _, id := range exclude {
			excludeMap[id] = true
		}
		var filtered []probe.Probe
		for _, p := range probes {
			if !excludeMap[p.Info().ID] {
				filtered = append(filtered, p)
			}
		}
		probes = filtered
	}

	return probes
}

func filterBySeverity(report *probe.Report, minSev probe.Severity) *probe.Report {
	var filtered []probe.Finding
	for _, f := range report.Findings {
		if f.Severity.AtLeast(minSev) {
			filtered = append(filtered, f)
		}
	}
	return probe.NewReport(report.Version, report.Target, filtered)
}
