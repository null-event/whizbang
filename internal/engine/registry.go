package engine

import "github.com/null-event/whizbang/internal/probe"

type Registry struct {
	probes []probe.Probe
	byID   map[string]probe.Probe
}

func NewRegistry() *Registry {
	return &Registry{
		byID: make(map[string]probe.Probe),
	}
}

func (r *Registry) Register(p probe.Probe) {
	r.probes = append(r.probes, p)
	r.byID[p.Info().ID] = p
}

func (r *Registry) All() []probe.Probe {
	return r.probes
}

func (r *Registry) ByCategory(cat probe.Category) []probe.Probe {
	var result []probe.Probe
	for _, p := range r.probes {
		if p.Info().Category == cat {
			result = append(result, p)
		}
	}
	return result
}

func (r *Registry) ByID(id string) probe.Probe {
	return r.byID[id]
}

func (r *Registry) ByIDs(ids []string) []probe.Probe {
	var result []probe.Probe
	for _, id := range ids {
		if p, ok := r.byID[id]; ok {
			result = append(result, p)
		}
	}
	return result
}

func (r *Registry) Exclude(ids []string) []probe.Probe {
	exclude := make(map[string]bool, len(ids))
	for _, id := range ids {
		exclude[id] = true
	}
	var result []probe.Probe
	for _, p := range r.probes {
		if !exclude[p.Info().ID] {
			result = append(result, p)
		}
	}
	return result
}
