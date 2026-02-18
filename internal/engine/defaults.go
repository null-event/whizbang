package engine

func NewDefaultAuditRegistry() *Registry {
	reg := NewRegistry()
	// Probes will be registered here as they're implemented
	return reg
}

func NewDefaultScanRegistry() *Registry {
	reg := NewRegistry()
	return reg
}

func NewDefaultAttackRegistry() *Registry {
	reg := NewRegistry()
	return reg
}
