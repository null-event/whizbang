package engine

import (
	"github.com/nullevent/whizbang/internal/probe/cred"
)

func NewDefaultAuditRegistry() *Registry {
	reg := NewRegistry()
	reg.Register(cred.New001())
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
