package engine

import (
	"github.com/nullevent/whizbang/internal/probe/cred"
	"github.com/nullevent/whizbang/internal/probe/mcp"
)

func NewDefaultAuditRegistry() *Registry {
	reg := NewRegistry()
	reg.Register(cred.New001())
	reg.Register(mcp.New001())
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
