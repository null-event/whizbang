package engine

import (
	"github.com/nullevent/whizbang/internal/probe/cred"
	"github.com/nullevent/whizbang/internal/probe/git"
	"github.com/nullevent/whizbang/internal/probe/mcp"
	"github.com/nullevent/whizbang/internal/probe/perm"
	"github.com/nullevent/whizbang/internal/probe/scan"
)

func NewDefaultAuditRegistry() *Registry {
	reg := NewRegistry()
	reg.Register(cred.New001())
	reg.Register(mcp.New001())
	reg.Register(perm.New001())
	reg.Register(git.New001())
	return reg
}

func NewDefaultScanRegistry() *Registry {
	reg := NewRegistry()
	reg.Register(scan.NewMCP001())
	reg.Register(scan.NewMCP002())
	reg.Register(scan.NewMCP003())
	reg.Register(scan.NewCFG001())
	reg.Register(scan.NewCFG002())
	reg.Register(scan.NewKEY001())
	reg.Register(scan.NewKEY002())
	reg.Register(scan.NewNET001())
	reg.Register(scan.NewNET002())
	return reg
}

func NewDefaultAttackRegistry() *Registry {
	reg := NewRegistry()
	return reg
}
