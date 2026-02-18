package engine

import (
	"github.com/null-event/whizbang/internal/probe/attack"
	"github.com/null-event/whizbang/internal/probe/cred"
	"github.com/null-event/whizbang/internal/probe/git"
	"github.com/null-event/whizbang/internal/probe/mcp"
	"github.com/null-event/whizbang/internal/probe/perm"
	"github.com/null-event/whizbang/internal/probe/scan"
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
	// Prompt Injection (ATK-PI-001..010)
	reg.Register(attack.NewPI001())
	reg.Register(attack.NewPI002())
	reg.Register(attack.NewPI003())
	reg.Register(attack.NewPI004())
	reg.Register(attack.NewPI005())
	reg.Register(attack.NewPI006())
	reg.Register(attack.NewPI007())
	reg.Register(attack.NewPI008())
	reg.Register(attack.NewPI009())
	reg.Register(attack.NewPI010())
	// Data Exfiltration (ATK-EX-001..008)
	reg.Register(attack.NewEX001())
	reg.Register(attack.NewEX002())
	reg.Register(attack.NewEX003())
	reg.Register(attack.NewEX004())
	reg.Register(attack.NewEX005())
	reg.Register(attack.NewEX006())
	reg.Register(attack.NewEX007())
	reg.Register(attack.NewEX008())
	// Tool Abuse (ATK-TA-001..008)
	reg.Register(attack.NewTA001())
	reg.Register(attack.NewTA002())
	reg.Register(attack.NewTA003())
	reg.Register(attack.NewTA004())
	reg.Register(attack.NewTA005())
	reg.Register(attack.NewTA006())
	reg.Register(attack.NewTA007())
	reg.Register(attack.NewTA008())
	// Memory Poisoning (ATK-MP-001..006)
	reg.Register(attack.NewMP001())
	reg.Register(attack.NewMP002())
	reg.Register(attack.NewMP003())
	reg.Register(attack.NewMP004())
	reg.Register(attack.NewMP005())
	reg.Register(attack.NewMP006())
	// Config Leak (ATK-CL-001..004)
	reg.Register(attack.NewCL001())
	reg.Register(attack.NewCL002())
	reg.Register(attack.NewCL003())
	reg.Register(attack.NewCL004())
	return reg
}
