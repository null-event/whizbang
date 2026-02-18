package probe

type Category string

const (
	CategoryCredential  Category = "credential"
	CategoryMCP         Category = "mcp"
	CategoryPermission  Category = "permission"
	CategorySupplyChain Category = "supply-chain"
	CategoryGit         Category = "git"
	CategoryToolChain   Category = "tool-chain"
	CategoryClaudeCode  Category = "claude-code"
	CategoryConfig      Category = "config"
	CategoryScanMCP     Category = "scan-mcp"
	CategoryScanConfig  Category = "scan-config"
	CategoryScanKey     Category = "scan-key"
	CategoryScanNet     Category = "scan-net"
	CategoryAttackPI    Category = "prompt-injection"
	CategoryAttackExfil Category = "data-exfil"
	CategoryAttackTool  Category = "tool-abuse"
	CategoryAttackMem   Category = "memory-poison"
	CategoryAttackLeak  Category = "config-leak"
)
