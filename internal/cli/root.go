package cli

import (
	"github.com/spf13/cobra"
)

var (
	appVersion = "dev"
	appCommit  = "none"

	cfgFile string
)

func SetVersion(version, commit string) {
	appVersion = version
	appCommit = commit
}

var rootCmd = &cobra.Command{
	Use:   "whizbang",
	Short: "AI Agent Security Scanner",
	Long:  "whizbang scans, audits, and red-teams AI agent setups with a focus on MCP ecosystems.",
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: whizbang.yaml)")
}

func Execute() error {
	return rootCmd.Execute()
}
