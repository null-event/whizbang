package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	rollbackLatest bool
	rollbackList   bool
)

var rollbackCmd = &cobra.Command{
	Use:   "rollback [path]",
	Short: "Undo auto-fix changes from backups",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runRollback,
}

func init() {
	rollbackCmd.Flags().BoolVar(&rollbackLatest, "latest", false, "restore most recent backup without prompting")
	rollbackCmd.Flags().BoolVar(&rollbackList, "list", false, "list available backups")

	rootCmd.AddCommand(rollbackCmd)
}

func runRollback(cmd *cobra.Command, args []string) error {
	fmt.Println("Rollback not yet implemented — backup system coming soon.")
	return nil
}
