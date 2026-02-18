package main

import (
	"os"

	"github.com/nullevent/whizbang/internal/cli"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	cli.SetVersion(version, commit)
	if err := cli.Execute(); err != nil {
		os.Exit(2)
	}
}
