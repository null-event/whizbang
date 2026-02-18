package output

import (
	"fmt"
	"io"

	"github.com/nullevent/whizbang/internal/probe"
)

type Formatter interface {
	Format(w io.Writer, report *probe.Report) error
}

func NewFormatter(name string, noColor bool, verbose bool) (Formatter, error) {
	switch name {
	case "text":
		return &TextFormatter{NoColor: noColor, Verbose: verbose}, nil
	case "json":
		return &JSONFormatter{}, nil
	case "sarif":
		return &SARIFFormatter{}, nil
	default:
		return nil, fmt.Errorf("unknown format: %q (available: text, json, sarif)", name)
	}
}
