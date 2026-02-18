package output

import (
	"encoding/json"
	"io"

	"github.com/null-event/whizbang/internal/probe"
)

type JSONFormatter struct{}

func (f *JSONFormatter) Format(w io.Writer, report *probe.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
