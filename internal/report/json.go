package report

import (
	"encoding/json"
	"io"
)

// JSONReporter outputs findings as JSON.
type JSONReporter struct{}

func (r *JSONReporter) Generate(w io.Writer, summary Summary) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}
