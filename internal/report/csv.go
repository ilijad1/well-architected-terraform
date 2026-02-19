package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"
)

// CSVReporter outputs findings as CSV.
type CSVReporter struct{}

func (r *CSVReporter) Generate(w io.Writer, summary Summary) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	header := []string{
		"RuleID", "RuleName", "Severity", "Pillar",
		"Resource", "File", "Line",
		"Description", "Remediation", "DocURL",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, f := range summary.Findings {
		row := []string{
			f.RuleID,
			f.RuleName,
			string(f.Severity),
			string(f.Pillar),
			f.Resource,
			f.File,
			fmt.Sprintf("%d", f.Line),
			f.Description,
			f.Remediation,
			f.DocURL,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// formatComplianceFrameworks serializes a map to "CIS:2.1.1;PCI:10.5.2" format.
func formatComplianceFrameworks(frameworks map[string][]string) string {
	if len(frameworks) == 0 {
		return ""
	}

	var keys []string
	for k := range frameworks {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		for _, v := range frameworks[k] {
			parts = append(parts, k+":"+v)
		}
	}
	return strings.Join(parts, ";")
}
