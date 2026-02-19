package report

import (
	"encoding/xml"
	"fmt"
	"io"
)

// JUnit XML output structs.

type junitTestSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Suites   []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Cases    []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

// JUnitReporter outputs findings as JUnit XML.
type JUnitReporter struct{}

func (r *JUnitReporter) Generate(w io.Writer, summary Summary) error {
	// Group findings by resource type
	byType := make(map[string][]int) // resource type -> indices into summary.Findings
	for i, f := range summary.Findings {
		// Extract resource type from the resource address (e.g. "aws_s3_bucket.foo" -> "aws_s3_bucket")
		rt := resourceTypeFromAddress(f.Resource)
		byType[rt] = append(byType[rt], i)
	}

	var suites []junitTestSuite
	totalTests := 0
	totalFailures := 0

	for rt, indices := range byType {
		suite := junitTestSuite{
			Name:     rt,
			Tests:    len(indices),
			Failures: len(indices),
		}
		for _, idx := range indices {
			f := summary.Findings[idx]
			tc := junitTestCase{
				Name:      fmt.Sprintf("[%s] %s", f.RuleID, f.RuleName),
				ClassName: f.Resource,
				Failure: &junitFailure{
					Message: f.Description,
					Type:    string(f.Severity),
					Text:    fmt.Sprintf("Remediation: %s", f.Remediation),
				},
			}
			suite.Cases = append(suite.Cases, tc)
		}
		suites = append(suites, suite)
		totalTests += suite.Tests
		totalFailures += suite.Failures
	}

	ts := junitTestSuites{
		Name:     "WAT Well-Architected Analysis",
		Tests:    totalTests,
		Failures: totalFailures,
		Suites:   suites,
	}

	if _, err := fmt.Fprint(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(ts)
}

// resourceTypeFromAddress extracts the resource type from a Terraform address.
// "module.vpc.aws_security_group.main" -> "aws_security_group"
// "aws_s3_bucket.data" -> "aws_s3_bucket".
func resourceTypeFromAddress(addr string) string {
	// Walk from the end; the resource type is the second-to-last dot-separated segment
	parts := splitAddress(addr)
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return addr
}

func splitAddress(addr string) []string {
	var parts []string
	current := ""
	for _, ch := range addr {
		if ch == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
