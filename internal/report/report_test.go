package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func testSummary() Summary {
	return Summary{
		TotalResources:     5,
		TotalFindings:      2,
		SuppressedFindings: 1,
		BySeverity: map[model.Severity]int{
			model.SeverityHigh:   1,
			model.SeverityMedium: 1,
		},
		ByPillar: map[model.Pillar]int{
			model.PillarSecurity:    1,
			model.PillarReliability: 1,
		},
		Findings: []model.Finding{
			{
				RuleID:      "S3-001",
				RuleName:    "S3 Bucket Encryption",
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				Resource:    "aws_s3_bucket.data",
				File:        "main.tf",
				Line:        10,
				Description: "S3 bucket is not encrypted",
				Remediation: "Enable server-side encryption",
			},
			{
				RuleID:      "RDS-001",
				RuleName:    "RDS Multi-AZ",
				Severity:    model.SeverityMedium,
				Pillar:      model.PillarReliability,
				Resource:    "aws_db_instance.main",
				File:        "rds.tf",
				Line:        25,
				Description: "RDS instance is not multi-AZ",
				Remediation: "Set multi_az = true",
			},
		},
		RuleMetadata: []model.RuleMetadata{
			{
				ID:          "S3-001",
				Name:        "S3 Bucket Encryption",
				Description: "S3 buckets should be encrypted",
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				ComplianceFrameworks: map[string][]string{
					"CIS": {"2.1.1"},
				},
			},
		},
	}
}

func TestNewReporter_AllFormats(t *testing.T) {
	tests := []struct {
		format   Format
		wantType string
	}{
		{FormatCLI, "*report.CLIReporter"},
		{FormatJSON, "*report.JSONReporter"},
		{FormatMarkdown, "*report.MarkdownReporter"},
		{FormatSARIF, "*report.SARIFReporter"},
		{FormatJUnit, "*report.JUnitReporter"},
		{FormatCSV, "*report.CSVReporter"},
	}
	for _, tt := range tests {
		r := NewReporter(tt.format)
		assert.NotNil(t, r, "format %s should return a reporter", tt.format)
	}
}

func TestBuildSummary(t *testing.T) {
	resources := []model.TerraformResource{
		{Type: "aws_s3_bucket", Name: "a"},
		{Type: "aws_instance", Name: "b"},
	}
	findings := []model.Finding{
		{RuleID: "S3-001", Severity: model.SeverityLow, Pillar: model.PillarSecurity},
		{RuleID: "EC2-001", Severity: model.SeverityHigh, Pillar: model.PillarReliability},
	}

	summary := BuildSummary(resources, findings)
	assert.Equal(t, 2, summary.TotalResources)
	assert.Equal(t, 2, summary.TotalFindings)
	assert.Equal(t, 1, summary.BySeverity[model.SeverityHigh])
	assert.Equal(t, 1, summary.BySeverity[model.SeverityLow])
	// Findings sorted by severity: HIGH first
	assert.Equal(t, "EC2-001", summary.Findings[0].RuleID)
	assert.Equal(t, "S3-001", summary.Findings[1].RuleID)
}

// --- SARIF tests ---

func TestSARIFReporter_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	r := &SARIFReporter{}
	err := r.Generate(&buf, testSummary())
	require.NoError(t, err)

	var log sarifLog
	err = json.Unmarshal(buf.Bytes(), &log)
	require.NoError(t, err)

	assert.Equal(t, "2.1.0", log.Version)
	assert.Len(t, log.Runs, 1)
	assert.Equal(t, "wat", log.Runs[0].Tool.Driver.Name)
	assert.Len(t, log.Runs[0].Results, 2)
}

func TestSARIFReporter_SeverityMapping(t *testing.T) {
	tests := []struct {
		severity model.Severity
		want     string
	}{
		{model.SeverityCritical, "error"},
		{model.SeverityHigh, "error"},
		{model.SeverityMedium, "warning"},
		{model.SeverityLow, "note"},
		{model.SeverityInfo, "note"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, severityToSARIFLevel(tt.severity))
	}
}

func TestSARIFReporter_ComplianceFrameworksInProperties(t *testing.T) {
	var buf bytes.Buffer
	r := &SARIFReporter{}
	err := r.Generate(&buf, testSummary())
	require.NoError(t, err)

	var log sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &log))

	// S3-001 should have compliance frameworks in properties
	found := false
	for _, rule := range log.Runs[0].Tool.Driver.Rules {
		if rule.ID == "S3-001" && rule.Properties != nil {
			_, ok := rule.Properties["complianceFrameworks"]
			assert.True(t, ok)
			found = true
		}
	}
	assert.True(t, found, "S3-001 should have complianceFrameworks in properties")
}

func TestSARIFReporter_Locations(t *testing.T) {
	var buf bytes.Buffer
	r := &SARIFReporter{}
	err := r.Generate(&buf, testSummary())
	require.NoError(t, err)

	var log sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &log))

	result := log.Runs[0].Results[0]
	require.Len(t, result.Locations, 1)
	assert.Equal(t, "main.tf", result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	assert.Equal(t, 10, result.Locations[0].PhysicalLocation.Region.StartLine)
}

// --- JUnit tests ---

func TestJUnitReporter_ValidXML(t *testing.T) {
	var buf bytes.Buffer
	r := &JUnitReporter{}
	err := r.Generate(&buf, testSummary())
	require.NoError(t, err)

	var ts junitTestSuites
	err = xml.Unmarshal(buf.Bytes(), &ts)
	require.NoError(t, err)

	assert.Equal(t, "WAT Well-Architected Analysis", ts.Name)
	assert.Equal(t, 2, ts.Tests)
	assert.Equal(t, 2, ts.Failures)
}

func TestJUnitReporter_FailureDetails(t *testing.T) {
	var buf bytes.Buffer
	r := &JUnitReporter{}
	err := r.Generate(&buf, testSummary())
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "[S3-001]")
	assert.Contains(t, output, "aws_s3_bucket.data")
	assert.Contains(t, output, "Remediation:")
}

func TestJUnitReporter_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &JUnitReporter{}
	summary := Summary{TotalResources: 5, TotalFindings: 0}
	err := r.Generate(&buf, summary)
	require.NoError(t, err)

	var ts junitTestSuites
	require.NoError(t, xml.Unmarshal(buf.Bytes(), &ts))
	assert.Equal(t, 0, ts.Tests)
}

// --- CSV tests ---

func TestCSVReporter_Header(t *testing.T) {
	var buf bytes.Buffer
	r := &CSVReporter{}
	err := r.Generate(&buf, testSummary())
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.GreaterOrEqual(t, len(lines), 1)
	assert.Contains(t, lines[0], "RuleID")
	assert.Contains(t, lines[0], "Severity")
	assert.Contains(t, lines[0], "Remediation")
}

func TestCSVReporter_RowCount(t *testing.T) {
	var buf bytes.Buffer
	r := &CSVReporter{}
	err := r.Generate(&buf, testSummary())
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// 1 header + 2 findings = 3 lines
	assert.Len(t, lines, 3)
}

func TestCSVReporter_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &CSVReporter{}
	summary := Summary{TotalResources: 5, TotalFindings: 0}
	err := r.Generate(&buf, summary)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 1) // just header
}

// --- Utility tests ---

func TestResourceTypeFromAddress(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"aws_s3_bucket.data", "aws_s3_bucket"},
		{"module.vpc.aws_security_group.main", "aws_security_group"},
		{"aws_instance.web", "aws_instance"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, resourceTypeFromAddress(tt.addr))
	}
}

func TestFormatComplianceFrameworks(t *testing.T) {
	tests := []struct {
		input map[string][]string
		want  string
	}{
		{nil, ""},
		{map[string][]string{}, ""},
		{map[string][]string{"CIS": {"2.1.1"}}, "CIS:2.1.1"},
		{map[string][]string{"CIS": {"2.1.1", "3.9"}, "PCI": {"10.5"}}, "CIS:2.1.1;CIS:3.9;PCI:10.5"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, formatComplianceFrameworks(tt.input))
	}
}
