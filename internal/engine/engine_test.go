package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// mockRule is a test rule that always returns a finding.
type mockRule struct {
	id            string
	pillar        model.Pillar
	severity      model.Severity
	resourceTypes []string
}

func (r *mockRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            r.id,
		Name:          r.id,
		Severity:      r.severity,
		Pillar:        r.pillar,
		ResourceTypes: r.resourceTypes,
	}
}

func (r *mockRule) Evaluate(resource model.TerraformResource) []model.Finding {
	return []model.Finding{{
		RuleID:   r.id,
		Resource: resource.Address(),
		Severity: r.severity,
		Pillar:   r.pillar,
	}}
}

func TestEngine_Analyze_DispatchesByResourceType(t *testing.T) {
	s3Rule := &mockRule{id: "S3-TEST", pillar: model.PillarSecurity, severity: model.SeverityHigh, resourceTypes: []string{"aws_s3_bucket"}}
	ec2Rule := &mockRule{id: "EC2-TEST", pillar: model.PillarSecurity, severity: model.SeverityHigh, resourceTypes: []string{"aws_instance"}}

	eng := NewWithRules([]model.Rule{s3Rule, ec2Rule}, nil)

	resources := []model.TerraformResource{
		{Type: "aws_s3_bucket", Name: "test"},
		{Type: "aws_instance", Name: "test"},
		{Type: "aws_rds_cluster", Name: "test"}, // no matching rule
	}

	findings := eng.Analyze(resources)
	assert.Len(t, findings, 2)
	assert.Equal(t, "S3-TEST", findings[0].RuleID)
	assert.Equal(t, "EC2-TEST", findings[1].RuleID)
}

func TestFilterRules_ByPillar(t *testing.T) {
	rules := []model.Rule{
		&mockRule{id: "SEC-1", pillar: model.PillarSecurity, severity: model.SeverityHigh, resourceTypes: []string{"aws_s3_bucket"}},
		&mockRule{id: "REL-1", pillar: model.PillarReliability, severity: model.SeverityHigh, resourceTypes: []string{"aws_s3_bucket"}},
	}

	filtered := filterRules(rules, Config{Pillars: []model.Pillar{model.PillarSecurity}})
	assert.Len(t, filtered, 1)
	assert.Equal(t, "SEC-1", filtered[0].Metadata().ID)
}

func TestFilterRules_ByMinSeverity(t *testing.T) {
	rules := []model.Rule{
		&mockRule{id: "HIGH-1", pillar: model.PillarSecurity, severity: model.SeverityHigh, resourceTypes: []string{"aws_s3_bucket"}},
		&mockRule{id: "LOW-1", pillar: model.PillarSecurity, severity: model.SeverityLow, resourceTypes: []string{"aws_s3_bucket"}},
	}

	filtered := filterRules(rules, Config{MinSeverity: model.SeverityHigh})
	assert.Len(t, filtered, 1)
	assert.Equal(t, "HIGH-1", filtered[0].Metadata().ID)
}

func TestFilterRules_ByExcludeIDs(t *testing.T) {
	rules := []model.Rule{
		&mockRule{id: "S3-001", pillar: model.PillarSecurity, severity: model.SeverityHigh, resourceTypes: []string{"aws_s3_bucket"}},
		&mockRule{id: "S3-002", pillar: model.PillarSecurity, severity: model.SeverityHigh, resourceTypes: []string{"aws_s3_bucket"}},
	}

	filtered := filterRules(rules, Config{ExcludeIDs: []string{"S3-001"}})
	assert.Len(t, filtered, 1)
	assert.Equal(t, "S3-002", filtered[0].Metadata().ID)
}

// mockCrossRule is a test cross-resource rule.
type mockCrossRule struct {
	id       string
	pillar   model.Pillar
	severity model.Severity
}

func (r *mockCrossRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            r.id,
		Name:          r.id,
		Severity:      r.severity,
		Pillar:        r.pillar,
		ResourceTypes: []string{"aws_s3_bucket", "aws_s3_bucket_public_access_block"},
	}
}

func (r *mockCrossRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	return []model.Finding{{
		RuleID:   r.id,
		Resource: "cross-check",
		Severity: r.severity,
		Pillar:   r.pillar,
	}}
}

func TestEngine_Analyze_CrossResourceRules(t *testing.T) {
	singleRule := &mockRule{id: "S3-001", pillar: model.PillarSecurity, severity: model.SeverityHigh, resourceTypes: []string{"aws_s3_bucket"}}
	crossRule := &mockCrossRule{id: "S3-CROSS", pillar: model.PillarSecurity, severity: model.SeverityCritical}

	eng := NewWithRules([]model.Rule{singleRule}, []model.CrossResourceRule{crossRule})

	resources := []model.TerraformResource{
		{Type: "aws_s3_bucket", Name: "test"},
	}

	findings := eng.Analyze(resources)
	assert.Len(t, findings, 2)
	assert.Equal(t, "S3-001", findings[0].RuleID)
	assert.Equal(t, "S3-CROSS", findings[1].RuleID)
}

func TestEngine_CrossRules_Accessor(t *testing.T) {
	crossRule := &mockCrossRule{id: "TEST-CROSS", pillar: model.PillarSecurity, severity: model.SeverityHigh}
	eng := NewWithRules(nil, []model.CrossResourceRule{crossRule})
	assert.Len(t, eng.CrossRules(), 1)
	assert.Equal(t, "TEST-CROSS", eng.CrossRules()[0].Metadata().ID)
}

func TestFilterCrossRules_ByPillar(t *testing.T) {
	rules := []model.CrossResourceRule{
		&mockCrossRule{id: "SEC-CROSS", pillar: model.PillarSecurity, severity: model.SeverityHigh},
		&mockCrossRule{id: "REL-CROSS", pillar: model.PillarReliability, severity: model.SeverityHigh},
	}

	filtered := filterCrossRules(rules, Config{Pillars: []model.Pillar{model.PillarSecurity}})
	assert.Len(t, filtered, 1)
	assert.Equal(t, "SEC-CROSS", filtered[0].Metadata().ID)
}

func TestFilterCrossRules_ByMinSeverity(t *testing.T) {
	rules := []model.CrossResourceRule{
		&mockCrossRule{id: "HIGH-CROSS", pillar: model.PillarSecurity, severity: model.SeverityHigh},
		&mockCrossRule{id: "LOW-CROSS", pillar: model.PillarSecurity, severity: model.SeverityLow},
	}

	filtered := filterCrossRules(rules, Config{MinSeverity: model.SeverityHigh})
	assert.Len(t, filtered, 1)
	assert.Equal(t, "HIGH-CROSS", filtered[0].Metadata().ID)
}

func TestFilterCrossRules_ByExcludeIDs(t *testing.T) {
	rules := []model.CrossResourceRule{
		&mockCrossRule{id: "CROSS-A", pillar: model.PillarSecurity, severity: model.SeverityHigh},
		&mockCrossRule{id: "CROSS-B", pillar: model.PillarSecurity, severity: model.SeverityHigh},
	}

	filtered := filterCrossRules(rules, Config{ExcludeIDs: []string{"CROSS-A"}})
	assert.Len(t, filtered, 1)
	assert.Equal(t, "CROSS-B", filtered[0].Metadata().ID)
}
