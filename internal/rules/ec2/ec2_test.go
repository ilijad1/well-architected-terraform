package ec2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/ilijad1/well-architected-terraform/internal/parser"
)

func loadResources(t *testing.T, file string) []model.TerraformResource {
	t.Helper()
	p := parser.New()
	resources, err := p.ParseFile(file)
	require.NoError(t, err)
	return resources
}

func findResource(resources []model.TerraformResource, resourceType, name string) model.TerraformResource {
	for _, r := range resources {
		if r.Type == resourceType && r.Name == name {
			return r
		}
	}
	return model.TerraformResource{}
}

func TestIMDSv2_NotRequired(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/bad.tf")

	rule := &IMDSv2{}

	// Instance with no metadata_options
	res := findResource(resources, "aws_instance", "no_imdsv2")
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EC2-001", findings[0].RuleID)

	// Instance with http_tokens = "optional"
	res = findResource(resources, "aws_instance", "old_gen")
	findings = rule.Evaluate(res)
	assert.Len(t, findings, 1)
}

func TestIMDSv2_Required(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/good.tf")
	res := findResource(resources, "aws_instance", "secure")

	rule := &IMDSv2{}
	findings := rule.Evaluate(res)
	assert.Empty(t, findings)
}

func TestEBSEncryption_Unencrypted(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/bad.tf")
	res := findResource(resources, "aws_ebs_volume", "unencrypted")

	rule := &EBSEncryption{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EC2-002", findings[0].RuleID)
}

func TestEBSEncryption_Encrypted(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/good.tf")
	res := findResource(resources, "aws_ebs_volume", "encrypted")

	rule := &EBSEncryption{}
	findings := rule.Evaluate(res)
	assert.Empty(t, findings)
}

func TestASGMinSize_Low(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/bad.tf")
	res := findResource(resources, "aws_autoscaling_group", "single_az")

	rule := &ASGMinSize{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EC2-003", findings[0].RuleID)
}

func TestASGMinSize_HA(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/good.tf")
	res := findResource(resources, "aws_autoscaling_group", "ha")

	rule := &ASGMinSize{}
	findings := rule.Evaluate(res)
	assert.Empty(t, findings)
}

func TestInstanceGeneration_OldGen(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/bad.tf")
	res := findResource(resources, "aws_instance", "old_gen")

	rule := &InstanceGeneration{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Contains(t, findings[0].Description, "m4.large")
}

func TestInstanceGeneration_CurrentGen(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/good.tf")
	res := findResource(resources, "aws_instance", "secure")

	rule := &InstanceGeneration{}
	findings := rule.Evaluate(res)
	assert.Empty(t, findings)
}

func TestInstanceTags_NoTags(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/bad.tf")
	res := findResource(resources, "aws_instance", "no_imdsv2")

	rule := &InstanceTags{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EC2-006", findings[0].RuleID)
}

func TestInstanceTags_WithTags(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/good.tf")
	res := findResource(resources, "aws_instance", "secure")

	rule := &InstanceTags{}
	findings := rule.Evaluate(res)
	assert.Empty(t, findings)
}

func TestDetailedMonitoring_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/bad.tf")
	res := findResource(resources, "aws_instance", "no_imdsv2")

	rule := &DetailedMonitoring{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
}

func TestDetailedMonitoring_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/good.tf")
	res := findResource(resources, "aws_instance", "secure")

	rule := &DetailedMonitoring{}
	findings := rule.Evaluate(res)
	assert.Empty(t, findings)
}

func TestNoPublicIP_HasPublicIP(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/bad.tf")
	res := findResource(resources, "aws_instance", "public_ip")

	rule := &NoPublicIP{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EC2-008", findings[0].RuleID)
}

func TestNoPublicIP_NoPublicIP(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/good.tf")
	res := findResource(resources, "aws_instance", "no_public_ip")

	rule := &NoPublicIP{}
	findings := rule.Evaluate(res)
	assert.Empty(t, findings)
}

func TestInstanceProfile_Missing(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/bad.tf")
	res := findResource(resources, "aws_instance", "no_profile")

	rule := &InstanceProfile{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EC2-009", findings[0].RuleID)
}

func TestInstanceProfile_Attached(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/good.tf")
	res := findResource(resources, "aws_instance", "no_public_ip")

	rule := &InstanceProfile{}
	findings := rule.Evaluate(res)
	assert.Empty(t, findings)
}

func TestEBSOptimized_NotOptimized(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/bad.tf")
	res := findResource(resources, "aws_instance", "not_ebs_optimized")

	rule := &EBSOptimized{}
	findings := rule.Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EC2-010", findings[0].RuleID)
}

func TestEBSOptimized_Optimized(t *testing.T) {
	resources := loadResources(t, "../../../testdata/ec2/good.tf")
	res := findResource(resources, "aws_instance", "no_public_ip")

	rule := &EBSOptimized{}
	findings := rule.Evaluate(res)
	assert.Empty(t, findings)
}
