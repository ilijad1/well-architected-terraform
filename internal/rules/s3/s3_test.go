package s3

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/ilijad1/well-architected-terraform/internal/parser"
)

func TestBucketEncryption_NoEncryption(t *testing.T) {
	p := parser.New()
	resources, err := p.ParseFile("../../../testdata/s3/bad.tf")
	if err != nil {
		t.Fatal(err)
	}

	rule := &BucketEncryption{}
	var bucket model.TerraformResource
	for _, r := range resources {
		if r.Type == "aws_s3_bucket" {
			bucket = r
			break
		}
	}

	findings := rule.Evaluate(bucket)
	assert.Len(t, findings, 1)
	assert.Equal(t, "S3-001", findings[0].RuleID)
	assert.Equal(t, model.SeverityHigh, findings[0].Severity)
}

func TestBucketEncryption_WithEncryption(t *testing.T) {
	// Bucket with inline encryption block (legacy style)
	resource := model.TerraformResource{
		Type: "aws_s3_bucket",
		Name: "encrypted",
		Blocks: map[string][]model.Block{
			"server_side_encryption_configuration": {{
				Type:       "server_side_encryption_configuration",
				Attributes: map[string]interface{}{},
			}},
		},
		Attributes: map[string]interface{}{},
	}

	rule := &BucketEncryption{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestPublicAccessBlock_AllEnabled(t *testing.T) {
	p := parser.New()
	resources, err := p.ParseFile("../../../testdata/s3/good.tf")
	if err != nil {
		t.Fatal(err)
	}

	rule := &PublicAccessBlock{}
	for _, r := range resources {
		if r.Type == "aws_s3_bucket_public_access_block" {
			findings := rule.Evaluate(r)
			assert.Empty(t, findings)
			return
		}
	}
	t.Fatal("no aws_s3_bucket_public_access_block resource found")
}

func TestPublicAccessBlock_PartialBlock(t *testing.T) {
	p := parser.New()
	resources, err := p.ParseFile("../../../testdata/s3/bad.tf")
	if err != nil {
		t.Fatal(err)
	}

	rule := &PublicAccessBlock{}
	for _, r := range resources {
		if r.Type == "aws_s3_bucket_public_access_block" {
			findings := rule.Evaluate(r)
			assert.Len(t, findings, 2) // block_public_policy and restrict_public_buckets are false
			for _, f := range findings {
				assert.Equal(t, "S3-002", f.RuleID)
				assert.Equal(t, model.SeverityCritical, f.Severity)
			}
			return
		}
	}
	t.Fatal("no aws_s3_bucket_public_access_block resource found")
}

func loadResources(t *testing.T, file string) []model.TerraformResource {
	t.Helper()
	p := parser.New()
	resources, err := p.ParseFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return resources
}

func findResource(t *testing.T, resources []model.TerraformResource, resType, name string) model.TerraformResource {
	t.Helper()
	for _, r := range resources {
		if r.Type == resType && r.Name == name {
			return r
		}
	}
	t.Fatalf("%s.%s not found", resType, name)
	return model.TerraformResource{}
}

func TestAccountPublicAccessBlock_Partial(t *testing.T) {
	resources := loadResources(t, "../../../testdata/s3/bad.tf")
	res := findResource(t, resources, "aws_s3_account_public_access_block", "partial")
	findings := (&AccountPublicAccessBlock{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "S3-007", findings[0].RuleID)
}

func TestAccountPublicAccessBlock_AllBlocked(t *testing.T) {
	resources := loadResources(t, "../../../testdata/s3/good.tf")
	res := findResource(t, resources, "aws_s3_account_public_access_block", "all_blocked")
	findings := (&AccountPublicAccessBlock{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestOwnershipControls_NotEnforced(t *testing.T) {
	resources := loadResources(t, "../../../testdata/s3/bad.tf")
	res := findResource(t, resources, "aws_s3_bucket_ownership_controls", "no_enforced")
	findings := (&OwnershipControls{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "S3-008", findings[0].RuleID)
}

func TestOwnershipControls_Enforced(t *testing.T) {
	resources := loadResources(t, "../../../testdata/s3/good.tf")
	res := findResource(t, resources, "aws_s3_bucket_ownership_controls", "enforced")
	findings := (&OwnershipControls{}).Evaluate(res)
	assert.Empty(t, findings)
}
