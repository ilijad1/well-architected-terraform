package s3

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&BucketTags{})
}

// BucketTags checks that S3 buckets have tags for cost allocation and organization.
type BucketTags struct{}

func (r *BucketTags) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "S3-005",
		Name:          "S3 Bucket Tags",
		Description:   "S3 buckets should have tags for cost allocation and resource organization.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarCostOptimization,
		ResourceTypes: []string{"aws_s3_bucket"},
	}
}

func (r *BucketTags) Evaluate(resource model.TerraformResource) []model.Finding {
	if _, ok := resource.Attributes["tags"]; ok {
		return nil
	}

	return []model.Finding{{
		RuleID:      "S3-005",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityLow,
		Pillar:      model.PillarCostOptimization,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "S3 bucket does not have tags configured.",
		Remediation: "Add tags to the S3 bucket for cost allocation and resource organization.",
	}}
}
