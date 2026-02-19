package s3

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&BucketLogging{})
}

// BucketLogging checks that S3 bucket has a target_bucket for access logging.
type BucketLogging struct{}

func (r *BucketLogging) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "S3-004",
		Name:          "S3 Bucket Access Logging",
		Description:   "S3 buckets should have access logging enabled for audit and monitoring.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_s3_bucket_logging"},
	}
}

func (r *BucketLogging) Evaluate(resource model.TerraformResource) []model.Finding {
	// If this resource exists with a target_bucket, logging is configured.
	if _, ok := resource.GetStringAttr("target_bucket"); ok {
		return nil
	}

	return []model.Finding{{
		RuleID:      "S3-004",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarOperationalExcellence,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "S3 bucket logging resource exists but target_bucket is not set.",
		Remediation: "Set the target_bucket attribute to a valid S3 bucket for storing access logs.",
	}}
}
