package s3

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&BucketVersioning{})
}

// BucketVersioning checks that S3 bucket versioning is enabled.
type BucketVersioning struct{}

func (r *BucketVersioning) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "S3-003",
		Name:          "S3 Bucket Versioning",
		Description:   "S3 buckets should have versioning enabled for data protection and recovery.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_s3_bucket_versioning"},
		DocURL:        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
	}
}

func (r *BucketVersioning) Evaluate(resource model.TerraformResource) []model.Finding {
	blocks := resource.GetBlocks("versioning_configuration")
	if len(blocks) > 0 {
		status, ok := blocks[0].GetStringAttr("status")
		if ok && status == "Enabled" {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "S3-003",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "S3 bucket versioning is not enabled.",
		Remediation: "Set versioning_configuration status to 'Enabled' in the aws_s3_bucket_versioning resource.",
		DocURL:      r.Metadata().DocURL,
	}}
}
