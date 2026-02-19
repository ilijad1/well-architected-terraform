package s3

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&BucketEncryption{})
}

// BucketEncryption checks that S3 buckets have server-side encryption configured.
type BucketEncryption struct{}

func (r *BucketEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "S3-001",
		Name:          "S3 Bucket Server-Side Encryption",
		Description:   "S3 buckets should have server-side encryption enabled to protect data at rest.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_s3_bucket"},
		DocURL:        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html",
	}
}

func (r *BucketEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	// In AWS provider v4+, encryption is typically configured via a separate
	// aws_s3_bucket_server_side_encryption_configuration resource.
	// Check for the legacy inline block.
	if resource.HasBlock("server_side_encryption_configuration") {
		return nil
	}

	return []model.Finding{{
		RuleID:      "S3-001",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "S3 bucket does not have inline server-side encryption configuration. Ensure an aws_s3_bucket_server_side_encryption_configuration resource exists for this bucket.",
		Remediation: "Add an aws_s3_bucket_server_side_encryption_configuration resource with sse_algorithm set to 'aws:kms' or 'AES256'.",
		DocURL:      r.Metadata().DocURL,
	}}
}
