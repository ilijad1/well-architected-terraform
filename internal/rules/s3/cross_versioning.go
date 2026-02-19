package s3

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CrossVersioningRule checks that every S3 bucket has a corresponding
// aws_s3_bucket_versioning resource.
type CrossVersioningRule struct{}

func init() {
	engine.RegisterCross(&CrossVersioningRule{})
}

func (r *CrossVersioningRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "S3-010",
		Name:          "S3 Bucket Missing Versioning Configuration",
		Description:   "Every S3 bucket should have versioning enabled via an aws_s3_bucket_versioning resource.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_s3_bucket", "aws_s3_bucket_versioning"},
	}
}

func (r *CrossVersioningRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	versionedBuckets := make(map[string]bool)
	for _, res := range resources {
		if res.Type == "aws_s3_bucket_versioning" {
			bucket, ok := res.GetStringAttr("bucket")
			if ok {
				versionedBuckets[bucket] = true
			}
		}
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_s3_bucket" {
			continue
		}

		bucketName, _ := res.GetStringAttr("bucket")
		bucketID, _ := res.GetStringAttr("id")

		if !versionedBuckets[bucketName] && !versionedBuckets[bucketID] && !versionedBuckets[res.Address()] {
			findings = append(findings, model.Finding{
				RuleID:      "S3-010",
				RuleName:    "S3 Bucket Missing Versioning Configuration",
				Severity:    model.SeverityMedium,
				Pillar:      model.PillarReliability,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "This S3 bucket has no aws_s3_bucket_versioning resource. Versioning protects against accidental deletion and enables object recovery.",
				Remediation: "Add an aws_s3_bucket_versioning resource with versioning_configuration { status = \"Enabled\" }.",
			})
		}
	}

	return findings
}
