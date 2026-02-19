package sustainability

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// S3IntelligentTieringRule checks that S3 buckets have intelligent tiering or lifecycle rules.
type S3IntelligentTieringRule struct{}

func init() {
	engine.RegisterCross(&S3IntelligentTieringRule{})
}

func (r *S3IntelligentTieringRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-004",
		Name:          "S3 Bucket Missing Intelligent Tiering or Lifecycle Rules",
		Description:   "S3 buckets should have intelligent tiering configuration or lifecycle rules to optimize storage costs and reduce waste.",
		Severity:      model.SeverityInfo,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_s3_bucket", "aws_s3_bucket_intelligent_tiering_configuration", "aws_s3_bucket_lifecycle_configuration"},
	}
}

func (r *S3IntelligentTieringRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	// Collect bucket names/IDs that have tiering or lifecycle configs
	optimized := make(map[string]bool)
	for _, res := range resources {
		switch res.Type {
		case "aws_s3_bucket_intelligent_tiering_configuration":
			bucket, ok := res.GetStringAttr("bucket")
			if ok {
				optimized[bucket] = true
			}
		case "aws_s3_bucket_lifecycle_configuration":
			bucket, ok := res.GetStringAttr("bucket")
			if ok {
				optimized[bucket] = true
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

		if !optimized[bucketName] && !optimized[bucketID] && !optimized[res.Address()] {
			findings = append(findings, model.Finding{
				RuleID:      "SUS-004",
				RuleName:    "S3 Bucket Missing Intelligent Tiering or Lifecycle Rules",
				Severity:    model.SeverityInfo,
				Pillar:      model.PillarSustainability,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "This S3 bucket has no intelligent tiering configuration or lifecycle rules. Objects may remain in expensive storage classes unnecessarily, wasting resources.",
				Remediation: "Add an aws_s3_bucket_intelligent_tiering_configuration or aws_s3_bucket_lifecycle_configuration resource to automatically move objects to cost-efficient storage tiers.",
			})
		}
	}

	return findings
}
