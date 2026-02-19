package s3

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CrossPublicAccessBlockRule checks that every S3 bucket has a corresponding
// aws_s3_bucket_public_access_block resource.
type CrossPublicAccessBlockRule struct{}

func init() {
	engine.RegisterCross(&CrossPublicAccessBlockRule{})
}

func (r *CrossPublicAccessBlockRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "S3-009",
		Name:          "S3 Bucket Missing Public Access Block",
		Description:   "Every S3 bucket should have an aws_s3_bucket_public_access_block resource to prevent accidental public exposure.",
		Severity:      model.SeverityCritical,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_s3_bucket", "aws_s3_bucket_public_access_block"},
		ComplianceFrameworks: map[string][]string{
			"CIS": {"2.1.4"},
		},
	}
}

func (r *CrossPublicAccessBlockRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	// Index which bucket names/IDs have a public access block
	blockedBuckets := make(map[string]bool)
	for _, res := range resources {
		if res.Type == "aws_s3_bucket_public_access_block" {
			bucket, ok := res.GetStringAttr("bucket")
			if ok {
				blockedBuckets[bucket] = true
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

		if !blockedBuckets[bucketName] && !blockedBuckets[bucketID] && !blockedBuckets[res.Address()] {
			findings = append(findings, model.Finding{
				RuleID:      "S3-009",
				RuleName:    "S3 Bucket Missing Public Access Block",
				Severity:    model.SeverityCritical,
				Pillar:      model.PillarSecurity,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "This S3 bucket has no aws_s3_bucket_public_access_block resource, leaving it vulnerable to accidental public access.",
				Remediation: "Add an aws_s3_bucket_public_access_block resource with block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets all set to true.",
			})
		}
	}

	return findings
}
