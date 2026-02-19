package s3

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CrossLoggingRule checks that every S3 bucket has a corresponding
// aws_s3_bucket_logging resource to enable access logging.
type CrossLoggingRule struct{}

func init() {
	engine.RegisterCross(&CrossLoggingRule{})
}

func (r *CrossLoggingRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "S3-011",
		Name:          "S3 Bucket Missing Access Logging",
		Description:   "Every S3 bucket should have an aws_s3_bucket_logging resource to capture access logs for auditing and security analysis.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_s3_bucket", "aws_s3_bucket_logging"},
	}
}

func (r *CrossLoggingRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	loggedBuckets := make(map[string]bool)
	for _, res := range resources {
		if res.Type == "aws_s3_bucket_logging" {
			bucket, ok := res.GetStringAttr("bucket")
			if ok && bucket != "" {
				loggedBuckets[bucket] = true
			}
			loggedBuckets[res.Name] = true
		}
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_s3_bucket" {
			continue
		}

		bucketName, _ := res.GetStringAttr("bucket")

		if !loggedBuckets[bucketName] && !loggedBuckets[res.Address()] && !loggedBuckets[res.Name] {
			findings = append(findings, model.Finding{
				RuleID:      "S3-011",
				RuleName:    "S3 Bucket Missing Access Logging",
				Severity:    model.SeverityMedium,
				Pillar:      model.PillarSecurity,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "This S3 bucket has no aws_s3_bucket_logging resource. Access logging enables auditing of requests and helps detect unauthorized access.",
				Remediation: "Add an aws_s3_bucket_logging resource that references this bucket via the bucket attribute.",
			})
		}
	}

	return findings
}
