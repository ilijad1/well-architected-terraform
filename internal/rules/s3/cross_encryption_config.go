package s3

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CrossEncryptionConfigRule checks that every S3 bucket has a corresponding
// aws_s3_bucket_server_side_encryption_configuration resource.
type CrossEncryptionConfigRule struct{}

func init() {
	engine.RegisterCross(&CrossEncryptionConfigRule{})
}

func (r *CrossEncryptionConfigRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "S3-012",
		Name:          "S3 Bucket Missing Server-Side Encryption Configuration",
		Description:   "Every S3 bucket should have an aws_s3_bucket_server_side_encryption_configuration resource to ensure data at rest is encrypted.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_s3_bucket", "aws_s3_bucket_server_side_encryption_configuration"},
		ComplianceFrameworks: map[string][]string{
			"CIS": {"2.1.1"},
		},
	}
}

func (r *CrossEncryptionConfigRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	encryptedBuckets := make(map[string]bool)
	for _, res := range resources {
		if res.Type == "aws_s3_bucket_server_side_encryption_configuration" {
			bucket, ok := res.GetStringAttr("bucket")
			if ok && bucket != "" {
				encryptedBuckets[bucket] = true
			}
			encryptedBuckets[res.Name] = true
		}
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_s3_bucket" {
			continue
		}

		bucketName, _ := res.GetStringAttr("bucket")

		if !encryptedBuckets[bucketName] && !encryptedBuckets[res.Address()] && !encryptedBuckets[res.Name] {
			findings = append(findings, model.Finding{
				RuleID:      "S3-012",
				RuleName:    "S3 Bucket Missing Server-Side Encryption Configuration",
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "This S3 bucket has no aws_s3_bucket_server_side_encryption_configuration resource. Data at rest may be unencrypted.",
				Remediation: "Add an aws_s3_bucket_server_side_encryption_configuration resource with an AES256 or aws:kms rule.",
			})
		}
	}

	return findings
}
